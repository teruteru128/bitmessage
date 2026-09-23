#include "peer_registry.h"

#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common/logging.h"
#include "object.h"
#include "protocol.h"

/* §11 2026-09-15: DESIGN.md §11項目23(ゴースト接続調査)向けの計測。「新規object受信のたび
 * handle_objectがこの関数を呼び、詰まったpeerが混じっているとbm_network_write_allの
 * select()タイムアウト(BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS)分だけnetwork_epoll_thread
 * (この関数の主な呼び出し元、object_sync.cのhandle_object参照)が同期的にブロックしうる」
 * という仮説を検証するため、1回のbroadcast呼び出しの所要時間を計測する。CLAUDE.mdの
 * 「time(NULL)を直接呼ばない」方針は決定ロジック(タイムアウト判定等)の決定性確保が目的で、
 * ここでの計測値はログ出力のみに使い制御フローに一切影響しないため、この方針の対象外と
 * 判断した(bm_log_leveled自体が内部でタイムスタンプ取得している既存パターンと同様)。
 * 壁時計(time())ではなくCLOCK_MONOTONICを使うのは、NTP補正等で時刻が巻き戻る影響を
 * 受けずに経過時間だけを正確に測るため。 */
#define BM_BROADCAST_INV_SLOW_WARN_MS 500

static int64_t monotonic_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void bm_peer_registry_init(struct bm_peer_registry *reg)
{
    pthread_mutex_init(&reg->lock, NULL);
    reg->conns = NULL;
    reg->count = 0;
    reg->capacity = 0;
    reg->next_generation = 1; /* 0は「未登録」を表すbm_fd_dataのcalloc既定値と衝突させない */
}

void bm_peer_registry_destroy(struct bm_peer_registry *reg)
{
    pthread_mutex_destroy(&reg->lock);
    free(reg->conns);
    reg->conns = NULL;
    reg->count = 0;
    reg->capacity = 0;
}

void bm_peer_registry_add(struct bm_peer_registry *reg, struct bm_fd_data *conn)
{
    pthread_mutex_lock(&reg->lock);
    if (reg->count >= reg->capacity)
    {
        size_t new_cap = reg->capacity == 0 ? 8 : reg->capacity * 2;
        struct bm_fd_data **grown = realloc(reg->conns, sizeof(*grown) * new_cap);
        if (grown == NULL)
        {
            pthread_mutex_unlock(&reg->lock);
            return;
        }
        reg->conns = grown;
        reg->capacity = new_cap;
    }
    conn->generation = reg->next_generation++;
    reg->conns[reg->count++] = conn;
    pthread_mutex_unlock(&reg->lock);
}

void bm_peer_registry_remove(struct bm_peer_registry *reg, struct bm_fd_data *conn)
{
    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        if (reg->conns[i] == conn)
        {
            reg->conns[i] = reg->conns[reg->count - 1];
            reg->count--;
            break;
        }
    }
    pthread_mutex_unlock(&reg->lock);
}

int bm_peer_registry_evict_if_current(struct bm_peer_registry *reg, struct bm_fd_data *conn, uint64_t generation)
{
    /* §11 2026-09-05: reg->conns[i] == connのポインタ一致は、比較する2つの側がどちらも
     * 「現在ロック中のreg->conns配列そのものの要素」であるうちは安全(このループの中でしか
     * conn->generationを読まない)。ポインタが一致した時点でconnは確実に生きている(配列に
     * 実在する)ため、その場でgenerationも読んで比較して問題ない。一致しなければ、呼び出し元が
     * 捕まえていたconnは既に別の理由で除去・free済みで、そのアドレスへたまたま別の新しい
     * connが割り当てられただけ(ABA問題)と判断し、一切触れずに除去を諦める。
     * §11 2026-09-09発覚のバグ修正: ここでgenerationが一致しても、その場でclose・
     * bm_fd_data_freeまで行ってはいけない(network.hのconn->pending_evictionのdoc参照)。
     * この関数はnetwork_epoll_thread以外のスレッドから呼ばれるため、まさに同じ瞬間に
     * network_epoll_thread側がepoll_wait()で同じconnへのイベントを既に受け取って処理中
     * だった場合、そちら側の処理と競合して二重close・二重freeを引き起こす
     * (実際に本番daemonをdouble free or corruptionでクラッシュさせた)。generation照合は
     * 「このconnがまだregistryに実在するか(=別の理由で既に片付いていないか)」しか保証せず、
     * 「他スレッドが今まさにこのメモリへアクセスしていないか」までは保証できないため、
     * 実際のfree()は必ずnetwork_epoll_thread単一スレッド内(idle_sweep_one)に一元化する。 */
    pthread_mutex_lock(&reg->lock);
    int found = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        if (reg->conns[i] == conn)
        {
            if (conn->generation == generation)
            {
                conn->pending_eviction = 1;
                found = 1;
            }
            break; /* ポインタ一致は高々1件のみなので、generation不一致でも探索終了 */
        }
    }
    pthread_mutex_unlock(&reg->lock);
    return found;
}

size_t bm_peer_registry_count(struct bm_peer_registry *reg)
{
    pthread_mutex_lock(&reg->lock);
    size_t count = reg->count;
    pthread_mutex_unlock(&reg->lock);
    return count;
}

size_t bm_peer_registry_count_by_type(struct bm_peer_registry *reg, enum bm_fd_type type)
{
    pthread_mutex_lock(&reg->lock);
    size_t count = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        if (reg->conns[i]->type == type)
        {
            count++;
        }
    }
    pthread_mutex_unlock(&reg->lock);
    return count;
}

int bm_peer_registry_has_peer(struct bm_peer_registry *reg, const char *ip, int port)
{
    pthread_mutex_lock(&reg->lock);
    int found = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        /* §11 2026-08-22発覚のバグ修正: 以前はreg->conns[i]->peer_addr(getpeername)を
         * そのまま比較していたが、SOCKS5(Tor)プロキシ経由の接続ではこれがプロキシ自身の
         * アドレス(例: 127.0.0.1:9050)になり、ipで渡される本来の候補アドレスとは
         * 絶対に一致しない。結果としてSOCKS5有効時は「既に接続済み」判定が常に偽になり、
         * peer_connector.cの二重接続防止(bm_peer_connector_connect_initial)が機能して
         * いなかった(rating調査で見つかった一連のバグと同じ根本原因)。
         * bm_network_resolve_peer_ip_port(logical_peer_ip優先、network.h参照)で解決した
         * ip:portと比較するよう修正した。 */
        char current_ip[BM_PEER_IP_STRLEN];
        int current_port = 0;
        bm_network_resolve_peer_ip_port(reg->conns[i], current_ip, sizeof(current_ip), &current_port);
        if (current_port == port && strcmp(current_ip, ip) == 0)
        {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&reg->lock);
    return found;
}

void bm_peer_registry_for_each(struct bm_peer_registry *reg, void (*callback)(struct bm_fd_data *conn, void *user_data),
                                void *user_data)
{
    /* §11 2026-08-23: broadcast_inv/pick_random_dandelion_peerと同じ「ロックを持っている間に
     * スナップショットだけ取り、実際の処理(コールバック呼び出し)はロック解放後に行う」方針。
     * コールバック側がbm_peer_registry_remove(切断処理の一部)を呼ぶ可能性があり、reg->lockを
     * 持ったままそれを許すと同じmutexを再帰的にロックしてデッドロックする。呼び出し元
     * (bm_network_idle_sweep)はnetwork_epoll_threadという単一スレッドの中でのみ動くため、
     * ロック解放後にスナップショット中の接続が他スレッドから並行にfreeされる心配は無い。 */
    pthread_mutex_lock(&reg->lock);
    size_t count = reg->count;
    struct bm_fd_data **snapshot = count > 0 ? malloc(sizeof(*snapshot) * count) : NULL;
    if (snapshot != NULL)
    {
        memcpy(snapshot, reg->conns, sizeof(*snapshot) * count);
    }
    pthread_mutex_unlock(&reg->lock);

    if (snapshot == NULL)
    {
        return;
    }
    for (size_t i = 0; i < count; i++)
    {
        callback(snapshot[i], user_data);
    }
    free(snapshot);
}

void bm_peer_registry_for_each_locked(struct bm_peer_registry *reg,
                                       void (*callback)(struct bm_fd_data *conn, void *user_data), void *user_data)
{
    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        callback(reg->conns[i], user_data);
    }
    pthread_mutex_unlock(&reg->lock);
}

/* §11 2026-09-24 項目43: 1接続ぶんのinv/dinvを組み立てて送信キューへ積む。reg->lockを
 * 持った状態で呼ぶ(connがこの間にfreeされないことをreg->lockで保証する、network.hの
 * bm_network_sendのdoc参照)。hashesのうちこの接続へFLUFFで送るものをinvに、STEMで送る
 * ものをdinvにまとめる。戻り値のビット0=invを積んだ、ビット1=dinvを積んだ、ビット2=積もうと
 * して失敗した(bm_network_sendがpending_evictionを立て済み)。 */
static int queue_inv_for_conn(struct bm_fd_data *conn, const unsigned char (*hashes)[32], size_t count,
                              int64_t now)
{
    /* §9 Dandelion++差し込み点(DESIGN.md §9.2「inv送信判断は必ずこの関数を経由させる」):
     * 接続ごと・hashごとにfluff/stem/skipを判断する。FLUFFは通常のinv、STEMはdinvとして
     * 別々のパケットで同じ接続へ送る(SKIPはその接続へは送らない)。 */
    unsigned char (*fluff)[32] = malloc(sizeof(*fluff) * count);
    unsigned char (*stem)[32] = malloc(sizeof(*stem) * count);
    if (fluff == NULL || stem == NULL)
    {
        free(fluff);
        free(stem);
        return 0;
    }
    size_t fluff_count = 0;
    size_t stem_count = 0;
    for (size_t h = 0; h < count; h++)
    {
        enum bm_propagation_mode mode = bm_decide_propagation(hashes[h], conn);
        if (mode == BM_PROPAGATE_FLUFF)
        {
            memcpy(fluff[fluff_count], hashes[h], 32);
            fluff_count++;
        }
        else if (mode == BM_PROPAGATE_STEM)
        {
            memcpy(stem[stem_count], hashes[h], 32);
            stem_count++;
        }
    }

    int result = 0;
    if (fluff_count > 0)
    {
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("inv", fluff, fluff_count, &packet_len);
        if (packet != NULL)
        {
            result |= bm_network_send(conn, packet, packet_len, now) == 0 ? 1 : 4;
            free(packet);
        }
    }
    if (stem_count > 0 && !(result & 4))
    {
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("dinv", stem, stem_count, &packet_len);
        if (packet != NULL)
        {
            result |= bm_network_send(conn, packet, packet_len, now) == 0 ? 2 : 4;
            free(packet);
        }
    }
    free(fluff);
    free(stem);
    return result;
}

void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except, int64_t now)
{
    if (count == 0)
    {
        return;
    }

    /* §11 2026-09-24 項目43: 以前は、ロックを早期に解放するため保持中にdup()した複製fdへ
     * ロック解放後にbm_network_write_allで同期的に書いていた(書き込み可能になるまで最大
     * BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS待つため、ロックを持ったままでは他スレッドの
     * registry操作を長時間止めてしまうから)。しかしこれは他スレッド(network_epoll_thread等)の
     * 書き込みと同じソケット上で混ざりうる構造だった。いまはbm_network_sendがブロックしない
     * ので、reg->lockを持ったまま各接続の送信キューへ積む。送り切れない分は
     * network_epoll_threadがEPOLLOUTで続きを送る。 */
    size_t attempted_peers = 0;
    size_t inv_sent_peers = 0;
    size_t dinv_sent_peers = 0;
    size_t evicted_peers = 0;
    int64_t start_ms = monotonic_now_ms();
    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn == except || conn->type == BM_FD_LISTEN_SOCKET)
        {
            continue;
        }
        int r = queue_inv_for_conn(conn, hashes, count, now);
        if (r != 0)
        {
            attempted_peers++;
        }
        if (r & 1)
        {
            inv_sent_peers++;
        }
        if (r & 2)
        {
            dinv_sent_peers++;
        }
        if (r & 4)
        {
            evicted_peers++;
        }
    }
    pthread_mutex_unlock(&reg->lock);

    /* §11 2026-08-24: これまで失敗時のログしか無く、正常系(何件のhashを何peerへ
     * 配信できたか)が可視化されていなかった(handle_inv等の可視化と同種の穴、
     * ユーザー指摘)。宛先ごとの個別ログにはせず(peer数が多いと大量に出るため)
     * 1回のbroadcast呼び出しにつき1行のサマリにした。誰にも送るものが無かった
     * 場合は出さない。 */
    if (attempted_peers > 0)
    {
        int64_t elapsed_ms = monotonic_now_ms() - start_ms;
        /* §11 2026-09-12: 8段階化に伴う移行。broadcast呼び出し1回につき1行のサマリなので
         * 無番号のDEBUGにした。 */
        bm_log_debug(
                "[peer_registry] broadcast inv: %zu hash(es) inv to %zu peer(s), dinv to %zu peer(s), evicted "
                "%zu dead peer(s), took %" PRId64 "ms\n",
                count, inv_sent_peers, dinv_sent_peers, evicted_peers, elapsed_ms);
        /* §11 2026-09-15: 項目23の「単一スレッドが詰まったpeerへのwriteで長時間ブロックする」
         * 仮説の検証用。DEBUGを有効にしなくても異常な遅さだけは見えるよう、閾値超過時は
         * WARNでも重ねて出す。§11 2026-09-24 項目43: 送信キュー化でブロックしなくなったため
         * 通常は0ms付近になるはず。それでも超えるなら、reg->lockの競合など別の原因を疑う。 */
        if (elapsed_ms >= BM_BROADCAST_INV_SLOW_WARN_MS)
        {
            bm_log_warn("[peer_registry] broadcast inv took %" PRId64 "ms (%zu peer(s) attempted, %zu evicted)\n",
                    elapsed_ms, attempted_peers, evicted_peers);
        }
    }
}

int bm_peer_registry_pick_random_dandelion_peer(struct bm_peer_registry *reg, char *out_ip, size_t out_ip_len,
                                                 int *out_port)
{
    pthread_mutex_lock(&reg->lock);
    /* 古典的なreservoir sampling: 事前に候補数を数え上げなくても、条件を満たす接続を
     * 順に見ながら「i番目の候補を1/iの確率で採用する」ことで最終的に一様ランダムな
     * 1件を選べる */
    size_t eligible_seen = 0;
    int found = 0;
    char chosen_ip[BM_PEER_IP_STRLEN];
    int chosen_port = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn->type != BM_FD_CLIENT_SOCKET || (conn->services & BM_SERVICE_NODE_DANDELION) == 0)
        {
            continue;
        }
        eligible_seen++;
        unsigned char r;
        RAND_bytes(&r, 1);
        if ((size_t)(r % eligible_seen) == 0)
        {
            char ip[BM_PEER_IP_STRLEN];
            int port = 0;
            bm_network_resolve_peer_ip_port(conn, ip, sizeof(ip), &port);
            strncpy(chosen_ip, ip, sizeof(chosen_ip) - 1);
            chosen_ip[sizeof(chosen_ip) - 1] = '\0';
            chosen_port = port;
            found = 1;
        }
    }
    pthread_mutex_unlock(&reg->lock);

    if (found)
    {
        strncpy(out_ip, chosen_ip, out_ip_len - 1);
        out_ip[out_ip_len - 1] = '\0';
        *out_port = chosen_port;
    }
    return found;
}
