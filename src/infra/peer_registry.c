#include "peer_registry.h"

#include <netinet/in.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/logging.h"
#include "object.h"
#include "protocol.h"

void bm_peer_registry_init(struct bm_peer_registry *reg)
{
    pthread_mutex_init(&reg->lock, NULL);
    reg->conns = NULL;
    reg->count = 0;
    reg->capacity = 0;
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

/* §9 Dandelion++ Stage 2: dup()した接続1本ぶんの送信予定。bm_decide_propagationの
 * 判定結果ごとにfluff_hashes(通常inv)とstem_hashes(dinv)へ振り分けたもの。
 * ロック解放後にまとめて書き込むための一時データ(既存のfd dup()方式と同じ理由、下記参照)。 */
struct pending_inv_send
{
    int fd;
    unsigned char (*fluff_hashes)[32];
    size_t fluff_count;
    unsigned char (*stem_hashes)[32];
    size_t stem_count;
};

void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except)
{
    if (count == 0)
    {
        return;
    }

    /* §11 部分書き込み対策: bm_network_write_all は書き込み可能になるまで(最大
     * BM_NETWORK_WRITE_TIMEOUT_SECONDS)select()で待つことがあるため、reg->lock を
     * 持ったまま呼ぶと1本の詰まったpeerが他スレッドのregistry操作を長時間ブロック
     * しかねない。かといってfd番号だけコピーしてロックを解放すると、書き込み前に
     * 元の接続がepoll thread側でclose()されfd番号が別の用途に再利用された場合に
     * 誤った相手へ書き込んでしまう恐れがある。dup()した複製fdはclose(conn->fd)されても
     * 無効化されず同じsocketを指し続けるため、ロックを持っている間にdup()するだけで
     * この競合を避けつつロックを早期に解放できる */
    struct pending_inv_send *pending = reg->count > 0 ? malloc(sizeof(*pending) * reg->count) : NULL;
    size_t pending_count = 0;

    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn == except)
        {
            continue;
        }

        /* §9 Dandelion++差し込み点(DESIGN.md §9.2「inv送信判断は必ずこの関数を経由させる」):
         * 接続ごと・hashごとにfluff/stem/skipを判断する。FLUFFは通常のinv、STEMはdinvとして
         * 別々のパケットで同じ接続へ送る(SKIPはその接続へは送らない)。Stage 1時点は常に
         * FLUFFを返すダミーだったが、Stage 2でdandelion.cの実ロジックに差し替えた。 */
        unsigned char (*fluff)[32] = malloc(sizeof(*fluff) * count);
        unsigned char (*stem)[32] = malloc(sizeof(*stem) * count);
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

        if (fluff_count == 0 && stem_count == 0)
        {
            free(fluff);
            free(stem);
            continue;
        }

        int dup_fd = dup(conn->fd);
        if (dup_fd >= 0)
        {
            pending[pending_count].fd = dup_fd;
            pending[pending_count].fluff_hashes = fluff;
            pending[pending_count].fluff_count = fluff_count;
            pending[pending_count].stem_hashes = stem;
            pending[pending_count].stem_count = stem_count;
            pending_count++;
        }
        else
        {
            free(fluff);
            free(stem);
        }
    }
    pthread_mutex_unlock(&reg->lock);

    size_t inv_sent_peers = 0;
    size_t dinv_sent_peers = 0;
    for (size_t i = 0; i < pending_count; i++)
    {
        if (pending[i].fluff_count > 0)
        {
            size_t packet_len = 0;
            unsigned char *packet =
                bm_create_inventory_message("inv", pending[i].fluff_hashes, pending[i].fluff_count, &packet_len);
            if (packet != NULL)
            {
                if (bm_network_write_all(pending[i].fd, packet, packet_len,
                                          BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS)
                    != 0)
                {
                    bm_log_warn("[peer_registry] failed to send inv to fd=%d\n", pending[i].fd);
                }
                else
                {
                    inv_sent_peers++;
                }
                free(packet);
            }
        }
        if (pending[i].stem_count > 0)
        {
            size_t packet_len = 0;
            unsigned char *packet =
                bm_create_inventory_message("dinv", pending[i].stem_hashes, pending[i].stem_count, &packet_len);
            if (packet != NULL)
            {
                if (bm_network_write_all(pending[i].fd, packet, packet_len,
                                          BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS)
                    != 0)
                {
                    bm_log_warn("[peer_registry] failed to send dinv to fd=%d\n", pending[i].fd);
                }
                else
                {
                    dinv_sent_peers++;
                }
                free(packet);
            }
        }
        close(pending[i].fd);
        free(pending[i].fluff_hashes);
        free(pending[i].stem_hashes);
    }
    /* §11 2026-08-24: これまで失敗時のログしか無く、正常系(何件のhashを何peerへ
     * 配信できたか)が可視化されていなかった(handle_inv等の可視化と同種の穴、
     * ユーザー指摘)。宛先ごとの個別ログにはせず(peer数が多いと大量に出るため)
     * 1回のbroadcast呼び出しにつき1行のサマリにした。誰にも送るものが無かった
     * (pending_count==0)場合は出さない。 */
    if (pending_count > 0)
    {
        bm_log_debug("[peer_registry] broadcast inv: %zu hash(es) inv to %zu peer(s), dinv to %zu peer(s)\n", count,
                inv_sent_peers, dinv_sent_peers);
    }
    free(pending);
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
