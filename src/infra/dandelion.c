#include "dandelion.h"

#include <math.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BM_DANDELION_EPOCH_SECONDS 600
#define BM_DANDELION_TIMEOUT_BASE_SECONDS 10
#define BM_DANDELION_TIMEOUT_MEAN_SECONDS 30.0
/* fluff済みになってからこの秒数以上経過したエントリは間引く(無制限のメモリ増加を防ぐ、
 * DESIGN.md §9.2ではhashMapのDB永続化は不要としているのと同じ発想で、プロセス内メモリの
 * 掃除だけ考えればよい) */
#define BM_DANDELION_ENTRY_PRUNE_AGE_SECONDS 300
/* 1回のbm_dandelion_expire_and_refluff呼び出しでまとめてfluffする上限(1秒間隔で呼ばれる
 * 想定のため、1秒間にこれ以上のobjectが同時にstemタイムアウトを迎えることは通常無い) */
#define BM_DANDELION_MAX_EXPIRE_PER_CALL 64

/* §11 2026-08-23発覚の重大な性能バグ修正: find_or_create_entryがg_state.entriesを
 * 先頭から線形探索(memcmp)していたため、handle_inv(未所持hashごとに呼ぶ)や
 * send_big_inv(保有する全hashごとに呼ぶ)がO(n^2)になっていた。今夜object_pool.dbが
 * 1万件規模まで育った状態でsend_big_invを1回呼ぶだけで概算5000万回超のmemcmpが発生し、
 * g_state.lockを握ったまま単一のnetwork_epoll_thread全体を一瞬止めていた(新規peerが
 * 繋がるたびに発生し、object_pool.dbが増えるほど二次関数的に悪化する)。相手から見ると
 * 「handshake後しばらく応答が無いnode」に見えてタイムアウト切断されうる、今夜観測していた
 * 接続churnの有力な一因と考えられる。
 *
 * オープンアドレッシング(線形探索、hash先頭8byteをキーにした単純なもの。Bitmessageの
 * hashは既に暗号学的ハッシュ値のため先頭8byteだけで十分一様分布する)のハッシュテーブルを
 * g_state.entriesと並行して持たせ、O(1)平均でfind_or_create_entryできるようにした。
 * g_state.entriesはbm_dandelion_expire_and_refluffの定期的な全走査(fluffタイムアウト
 * 判定・古いエントリの間引き)用に配列のまま維持し、間引き後(要素の位置がずれる)にだけ
 * インデックスを再構築する(その関数自体が既にO(n)なので、再構築を足しても計算量は
 * 変わらない)。 */
#define BM_DANDELION_INDEX_INITIAL_CAPACITY 128
#define BM_DANDELION_INDEX_EMPTY SIZE_MAX

struct dandelion_entry
{
    unsigned char hash[32];
    int64_t fluff_deadline;
    int64_t fluffed_at; /* 0 = まだfluffしていない */
    /* §9.5 Stage 3: このhashを最初にどちらのコマンドで知ったか。0(既定、自分発object
     * またはまだ不明)ならstem→タイムアウトfluffの通常経路。1(通常inv経由、既に他ノードが
     * fluff済み)ならstemを一切試みず即座にFLUFFする(bm_dandelion_note_source参照)。 */
    int learned_via_plain_inv;
};

static struct
{
    pthread_mutex_t lock;

    char stem_ip[BM_PEER_IP_STRLEN];
    int stem_port;
    int has_stem;
    int64_t epoch_started; /* 0 = まだ一度も抽選していない */

    struct dandelion_entry *entries;
    size_t entry_count;
    size_t entry_capacity;

    /* §11 2026-08-23: find_or_create_entry高速化用インデックス(上記doc参照)。
     * index_slots[i]はg_state.entriesのインデックス、BM_DANDELION_INDEX_EMPTYなら空き
     * スロット。entry_countとは独立してcapacityを管理する(負荷率50%を超えたら倍に
     * 拡張する、index_ensure_capacity参照)。 */
    size_t *index_slots;
    size_t index_capacity;
} g_state;

/* g_state.lockが初期化済みかどうか(未初期化のmutexをdestroy/lockするのはUBのため、
 * 二重初期化を安全にするために別途フラグで管理する) */
static int g_state_lock_initialized = 0;

void bm_dandelion_module_init(void)
{
    if (g_state_lock_initialized)
    {
        pthread_mutex_destroy(&g_state.lock);
    }
    free(g_state.entries);
    free(g_state.index_slots);
    memset(&g_state, 0, sizeof(g_state));
    pthread_mutex_init(&g_state.lock, NULL);
    g_state_lock_initialized = 1;
}

/* 平均meanの指数分布に従う乱数を返す(逆関数法)。タイミング解析対策の揺らぎ用であり
 * 暗号強度は不要だが、他のnonce生成箇所と同様RAND_bytesで揃えた */
static double exponential_random(double mean)
{
    unsigned char buf[4];
    RAND_bytes(buf, sizeof(buf));
    uint32_t r;
    memcpy(&r, buf, sizeof(r));
    /* (0,1)の開区間に収める(u=0だとlog(0)で発散するため+1、u=1にならないよう+2で正規化) */
    double u = ((double)r + 1.0) / (4294967296.0 + 1.0);
    return -mean * log(u);
}

/* hash先頭8byteをそのままキーにする(既に暗号学的ハッシュ値のため十分一様分布する、
 * 追加のハッシュ関数は不要)。 */
static uint64_t index_key(const unsigned char hash[32])
{
    uint64_t key;
    memcpy(&key, hash, sizeof(key));
    return key;
}

/* g_state.lockを保持したまま呼ぶこと。g_state.entries[0..entry_count)の内容から
 * インデックスをcapacity個のスロットで作り直す(古い内容は破棄)。
 * bm_dandelion_expire_and_refluffがg_state.entriesを間引いて要素の位置がずれた直後や、
 * 負荷率が高くなり拡張が必要な時に呼ぶ。malloc失敗時は既存のindex_slotsを維持したまま
 * 諦める(呼び出し元はindex_capacityが変わっていないことを前提にできる)。 */
static void index_rebuild(size_t capacity)
{
    size_t *slots = malloc(sizeof(*slots) * capacity);
    if (slots == NULL)
    {
        return;
    }
    for (size_t i = 0; i < capacity; i++)
    {
        slots[i] = BM_DANDELION_INDEX_EMPTY;
    }
    for (size_t i = 0; i < g_state.entry_count; i++)
    {
        size_t slot = (size_t)(index_key(g_state.entries[i].hash) % capacity);
        while (slots[slot] != BM_DANDELION_INDEX_EMPTY)
        {
            slot = (slot + 1) % capacity;
        }
        slots[slot] = i;
    }
    free(g_state.index_slots);
    g_state.index_slots = slots;
    g_state.index_capacity = capacity;
}

/* 負荷率(entry_count/index_capacity)が50%を超えないよう、必要なら拡張(倍に)する。
 * g_state.lockを保持したまま呼ぶこと。 */
static void index_ensure_capacity(void)
{
    if (g_state.index_capacity == 0)
    {
        index_rebuild(BM_DANDELION_INDEX_INITIAL_CAPACITY);
        return;
    }
    if ((g_state.entry_count + 1) * 2 > g_state.index_capacity)
    {
        index_rebuild(g_state.index_capacity * 2);
    }
}

/* hashが見つかればそのentries内インデックス、無ければBM_DANDELION_INDEX_EMPTYを返す。
 * g_state.lockを保持したまま呼ぶこと。index_slots未初期化(capacity==0、通常は
 * find_or_create_entryがindex_ensure_capacityで先に確保しているため起きない)の場合も
 * 安全にBM_DANDELION_INDEX_EMPTYを返す。 */
static size_t index_lookup(const unsigned char hash[32])
{
    if (g_state.index_capacity == 0)
    {
        return BM_DANDELION_INDEX_EMPTY;
    }
    size_t slot = (size_t)(index_key(hash) % g_state.index_capacity);
    for (size_t probes = 0; probes < g_state.index_capacity; probes++)
    {
        size_t idx = g_state.index_slots[slot];
        if (idx == BM_DANDELION_INDEX_EMPTY)
        {
            return BM_DANDELION_INDEX_EMPTY; /* このhashは無い(空きスロットに到達) */
        }
        if (memcmp(g_state.entries[idx].hash, hash, 32) == 0)
        {
            return idx;
        }
        slot = (slot + 1) % g_state.index_capacity;
    }
    return BM_DANDELION_INDEX_EMPTY; /* 理論上index_ensure_capacityのおかげで起きないはず */
}

/* g_state.lockを保持したまま呼ぶこと。既存エントリを返すか、無ければ新規作成して返す
 * (この時点でタイムアウトも決定する)。malloc失敗時のみNULL */
static struct dandelion_entry *find_or_create_entry(const unsigned char hash[32], int64_t now)
{
    size_t existing = index_lookup(hash);
    if (existing != BM_DANDELION_INDEX_EMPTY)
    {
        return &g_state.entries[existing];
    }

    if (g_state.entry_count >= g_state.entry_capacity)
    {
        size_t new_cap = g_state.entry_capacity == 0 ? 64 : g_state.entry_capacity * 2;
        struct dandelion_entry *grown = realloc(g_state.entries, sizeof(*grown) * new_cap);
        if (grown == NULL)
        {
            return NULL;
        }
        g_state.entries = grown;
        g_state.entry_capacity = new_cap;
    }
    struct dandelion_entry *e = &g_state.entries[g_state.entry_count];
    size_t new_index = g_state.entry_count;
    g_state.entry_count++;
    memcpy(e->hash, hash, 32);
    e->fluff_deadline =
        now + BM_DANDELION_TIMEOUT_BASE_SECONDS + (int64_t)exponential_random(BM_DANDELION_TIMEOUT_MEAN_SECONDS);
    e->fluffed_at = 0;
    e->learned_via_plain_inv = 0; /* 既定はstem対象(自分発object、またはprovenance不明) */

    /* インデックスへ登録する。entries配列を伸ばした直後でも(realloc)既存の
     * index_slotsが指すインデックス番号自体は不変(位置がずれるのはentries配列の中身の
     * 並び替え時=間引き時だけ)なので、そのまま追記できる。負荷率次第でここが拡張の
     * トリガーにもなる(次回呼び出し用、今回のnew_indexの登録は拡張後のテーブルへ行う) */
    index_ensure_capacity();
    /* §11 2026-08-24発覚: index_rebuildのmalloc失敗時、g_state.index_capacityが0のまま
     * 呼び出し元へ戻ってくる(index_rebuild自身はエラー時に既存の状態を維持したまま
     * 諦める設計、上記doc参照)。それに気付かず%g_state.index_capacityへ進むと
     * ゼロ除算(SIGFPE)になる。エントリ自体はentries配列には既に追加済みなので、
     * この場合は索引登録だけ諦める(次回find_or_create_entry呼び出し時、索引に
     * 無いため線形探索フォールバックは無いが、次のindex_ensure_capacity呼び出しで
     * 再度拡張を試みるため、メモリ不足が解消すれば自然に復旧する)。 */
    if (g_state.index_capacity == 0)
    {
        return e;
    }
    size_t slot = (size_t)(index_key(hash) % g_state.index_capacity);
    while (g_state.index_slots[slot] != BM_DANDELION_INDEX_EMPTY)
    {
        slot = (slot + 1) % g_state.index_capacity;
    }
    g_state.index_slots[slot] = new_index;

    return e;
}

void bm_dandelion_note_source(const unsigned char object_hash[32], int is_dinv, int64_t now)
{
    if (is_dinv)
    {
        /* dinv経由はstem継続が既定動作のまま(find_or_create_entryのlearned_via_plain_inv=0と
         * 同じ)なので、わざわざエントリを先回りして作る必要は無い。呼び出し元
         * (object_sync.cのhandle_inv)からの一律呼び出しを許容するための早期returnであり、
         * この関数はis_dinv=0の場合にのみ実質的な意味を持つ。 */
        return;
    }
    pthread_mutex_lock(&g_state.lock);
    struct dandelion_entry *e = find_or_create_entry(object_hash, now);
    if (e != NULL)
    {
        e->learned_via_plain_inv = 1;
    }
    pthread_mutex_unlock(&g_state.lock);
}

void bm_dandelion_maybe_reshuffle(struct bm_peer_registry *registry, int64_t now)
{
    pthread_mutex_lock(&g_state.lock);
    if (g_state.epoch_started != 0 && now - g_state.epoch_started < BM_DANDELION_EPOCH_SECONDS)
    {
        pthread_mutex_unlock(&g_state.lock);
        return;
    }
    g_state.epoch_started = now;

    char ip[BM_PEER_IP_STRLEN];
    int port = 0;
    int found = bm_peer_registry_pick_random_dandelion_peer(registry, ip, sizeof(ip), &port);
    if (found)
    {
        strncpy(g_state.stem_ip, ip, sizeof(g_state.stem_ip) - 1);
        g_state.stem_ip[sizeof(g_state.stem_ip) - 1] = '\0';
        g_state.stem_port = port;
        g_state.has_stem = 1;
    }
    else
    {
        g_state.has_stem = 0;
    }
    pthread_mutex_unlock(&g_state.lock);
}

enum bm_propagation_mode bm_dandelion_decide(const unsigned char object_hash[32],
                                              const struct bm_fd_data *target_connection, int64_t now)
{
    pthread_mutex_lock(&g_state.lock);
    struct dandelion_entry *e = find_or_create_entry(object_hash, now);
    if (e == NULL)
    {
        /* mallocエラー時は安全側(fluff、確実に配信する)に倒す */
        pthread_mutex_unlock(&g_state.lock);
        return BM_PROPAGATE_FLUFF;
    }

    if (e->fluffed_at != 0 || now >= e->fluff_deadline || !g_state.has_stem || e->learned_via_plain_inv)
    {
        if (e->fluffed_at == 0)
        {
            e->fluffed_at = now;
        }
        pthread_mutex_unlock(&g_state.lock);
        return BM_PROPAGATE_FLUFF;
    }

    enum bm_propagation_mode result = BM_PROPAGATE_SKIP;
    if (target_connection != NULL)
    {
        char ip[BM_PEER_IP_STRLEN];
        int port = 0;
        bm_network_resolve_peer_ip_port(target_connection, ip, sizeof(ip), &port);
        if (port == g_state.stem_port && strcmp(ip, g_state.stem_ip) == 0)
        {
            result = BM_PROPAGATE_STEM;
        }
    }
    pthread_mutex_unlock(&g_state.lock);
    return result;
}

int bm_dandelion_expire_and_refluff(struct bm_peer_registry *registry, int64_t now)
{
    unsigned char to_fluff[BM_DANDELION_MAX_EXPIRE_PER_CALL][32];
    size_t to_fluff_count = 0;

    pthread_mutex_lock(&g_state.lock);
    for (size_t i = 0; i < g_state.entry_count && to_fluff_count < BM_DANDELION_MAX_EXPIRE_PER_CALL; i++)
    {
        struct dandelion_entry *e = &g_state.entries[i];
        if (e->fluffed_at == 0 && now >= e->fluff_deadline)
        {
            e->fluffed_at = now;
            memcpy(to_fluff[to_fluff_count], e->hash, 32);
            to_fluff_count++;
        }
    }

    /* 古いfluff済みエントリを間引く */
    size_t original_count = g_state.entry_count;
    size_t write = 0;
    for (size_t i = 0; i < g_state.entry_count; i++)
    {
        struct dandelion_entry *e = &g_state.entries[i];
        if (e->fluffed_at != 0 && now - e->fluffed_at > BM_DANDELION_ENTRY_PRUNE_AGE_SECONDS)
        {
            continue; /* 書き戻さない=削除 */
        }
        if (write != i)
        {
            g_state.entries[write] = g_state.entries[i];
        }
        write++;
    }
    g_state.entry_count = write;
    /* §11 2026-08-23: 間引きでentries内の要素が移動した(=以前のインデックスが古い
     * ハッシュを指さなくなった)場合のみ、find_or_create_entry高速化用インデックスを
     * 作り直す。何も間引かれなかった通常時は位置がずれないため不要(この関数は1秒間隔で
     * 呼ばれる想定のため、毎回無条件で再構築するとそれ自体がO(n)コストの積み重ねになる)。 */
    if (write != original_count && g_state.index_capacity > 0)
    {
        index_rebuild(g_state.index_capacity);
    }
    pthread_mutex_unlock(&g_state.lock);

    for (size_t i = 0; i < to_fluff_count; i++)
    {
        bm_peer_registry_broadcast_inv(registry, &to_fluff[i], 1, NULL);
    }
    return (int)to_fluff_count;
}
