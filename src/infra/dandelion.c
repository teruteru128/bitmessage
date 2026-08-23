#include "dandelion.h"

#include <math.h>
#include <openssl/rand.h>
#include <pthread.h>
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

/* g_state.lockを保持したまま呼ぶこと。既存エントリを返すか、無ければ新規作成して返す
 * (この時点でタイムアウトも決定する)。malloc失敗時のみNULL */
static struct dandelion_entry *find_or_create_entry(const unsigned char hash[32], int64_t now)
{
    for (size_t i = 0; i < g_state.entry_count; i++)
    {
        if (memcmp(g_state.entries[i].hash, hash, 32) == 0)
        {
            return &g_state.entries[i];
        }
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
    struct dandelion_entry *e = &g_state.entries[g_state.entry_count++];
    memcpy(e->hash, hash, 32);
    e->fluff_deadline =
        now + BM_DANDELION_TIMEOUT_BASE_SECONDS + (int64_t)exponential_random(BM_DANDELION_TIMEOUT_MEAN_SECONDS);
    e->fluffed_at = 0;
    e->learned_via_plain_inv = 0; /* 既定はstem対象(自分発object、またはprovenance不明) */
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
    pthread_mutex_unlock(&g_state.lock);

    for (size_t i = 0; i < to_fluff_count; i++)
    {
        bm_peer_registry_broadcast_inv(registry, &to_fluff[i], 1, NULL);
    }
    return (int)to_fluff_count;
}
