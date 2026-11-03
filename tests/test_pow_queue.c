/*
 * pow/pow_queue.c のテスト。DESIGN.md §11 項目38(PoWをワーカースレッドへ追い出す)。
 *
 * 背景: bm_pow_runは呼び出し元スレッドをPoWが終わるまで止める。getpubkey自応答では
 * network_epoll_threadが止まり、その間すべてのピア接続が停止していた(v4で実測20秒超、
 * ポスト量子v5では期待141秒)。pow_queueは1本のワーカーでPoWを実行し、完了コールバックで
 * object_pool.dbへの登録やbroadcastを行う。
 *
 * 「ワーカーを塞ぐジョブ」としてtarget=0のジョブを使う(trial value <= 0 を満たすnonceは
 * 事実上存在しないので、cancelされるまで終わらない)。これで「呼び出し元がPoWの完了を
 * 待たずに戻ること」を、時間計測ではなく「待っていたら永遠に戻らない」形で決定的に検証できる。
 *
 * 検証観点:
 * 1. q==NULLなら呼び出し元スレッドで同期実行され、submitが戻る前にdoneが正しいobject
 *    (nonce(8byte BE) || payload、nonceはtargetを満たす)で呼ばれること
 * 2. キューを使うと、ワーカーでPoWされてdoneが呼ばれること
 * 3. 同じdedupキーのジョブが走行中・待ち中なら1を返して破棄し(投入時の拒否ではdoneは
 *    呼ばない。§11 Tier 2で契約を変更)、別キー・キー無しは投入されること
 * 4. 待ちジョブ数がmax_pendingに達したら-1で拒否すること(走行中の1本は数えない)
 *    BM_POW_QUEUE_KEY_MAXを超えるキーも-1で拒否すること(黙って「キー無し」にしない)
 * 5. shutdownが走行中のPoWをcancelで打ち切り、走行中・待ちのジョブのdoneをobject==NULLで
 *    呼んで速やかに戻ること。shutdown後のsubmitは-1
 * 6. object_sync経由: ワーカーが塞がっていてもgetpubkeyの受信処理(network_epoll_threadの
 *    ハンドラ)がすぐ戻ること、同じ要求を2回受けても応答PoWは1本しか積まれないこと
 * 7. object_sync経由: キューで実行されたgetpubkey自応答がobject_pool.dbへ入り、応答
 *    キャッシュも更新され、その後の同じ要求ではPoWを積まずにキャッシュを再利用すること
 * 8. onionpeer announceもキュー経由でobject_pool.dbへ入ること
 */

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/message_builder.h"
#include "../src/core/messages_store.h"
#include "../src/core/pubkey_cache.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"
#include "../src/pow/pow_queue.h"

#define TEST_IDENTITY_DB "test_pow_queue_identity.db"
#define TEST_MESSAGES_DB "test_pow_queue_messages.db"
#define TEST_OBJECT_POOL_DB "test_pow_queue_pool.db"

/* 有効なv3 onionアドレスの形式(56文字のbase32 + ".onion")を満たすだけのダミー。
 * 実在するアドレスではない */
#define TEST_ONION_ADDRESS "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

/* doneの呼ばれ方を記録する。ワーカースレッドから書かれ、メインスレッドは
 * bm_pow_queue_completed_count(mutex越し)で完了を確認してから読むか、
 * shutdown(join)の後に読むので、ここ自体には排他制御をしない */
struct record
{
    int calls;
    int null_calls;
    unsigned char *object;
    size_t object_len;
    int64_t now;
};

static void record_done(void *user_data, unsigned char *object, size_t object_len, int64_t now)
{
    struct record *r = user_data;
    r->calls++;
    if (object == NULL)
    {
        r->null_calls++;
        return;
    }
    free(r->object);
    r->object = object;
    r->object_len = object_len;
    r->now = now;
}

static unsigned char *random_payload(size_t len)
{
    unsigned char *p = malloc(len);
    RAND_bytes(p, (int)len);
    return p;
}

/* objectが nonce || payload の形で、nonceがtargetを満たすかを確かめる */
static int object_is_valid(const unsigned char *object, size_t object_len, const unsigned char *payload,
                           size_t payload_len, uint64_t target)
{
    if (object == NULL || object_len != 8 + payload_len || memcmp(object + 8, payload, payload_len) != 0)
    {
        return 0;
    }
    uint64_t nonce = 0;
    for (int i = 0; i < 8; i++)
    {
        nonce = (nonce << 8) | object[i];
    }
    unsigned char initial_hash[64];
    bm_sha512(payload, payload_len, initial_hash);
    return bm_pow_trial_value(nonce, initial_hash) <= target;
}

static int wait_completed(struct bm_pow_queue *q, uint64_t expected)
{
    for (int i = 0; i < 6000; i++) /* 最大60秒 */
    {
        if (bm_pow_queue_completed_count(q) >= expected)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

/* ワーカーがジョブを取り出して走行中になるまで待つ */
static int wait_running(struct bm_pow_queue *q)
{
    for (int i = 0; i < 6000; i++)
    {
        pthread_mutex_lock(&q->mutex);
        int running = q->running != NULL;
        pthread_mutex_unlock(&q->mutex);
        if (running)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

static size_t pending_count(struct bm_pow_queue *q)
{
    pthread_mutex_lock(&q->mutex);
    size_t n = q->pending;
    pthread_mutex_unlock(&q->mutex);
    return n;
}

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void test_sync_fallback(void)
{
    struct record r = {0};
    size_t len = 64;
    unsigned char *payload = random_payload(len);
    unsigned char copy[64];
    memcpy(copy, payload, len);
    uint64_t target = bm_pow_get_target(len, 60, 50, 50);

    int rc = bm_pow_queue_submit(NULL, payload, len, target, NULL, 0, record_done, &r, 12345);
    CHECK(rc == 0, "sync submit returns 0");
    CHECK(r.calls == 1 && r.null_calls == 0, "sync submit calls done before returning");
    CHECK(object_is_valid(r.object, r.object_len, copy, len, target), "sync object is nonce || payload");
    CHECK(r.now == 12345, "sync submit passes the caller's now");
    free(r.object);
}

static void test_async_completion(void)
{
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 8) == 0, "init queue");

    struct record r = {0};
    size_t len = 100;
    unsigned char *payload = random_payload(len);
    unsigned char copy[100];
    memcpy(copy, payload, len);
    uint64_t target = bm_pow_get_target(len, 60, 50, 50);

    CHECK(bm_pow_queue_submit(&q, payload, len, target, NULL, 0, record_done, &r, 0) == 0, "async submit");
    CHECK(wait_completed(&q, 1), "async job completes");
    CHECK(r.calls == 1 && r.null_calls == 0, "async done called once with an object");
    CHECK(object_is_valid(r.object, r.object_len, copy, len, target), "async object is nonce || payload");
    CHECK(r.now > 0, "worker passes its own now");

    bm_pow_queue_shutdown(&q);
    bm_pow_queue_destroy(&q);
    free(r.object);
}

static void test_dedup_limit_and_cancel(void)
{
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 2) == 0, "init queue");

    struct record blocker = {0}, dup = {0}, other = {0}, nokey = {0}, over = {0}, late = {0};
    const unsigned char key_a[] = {'A'};
    const unsigned char key_b[] = {'B'};

    /* target=0: cancelされるまで終わらない */
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, key_a, sizeof(key_a), record_done, &blocker, 0) == 0,
          "submit blocker");
    CHECK(wait_running(&q), "blocker becomes running");

    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, key_a, sizeof(key_a), record_done, &dup, 0) == 1,
          "same key as the running job is deduplicated");
    CHECK(dup.calls == 0, "deduplicated job's done is not called (the caller keeps user_data)");

    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, key_b, sizeof(key_b), record_done, &other, 0) == 0,
          "different key is queued");
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, key_b, sizeof(key_b), record_done, &dup, 0) == 1,
          "same key as a pending job is deduplicated");
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, NULL, 0, record_done, &nokey, 0) == 0,
          "job without key is queued");
    CHECK(pending_count(&q) == 2, "two jobs are pending (the running one is not counted)");
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, NULL, 0, record_done, &over, 0) == -1,
          "submit beyond max_pending is rejected");
    CHECK(over.calls == 0, "rejected job's done is not called");
    unsigned char long_key[BM_POW_QUEUE_KEY_MAX + 1];
    memset(long_key, 'L', sizeof(long_key));
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, long_key, sizeof(long_key), record_done, &over, 0)
              == -1,
          "a key longer than BM_POW_QUEUE_KEY_MAX is rejected instead of silently ignored");

    int64_t start = monotonic_ms();
    bm_pow_queue_shutdown(&q);
    int64_t elapsed = monotonic_ms() - start;
    CHECK(elapsed < 5000, "shutdown cancels the running PoW and returns promptly");
    CHECK(blocker.calls == 1 && blocker.null_calls == 1, "cancelled running job's done is called with NULL");
    CHECK(other.calls == 1 && other.null_calls == 1, "pending job is discarded on shutdown");
    CHECK(nokey.calls == 1 && nokey.null_calls == 1, "pending job without key is discarded on shutdown");

    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, NULL, 0, record_done, &late, 0) == -1,
          "submit after shutdown is rejected");
    CHECK(late.calls == 0, "late job's done is not called");

    bm_pow_queue_shutdown(&q); /* 2回呼んでも安全 */
    bm_pow_queue_destroy(&q);
}

/* --- object_sync経由のシナリオ(test_getpubkey_twin_versions.cと同じ環境の組み方) --- */

static sqlite3 *open_fresh_db(const char *path, int (*init_schema)(sqlite3 *))
{
    unlink(path);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || init_schema(db) != 0)
    {
        fprintf(stderr, "failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }
    return db;
}

struct env
{
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    sqlite3 *object_pool_db;
    bm_keyring_t kr;
    struct bm_peer_registry registry;
    struct bm_object_sync_ctx ctx;
    int fds[2];
    struct bm_fd_data *conn;
    struct bm_generated_address gen;
};

static void env_open(struct env *e, struct bm_pow_queue *q)
{
    e->identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    e->messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    e->object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    bm_keyring_init(&e->kr);
    bm_peer_registry_init(&e->registry);
    bm_object_sync_ctx_init(&e->ctx, e->object_pool_db, e->identity_db, e->messages_db, NULL, &e->kr,
                            &e->registry, NULL);
    e->ctx.pow_queue = q;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, e->fds) == 0, "socketpair");
    e->conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, e->fds[0]);

    /* 応答PoWを軽くするため難易度は50,50(test_getpubkey_twin_versions.cと同じ理由) */
    CHECK(bm_address_generate_deterministic("pow queue getpubkey", 1, &e->gen) == 0, "generate address");
    char *address = bm_address_encode(4, 1, e->gen.ripe, BM_RIPE_LEN);
    CHECK(address != NULL, "encode address");
    CHECK(bm_keyring_create_identity(e->identity_db, address, "powq", 4, 1, e->gen.pub_signing,
                                      e->gen.pub_encryption, e->gen.priv_signing, e->gen.priv_encryption,
                                      "powq pass", 50, 50) == 0,
          "create identity");
    CHECK(bm_keyring_unlock(&e->kr, e->identity_db, address, "powq pass") == 0, "unlock identity");
    free(address);
}

static void env_close(struct env *e)
{
    close(e->fds[0]);
    close(e->fds[1]);
    bm_fd_data_free(e->conn);
    bm_peer_registry_destroy(&e->registry);
    bm_keyring_destroy(&e->kr);
    sqlite3_close(e->identity_db);
    sqlite3_close(e->messages_db);
    sqlite3_close(e->object_pool_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);
}

/* 自分のv4アドレス宛のgetpubkeyを作る(同じ要求を2回受けさせられるよう、組み立てと
 * 受信を分ける)。要求側のPoWはネットワーク既定(1000,1000)。同じ秒に作るとobjectが
 * 同一になり重複として応答処理まで届かないので、2つ目以降はttlを変えて別objectにする */
static unsigned char *build_getpubkey_object(struct env *e, uint64_t ttl, size_t *out_len)
{
    size_t len = 0;
    unsigned char *payload = bm_build_getpubkey(4, 1, e->gen.ripe, (uint64_t)time(NULL) + ttl, &len);
    uint64_t target = bm_pow_get_target(len, ttl, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, len, target);
    unsigned char *object = malloc(8 + len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, len);
    free(payload);
    *out_len = 8 + len;
    return object;
}

static void receive_object(struct env *e, unsigned char *object, size_t object_len)
{
    struct bm_message msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.command, "object", 6);
    msg.length = (uint32_t)object_len;
    msg.payload = object;
    bm_object_sync_dispatch(e->conn, &msg, &e->ctx);
}

static int count_objects(sqlite3 *db, int object_type)
{
    unsigned char(*hashes)[32] = NULL;
    size_t count = 0;
    if (bm_object_store_list_hashes_by_type(db, object_type, &hashes, &count) != 0)
    {
        return -1;
    }
    free(hashes);
    return (int)count;
}

static void test_getpubkey_does_not_block(void)
{
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 8) == 0, "init queue");
    struct env e;
    env_open(&e, &q);

    struct record blocker = {0};
    CHECK(bm_pow_queue_submit(&q, random_payload(32), 32, 0, NULL, 0, record_done, &blocker, 0) == 0,
          "submit blocker");
    CHECK(wait_running(&q), "blocker becomes running");

    /* ワーカーが塞がっている。同期実装のままならここで永遠に戻らない */
    size_t len = 0;
    unsigned char *gp = build_getpubkey_object(&e, 3600, &len);
    receive_object(&e, gp, len);
    CHECK(pending_count(&q) == 1, "getpubkey response PoW is queued without blocking the handler");

    /* 同じアドレス宛の要求をもう一度(ttlを変えてhashの違う別objectにし、重複排除ではなく
     * 応答処理まで確実に通す) */
    size_t len2 = 0;
    unsigned char *gp2 = build_getpubkey_object(&e, 3601, &len2);
    receive_object(&e, gp2, len2);
    CHECK(pending_count(&q) == 1, "a second getpubkey for the same address does not queue a second PoW");
    CHECK(count_objects(e.object_pool_db, BM_OBJECT_PUBKEY) == 0, "no pubkey is stored before the PoW runs");

    bm_pow_queue_shutdown(&q);
    CHECK(count_objects(e.object_pool_db, BM_OBJECT_PUBKEY) == 0, "cancelled response is not stored");
    bm_pow_queue_destroy(&q);
    free(gp);
    free(gp2);
    env_close(&e);
}

static void test_getpubkey_response_via_queue(void)
{
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 8) == 0, "init queue");
    struct env e;
    env_open(&e, &q);

    size_t len = 0;
    unsigned char *gp = build_getpubkey_object(&e, 3600, &len);
    receive_object(&e, gp, len);
    CHECK(wait_completed(&q, 1), "getpubkey response PoW completes");
    CHECK(count_objects(e.object_pool_db, BM_OBJECT_PUBKEY) == 1, "response pubkey is stored in object_pool.db");
    unsigned char cached_hash[32];
    CHECK(bm_pubkey_cache_get_self_response(e.identity_db, e.gen.ripe, 4, 1, (int64_t)time(NULL), cached_hash) == 1,
          "self response cache is updated by the completion callback");

    /* 2回目はキャッシュを再利用する(PoWを積まない) */
    size_t len2 = 0;
    unsigned char *gp2 = build_getpubkey_object(&e, 3601, &len2);
    receive_object(&e, gp2, len2);
    CHECK(pending_count(&q) == 0, "cached response is reused without queuing PoW");
    CHECK(bm_pow_queue_completed_count(&q) == 1, "no second PoW ran");
    CHECK(count_objects(e.object_pool_db, BM_OBJECT_PUBKEY) == 1, "still a single pubkey object");

    /* onionpeer announceもキュー経由で入る */
    CHECK(bm_object_sync_announce_onion_peer(&e.ctx, TEST_ONION_ADDRESS, 8444, (int64_t)time(NULL)) == 0,
          "announce onion peer");
    CHECK(wait_completed(&q, 2), "onionpeer PoW completes");
    CHECK(count_objects(e.object_pool_db, BM_OBJECT_ONIONPEER) == 1, "onionpeer object is stored");

    bm_pow_queue_shutdown(&q);
    bm_pow_queue_destroy(&q);
    free(gp);
    free(gp2);
    env_close(&e);
}

int main(void)
{
    test_sync_fallback();
    test_async_completion();
    test_dedup_limit_and_cancel();
    test_getpubkey_does_not_block();
    test_getpubkey_response_via_queue();

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_pow_queue: all checks passed\n");
    return EXIT_SUCCESS;
}
