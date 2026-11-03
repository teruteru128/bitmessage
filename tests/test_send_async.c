/*
 * DESIGN.md §11 項目38 Tier 2(送信のPoWをAPIスレッドから追い出す)のテスト。
 *
 * 背景: sendMessage/sendBroadcastはAPIハンドラの中でPoWを同期実行しており、API serverは
 * MHDの内部スレッド1本で全リクエストを直列に処理するので、送信のPoW中は他のAPI呼び出しが
 * 全て待たされていた。再送チェックはnetwork_epoll_threadの上で同じPoWを同期実行していた。
 * send_pipelineに非同期版(PoWはpow_queue、ack→msgの2段チェーン)を足し、APIはMHDの
 * suspend/resumeで「返り値の形は変えずに、待たされるのはその接続だけ」にした。
 *
 * 「ワーカーを塞ぐジョブ」はtest_pow_queue.cと同じくtarget=0のジョブ(cancelされるまで
 * 終わらない)を使う。受信にはSO_RCVTIMEOを付けるので、APIが塞がっていればハングではなく
 * 失敗として報告される。
 *
 * 検証観点:
 * 1. send_messageの非同期版がpow_queue上でack→msgの2段を通り(2段目が同じdedupキーで
 *    1段目に弾かれないこと)、sent行を記録してからdoneをrc=0で呼ぶこと
 * 2. 自分宛(ack無しの1段)でもsent行とinboxへのコピーができること
 * 3. 同じreuse_msg_id(再送)のPoWが走行中・待ち中なら1を返し、doneは呼ばないこと。
 *    shutdownで打ち切られたジョブのdoneはrc=-1で呼ばれ、sent行は書かれないこと。
 *    shutdown後の投入は-1でdoneを呼ばないこと
 * 4. HTTP: pow_queueを使うAPI serverでも、sendMessageは従来通りPoWの完了後に
 *    {objectLength, inventoryHash}を返し、そのobjectがbroadcast_queueへ積まれること
 * 5. HTTP: バッチ(sendBroadcast + listAddresses + 通知のsendMessage)が、全ての送信の
 *    完了後に1つの応答配列で返ること(通知の分は応答に含まれないが送信はされる)
 * 6. HTTP: sendMessageがPoW待ちで保留されている間も、別の接続のlistAddressesが応答される
 *    こと。その後pow_queueをshutdownすると、保留中のsendMessageにはerrorの応答が返り、
 *    API serverは正常に停止できること
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/broadcast_item.h"
#include "../src/common/hash.h"
#include "../src/common/queue.h"
#include "../src/core/address.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pubkey_cache.h"
#include "../src/core/send_pipeline.h"
#include "../src/pow/pow_queue.h"

#define TEST_PORT 18453
#define TEST_IDENTITY_DB "test_send_async_identity.db"
#define TEST_MESSAGES_DB "test_send_async_messages.db"

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
    bm_keyring_t kr;
    char *sender;    /* unlock済みの自分のアドレス */
    char *recipient; /* 他人(pubkey_cacheにだけ居る) */
};

/* 自分のidentityを作ってunlockする。応答・送信のPoWを軽くするため難易度は50,50 */
static char *add_identity(struct env *e, const char *passphrase)
{
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic(passphrase, 1, &gen) == 0, "generate address");
    char *address = bm_address_encode(4, 1, gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(e->identity_db, address, "async", 4, 1, gen.pub_signing, gen.pub_encryption,
                                      gen.priv_signing, gen.priv_encryption, "async pass", 50, 50) == 0,
          "create identity");
    CHECK(bm_keyring_unlock(&e->kr, e->identity_db, address, "async pass") == 0, "unlock identity");
    return address;
}

static void env_open(struct env *e)
{
    e->identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    e->messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    bm_keyring_init(&e->kr);
    e->sender = add_identity(e, "send async sender");

    /* 宛先は他人: identity.dbには入れず、pubkey_cacheにだけ登録する(ack付きの2段になる) */
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic("send async recipient", 1, &gen) == 0, "generate recipient");
    e->recipient = bm_address_encode(4, 1, gen.ripe, BM_RIPE_LEN);
    struct bm_cached_pubkey cached;
    memset(&cached, 0, sizeof(cached));
    memcpy(cached.ripe, gen.ripe, BM_RIPE_LEN);
    cached.address_version = 4;
    cached.stream = 1;
    memcpy(cached.signing_pubkey, gen.pub_signing, 65);
    memcpy(cached.encryption_pubkey, gen.pub_encryption, 65);
    cached.nonce_trials_per_byte = 50;
    cached.payload_length_extra_bytes = 50;
    CHECK(bm_pubkey_cache_upsert(e->identity_db, &cached, 1234567890) == 0, "seed pubkey_cache");
}

static void env_close(struct env *e)
{
    free(e->sender);
    free(e->recipient);
    bm_keyring_destroy(&e->kr);
    sqlite3_close(e->identity_db);
    sqlite3_close(e->messages_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
}

static int count_rows(sqlite3 *db, const char *sql, const char *text_param)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    if (text_param != NULL)
    {
        sqlite3_bind_text(stmt, 1, text_param, -1, SQLITE_TRANSIENT);
    }
    int n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        n = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return n;
}

/* doneの記録。ワーカースレッドから書かれ、メインスレッドはcalls(atomic)を見てから読む */
struct send_record
{
    atomic_int calls;
    int rc;
    size_t object_len;
};

static void record_send_done(void *user_data, int rc, unsigned char *object, size_t object_len, int64_t now)
{
    (void)now;
    struct send_record *r = user_data;
    r->rc = rc;
    r->object_len = object_len;
    free(object);
    atomic_fetch_add(&r->calls, 1);
}

static int wait_calls(struct send_record *r, int expected)
{
    for (int i = 0; i < 6000; i++) /* 最大60秒 */
    {
        if (atomic_load(&r->calls) >= expected)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

static void blocker_done(void *user_data, unsigned char *object, size_t object_len, int64_t now)
{
    (void)user_data;
    (void)object_len;
    (void)now;
    free(object);
}

/* target=0のジョブでワーカーを塞ぎ、走行中になるまで待つ */
static void block_worker(struct bm_pow_queue *q)
{
    unsigned char *payload = malloc(32);
    RAND_bytes(payload, 32);
    CHECK(bm_pow_queue_submit(q, payload, 32, 0, NULL, 0, blocker_done, NULL, 0) == 0, "submit blocker");
    for (int i = 0; i < 6000; i++)
    {
        pthread_mutex_lock(&q->mutex);
        int running = q->running != NULL;
        pthread_mutex_unlock(&q->mutex);
        if (running)
        {
            return;
        }
        usleep(10000);
    }
    CHECK(0, "blocker becomes running");
}

static void test_pipeline_async(void)
{
    struct env e;
    env_open(&e);
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 8) == 0, "init queue");
    int64_t now = (int64_t)time(NULL);

    /* 1. 他人宛: ack→msgの2段 */
    struct send_record r1 = {0};
    CHECK(bm_send_pipeline_send_message_async(&q, &e.kr, e.identity_db, e.messages_db, e.sender, e.recipient,
                                              "async subject", "async body", 300, 1, NULL, now + 3600, now,
                                              record_send_done, &r1) == 0,
          "async send to another user is accepted");
    CHECK(wait_calls(&r1, 1), "async send completes");
    CHECK(r1.rc == 0 && r1.object_len > 0, "async send succeeds through the ack -> msg chain");
    CHECK(count_rows(e.messages_db, "SELECT COUNT(*) FROM sent WHERE to_address = ?1 AND status = 'sent' "
                                    "AND length(ack_data) > 0;",
                     e.recipient) == 1,
          "sent row with the ack object is recorded before done");

    /* 2. 自分宛: ack無しの1段、inboxへコピー */
    struct send_record r2 = {0};
    CHECK(bm_send_pipeline_send_message_async(&q, &e.kr, e.identity_db, e.messages_db, e.sender, e.sender,
                                              "self subject", "self body", 300, 1, NULL, now + 3600, now,
                                              record_send_done, &r2) == 0,
          "async send to self is accepted");
    CHECK(wait_calls(&r2, 1), "async self send completes");
    CHECK(r2.rc == 0, "async self send succeeds");
    CHECK(count_rows(e.messages_db, "SELECT COUNT(*) FROM sent WHERE status = 'msgsentnoackexpected';", NULL) == 1,
          "self send is recorded as msgsentnoackexpected");
    CHECK(count_rows(e.messages_db, "SELECT COUNT(*) FROM inbox WHERE to_address = ?1;", e.sender) == 1,
          "self send is copied into the inbox");

    /* 3. 再送のdedupとshutdown */
    block_worker(&q);
    unsigned char msg_id[32];
    RAND_bytes(msg_id, sizeof(msg_id));
    struct send_record r3 = {0}, r4 = {0}, r5 = {0};
    CHECK(bm_send_pipeline_send_message_async(&q, &e.kr, e.identity_db, e.messages_db, e.sender, e.recipient,
                                              "resend", "resend body", 300, 1, msg_id, now + 3600, now,
                                              record_send_done, &r3) == 0,
          "first resend is queued behind the blocker");
    CHECK(bm_send_pipeline_send_message_async(&q, &e.kr, e.identity_db, e.messages_db, e.sender, e.recipient,
                                              "resend", "resend body", 300, 1, msg_id, now + 3600, now,
                                              record_send_done, &r4) == 1,
          "second resend of the same msg_id is deduplicated");
    CHECK(atomic_load(&r4.calls) == 0, "done is not called for a deduplicated resend");

    bm_pow_queue_shutdown(&q);
    CHECK(atomic_load(&r3.calls) == 1 && r3.rc == -1, "queued resend is reported as failed on shutdown");
    CHECK(count_rows(e.messages_db, "SELECT COUNT(*) FROM sent WHERE subject = ?1;", "resend") == 0,
          "cancelled send does not write a sent row");
    CHECK(bm_send_pipeline_send_message_async(&q, &e.kr, e.identity_db, e.messages_db, e.sender, e.recipient,
                                              "late", "late body", 300, 1, NULL, now + 3600, now,
                                              record_send_done, &r5) == -1,
          "send after shutdown is rejected");
    CHECK(atomic_load(&r5.calls) == 0, "done is not called for a rejected send");
    bm_pow_queue_destroy(&q);
    env_close(&e);
}

/* --- HTTP --- */

/* JSON-RPCのボディを1本送り、応答全体(ヘッダ込み)をmallocして返す。受信は最大timeout_sec秒 */
static char *http_post(const char *body, int timeout_sec)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {timeout_sec, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        return NULL;
    }
    char header[256];
    int header_len = snprintf(header, sizeof(header),
                              "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                              strlen(body));
    if (write(sock, header, (size_t)header_len) != header_len
        || write(sock, body, strlen(body)) != (ssize_t)strlen(body))
    {
        close(sock);
        return NULL;
    }
    size_t cap = 16384;
    size_t total = 0;
    char *buf = malloc(cap);
    ssize_t n;
    while ((n = read(sock, buf + total, cap - 1 - total)) > 0)
    {
        total += (size_t)n;
        if (total + 1 >= cap)
        {
            break;
        }
    }
    close(sock);
    buf[total] = '\0';
    if (total == 0)
    {
        free(buf);
        return NULL;
    }
    return buf;
}

static size_t queued_items(bm_queue_t *q)
{
    pthread_mutex_lock(&q->mutex);
    size_t n = 0;
    for (bm_queue_node_t *node = q->head; node != NULL; node = node->next)
    {
        n++;
    }
    pthread_mutex_unlock(&q->mutex);
    return n;
}

static int wait_queued_items(bm_queue_t *q, size_t expected)
{
    for (int i = 0; i < 6000; i++)
    {
        if (queued_items(q) >= expected)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

/* broadcast_queueの先頭の要素を取り出し、そのinventory hashをhexで返す */
static void pop_inv_hex(bm_queue_t *q, char out_hex[65])
{
    void *raw = NULL;
    out_hex[0] = '\0';
    if (!bm_queue_pop(q, &raw))
    {
        return;
    }
    struct bm_broadcast_item *item = raw;
    unsigned char hash[32];
    bm_inventory_hash(item->object, item->object_len, hash);
    for (int i = 0; i < 32; i++)
    {
        snprintf(out_hex + i * 2, 3, "%02x", hash[i]);
    }
    free(item->object);
    free(item);
}

struct client_arg
{
    const char *body;
    char *response;
    atomic_int finished;
};

static void *client_thread(void *arg_)
{
    struct client_arg *arg = arg_;
    arg->response = http_post(arg->body, 60);
    atomic_store(&arg->finished, 1);
    return NULL;
}

static void test_http(void)
{
    struct env e;
    env_open(&e);
    struct bm_pow_queue q;
    CHECK(bm_pow_queue_init(&q, 8) == 0, "init queue");
    bm_queue_t broadcast_queue;
    bm_queue_init(&broadcast_queue);

    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = NULL; /* 認証なし(テスト用) */
    config.keyring = &e.kr;
    config.identity_db = e.identity_db;
    config.messages_db = e.messages_db;
    config.broadcast_queue = &broadcast_queue;
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;
    config.pow_queue = &q;

    _Atomic sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args);
    usleep(200000);

    /* 4. 単発のsendMessage */
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\",\"params\":[\"%s\",\"%s\",\"http subject\","
             "\"http body\",300],\"id\":1}",
             e.sender, e.recipient);
    char *resp = http_post(body, 60);
    CHECK(resp != NULL && strstr(resp, "\"objectLength\"") != NULL && strstr(resp, "\"inventoryHash\"") != NULL,
          "sendMessage still returns objectLength and inventoryHash after the PoW");
    CHECK(wait_queued_items(&broadcast_queue, 1), "sendMessage pushes the object to broadcast_queue");
    char inv_hex[65];
    pop_inv_hex(&broadcast_queue, inv_hex);
    CHECK(resp != NULL && inv_hex[0] != '\0' && strstr(resp, inv_hex) != NULL,
          "returned inventoryHash matches the queued object");
    free(resp);

    /* 5. バッチ: sendBroadcast + listAddresses + 通知(id無し)のsendMessage */
    char batch[2048];
    snprintf(batch, sizeof(batch),
             "[{\"jsonrpc\":\"2.0\",\"method\":\"sendBroadcast\",\"params\":[\"%s\",\"b subject\",\"b body\",300],"
             "\"id\":10},"
             "{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":11},"
             "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\",\"params\":[\"%s\",\"%s\",\"n subject\",\"n body\",300]}]",
             e.sender, e.sender, e.recipient);
    resp = http_post(batch, 60);
    CHECK(resp != NULL && strstr(resp, "\"id\":10") != NULL && strstr(resp, "\"id\":11") != NULL,
          "batch returns responses for the two requests with ids");
    CHECK(resp != NULL && strstr(resp, "\"inventoryHash\"") != NULL, "batch sendBroadcast result is filled in");
    CHECK(wait_queued_items(&broadcast_queue, 2), "both the broadcast and the notification send are queued");
    pop_inv_hex(&broadcast_queue, inv_hex);
    pop_inv_hex(&broadcast_queue, inv_hex);
    free(resp);

    /* 6. 保留中でも他の接続は応答される */
    block_worker(&q);
    struct client_arg client = {body, NULL, 0};
    pthread_t client_tid;
    pthread_create(&client_tid, NULL, client_thread, &client);
    usleep(300000); /* sendMessageがsuspendされるまでの猶予(短くても検証の正しさは変わらない) */

    char *list = http_post("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":20}", 10);
    CHECK(list != NULL && strstr(list, "\"id\":20") != NULL,
          "another API call is answered while sendMessage is waiting for its PoW");
    CHECK(atomic_load(&client.finished) == 0, "the sendMessage request is still pending behind the blocker");
    free(list);

    bm_pow_queue_shutdown(&q);
    pthread_join(client_tid, NULL);
    CHECK(client.response != NULL && strstr(client.response, "\"error\"") != NULL
              && strstr(client.response, "send failed after its PoW was queued") != NULL,
          "pending sendMessage gets an error response when the PoW is cancelled");
    free(client.response);

    server_stop = 1;
    pthread_join(server_thread, NULL);
    bm_pow_queue_destroy(&q);
    bm_queue_shutdown(&broadcast_queue);
    bm_queue_destroy(&broadcast_queue);
    env_close(&e);
}

int main(void)
{
    test_pipeline_async();
    test_http();

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_send_async: all checks passed\n");
    return EXIT_SUCCESS;
}
