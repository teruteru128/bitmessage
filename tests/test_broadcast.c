/*
 * §5.4/§11 broadcast購読・復号のテスト。
 * - 購読中のアドレスからのbroadcastが復号されinboxへ保存されること(v4/v5両方の
 *   objectVersion、つまりaddressVersion<=3と>=4の両方)
 * - 購読していないアドレスからのbroadcastは復号されないこと
 * - remove-subscription後は復号されなくなること
 * - addSubscription/listSubscriptions/sendBroadcast APIが実HTTPリクエスト経由で
 *   動作すること
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/broadcast_item.h"
#include "../src/common/json.h"
#include "../src/core/address.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/message_builder.h"
#include "../src/core/messages_store.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"

#define TEST_PORT 18444
#define TEST_IDENTITY_DB "test_broadcast_identity.db"
#define TEST_MESSAGES_DB "test_broadcast_messages.db"
#define TEST_OBJECT_POOL_DB "test_broadcast_pool.db"

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
        fprintf(stderr, "FATAL: could not open/init %s\n", path);
        exit(EXIT_FAILURE);
    }
    return db;
}

static void make_identity(const char *passphrase, uint64_t version, struct bm_identity_info *out_id,
                           unsigned char out_ripe[20])
{
    struct bm_generated_address gen;
    if (bm_address_generate_deterministic(passphrase, 1, &gen) != 0)
    {
        fprintf(stderr, "FATAL: generate_deterministic failed\n");
        exit(EXIT_FAILURE);
    }
    memset(out_id, 0, sizeof(*out_id));
    out_id->address_version = version;
    out_id->stream = 1;
    memcpy(out_id->pub_signing, gen.pub_signing, 65);
    memcpy(out_id->pub_encryption, gen.pub_encryption, 65);
    memcpy(out_id->priv_signing, gen.priv_signing, 32);
    out_id->nonce_trials_per_byte = 50;
    out_id->payload_length_extra_bytes = 50;
    out_id->does_ack = 0;
    memcpy(out_ripe, gen.ripe, 20);
}

/* subjectのbroadcastを実PoW付きで組み立てて"object"メッセージとして返す(呼び出し側でfree) */
/* §11のPoW検証(受信側)はexpires_time-nowからttlを再計算しネットワーク既定の最低難易度
 * (1000,1000)を満たすか確認するため、expires_timeは固定の遠い未来ではなくnow+ttlにし、
 * PoW計算時のttl・難易度と一致させる必要がある */
static unsigned char *build_broadcast_object(const struct bm_identity_info *id, const unsigned char ripe[20],
                                              const char *subject, const char *body, size_t *out_len)
{
    uint64_t ttl = 3600;
    size_t payload_len = 0;
    unsigned char *payload = bm_build_broadcast(id, ripe, subject, body, (uint64_t)time(NULL) + ttl, &payload_len);
    if (payload == NULL)
    {
        return NULL;
    }
    uint64_t target = bm_pow_get_target(payload_len, ttl, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);

    *out_len = object_len;
    return object;
}

static int inbox_count(sqlite3 *messages_db)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT COUNT(*) FROM inbox;", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

int main(void)
{
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);
    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);
    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, NULL, &kr, &registry, NULL);

    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);

    /* --- 1. objectVersion=4(addressVersion<=3)のbroadcast、購読中 --- */
    struct bm_identity_info broadcaster_v3;
    unsigned char broadcaster_v3_ripe[20];
    make_identity("broadcast test v3 broadcaster", 3, &broadcaster_v3, broadcaster_v3_ripe);
    char *broadcaster_v3_address = bm_address_encode(3, 1, broadcaster_v3_ripe, BM_RIPE_LEN);

    CHECK(bm_messages_store_add_subscription(messages_db, broadcaster_v3_address, "v3 broadcaster") == 0,
          "subscribe to v3 broadcaster");

    size_t obj_v4_len = 0;
    unsigned char *obj_v4 = build_broadcast_object(&broadcaster_v3, broadcaster_v3_ripe, "v4 wire broadcast",
                                                     "objectVersion=4 (addressVersion<=3) body", &obj_v4_len);
    CHECK(obj_v4 != NULL, "build v4-wire broadcast object");

    struct bm_message msg_v4;
    memset(&msg_v4, 0, sizeof(msg_v4));
    memcpy(msg_v4.command, "object", 6);
    msg_v4.length = (uint32_t)obj_v4_len;
    msg_v4.payload = obj_v4;
    bm_object_sync_dispatch(conn, &msg_v4, &ctx);
    free(obj_v4);

    CHECK(inbox_count(messages_db) == 1, "subscribed v3 broadcaster's broadcast should be decrypted into inbox");

    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT to_address, from_address, subject, body FROM inbox;", -1, &stmt, NULL);
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 0), broadcaster_v3_address) == 0,
              "broadcast inbox row to_address == from_address (§5.4 convention)");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 1), broadcaster_v3_address) == 0,
              "broadcast inbox row from_address matches broadcaster");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 2), "v4 wire broadcast") == 0,
              "broadcast subject matches");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 3), "objectVersion=4 (addressVersion<=3) body") == 0,
              "broadcast body matches");
    }
    sqlite3_finalize(stmt);

    /* --- 2. objectVersion=5(addressVersion>=4)のbroadcast、購読中 --- */
    struct bm_identity_info broadcaster_v4;
    unsigned char broadcaster_v4_ripe[20];
    make_identity("broadcast test v4 broadcaster", 4, &broadcaster_v4, broadcaster_v4_ripe);
    char *broadcaster_v4_address = bm_address_encode(4, 1, broadcaster_v4_ripe, BM_RIPE_LEN);
    CHECK(bm_messages_store_add_subscription(messages_db, broadcaster_v4_address, "v4 broadcaster") == 0,
          "subscribe to v4 broadcaster");

    size_t obj_v5_len = 0;
    unsigned char *obj_v5 = build_broadcast_object(&broadcaster_v4, broadcaster_v4_ripe, "v5 wire broadcast",
                                                     "objectVersion=5 (addressVersion>=4) body", &obj_v5_len);
    CHECK(obj_v5 != NULL, "build v5-wire broadcast object");

    struct bm_message msg_v5;
    memset(&msg_v5, 0, sizeof(msg_v5));
    memcpy(msg_v5.command, "object", 6);
    msg_v5.length = (uint32_t)obj_v5_len;
    msg_v5.payload = obj_v5;
    bm_object_sync_dispatch(conn, &msg_v5, &ctx);
    free(obj_v5);

    CHECK(inbox_count(messages_db) == 2, "subscribed v4 broadcaster's broadcast should also be decrypted into inbox");

    /* --- 3. 購読していないアドレスからのbroadcastは復号されない --- */
    struct bm_identity_info stranger;
    unsigned char stranger_ripe[20];
    make_identity("broadcast test unsubscribed stranger", 4, &stranger, stranger_ripe);

    size_t obj_stranger_len = 0;
    unsigned char *obj_stranger =
        build_broadcast_object(&stranger, stranger_ripe, "should not be decrypted", "nobody subscribed", &obj_stranger_len);
    CHECK(obj_stranger != NULL, "build stranger broadcast object");

    struct bm_message msg_stranger;
    memset(&msg_stranger, 0, sizeof(msg_stranger));
    memcpy(msg_stranger.command, "object", 6);
    msg_stranger.length = (uint32_t)obj_stranger_len;
    msg_stranger.payload = obj_stranger;
    bm_object_sync_dispatch(conn, &msg_stranger, &ctx);
    free(obj_stranger);

    CHECK(inbox_count(messages_db) == 2, "unsubscribed broadcaster's broadcast should not appear in inbox");

    /* --- 4. remove-subscription後は復号されなくなる --- */
    CHECK(bm_messages_store_remove_subscription(messages_db, broadcaster_v3_address) == 0,
          "remove subscription for v3 broadcaster");

    size_t obj_v4b_len = 0;
    unsigned char *obj_v4b = build_broadcast_object(&broadcaster_v3, broadcaster_v3_ripe, "after unsubscribe",
                                                      "should not be decrypted anymore", &obj_v4b_len);
    CHECK(obj_v4b != NULL, "build second v3 broadcaster object");

    struct bm_message msg_v4b;
    memset(&msg_v4b, 0, sizeof(msg_v4b));
    memcpy(msg_v4b.command, "object", 6);
    msg_v4b.length = (uint32_t)obj_v4b_len;
    msg_v4b.payload = obj_v4b;
    bm_object_sync_dispatch(conn, &msg_v4b, &ctx);
    free(obj_v4b);

    CHECK(inbox_count(messages_db) == 2, "broadcast from a removed subscription should not be decrypted");

    close(fds[0]);
    close(fds[1]);
    bm_fd_data_free(conn);
    bm_peer_registry_destroy(&registry);
    free(broadcaster_v3_address);
    free(broadcaster_v4_address);

    /* --- 5. addSubscription/listSubscriptions APIが実HTTPリクエスト経由で動作すること --- */
    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = "testuser";
    config.password = "testpass";
    config.keyring = &kr;
    config.identity_db = identity_db;
    config.messages_db = messages_db;
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;

    bm_queue_t broadcast_queue;
    bm_queue_init(&broadcast_queue);
    config.broadcast_queue = &broadcast_queue;

    /* sendBroadcast HTTPテスト用のidentity(keyringでunlock済みである必要がある) */
    struct bm_generated_address sender_for_http_gen;
    CHECK(bm_address_generate_deterministic("broadcast test sendBroadcast sender", 1, &sender_for_http_gen) == 0,
          "generate sendBroadcast sender address");
    char *sender_for_http_address = bm_address_encode(4, 1, sender_for_http_gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(identity_db, sender_for_http_address, "http sender", 4, 1,
                                      sender_for_http_gen.pub_signing, sender_for_http_gen.pub_encryption,
                                      sender_for_http_gen.priv_signing, sender_for_http_gen.priv_encryption,
                                      "http sender pass", 1000, 1000) == 0,
          "create sendBroadcast sender identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, sender_for_http_address, "http sender pass") == 0,
          "unlock sendBroadcast sender");

    _Atomic sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args);
    usleep(200000);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    CHECK(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0, "connect to api_server for addSubscription");

    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *auth_plain = "testuser:testpass";
    unsigned char auth_b64[64];
    size_t in_len = strlen(auth_plain);
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3)
    {
        unsigned int n = (unsigned char)auth_plain[i] << 16;
        if (i + 1 < in_len)
        {
            n |= (unsigned char)auth_plain[i + 1] << 8;
        }
        if (i + 2 < in_len)
        {
            n |= (unsigned char)auth_plain[i + 2];
        }
        auth_b64[o++] = (unsigned char)b64_table[(n >> 18) & 0x3f];
        auth_b64[o++] = (unsigned char)b64_table[(n >> 12) & 0x3f];
        auth_b64[o++] = (i + 1 < in_len) ? (unsigned char)b64_table[(n >> 6) & 0x3f] : (unsigned char)'=';
        auth_b64[o++] = (i + 2 < in_len) ? (unsigned char)b64_table[n & 0x3f] : (unsigned char)'=';
    }
    auth_b64[o] = '\0';

    struct bm_generated_address http_test_gen;
    CHECK(bm_address_generate_deterministic("broadcast test http subscription target", 1, &http_test_gen) == 0,
          "generate address for HTTP addSubscription test");
    char *http_test_address = bm_address_encode(4, 1, http_test_gen.ripe, BM_RIPE_LEN);

    char body[512];
    snprintf(body, sizeof(body),
             "{\"jsonrpc\":\"2.0\",\"method\":\"addSubscription\",\"params\":[\"%s\",\"http test\"],\"id\":1}",
             http_test_address);
    free(http_test_address);
    char request[2048];
    int req_len = snprintf(request, sizeof(request),
                            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic %s\r\n"
                            "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                            auth_b64, strlen(body), body);
    write(sock, request, (size_t)req_len);
    char resp_buf[8192];
    ssize_t total = 0;
    ssize_t n;
    while ((n = read(sock, resp_buf + total, sizeof(resp_buf) - 1 - (size_t)total)) > 0)
    {
        total += n;
    }
    close(sock);
    resp_buf[total] = '\0';
    CHECK(strstr(resp_buf, "true") != NULL, "addSubscription HTTP request should return true");

    /* --- 6. sendBroadcast APIが実HTTPリクエスト経由でobjectを組み立てbroadcast_queueへ
     * 投入すること --- */
    int sock2 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(sock2, (struct sockaddr *)&addr, sizeof(addr)) == 0, "connect to api_server for sendBroadcast");

    char broadcast_body[512];
    snprintf(broadcast_body, sizeof(broadcast_body),
             "{\"jsonrpc\":\"2.0\",\"method\":\"sendBroadcast\",\"params\":[\"%s\",\"http broadcast subject\","
             "\"http broadcast body\"],\"id\":2}",
             sender_for_http_address);
    char broadcast_request[2048];
    int broadcast_req_len =
        snprintf(broadcast_request, sizeof(broadcast_request),
                 "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic %s\r\n"
                 "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                 auth_b64, strlen(broadcast_body), broadcast_body);
    write(sock2, broadcast_request, (size_t)broadcast_req_len);
    char broadcast_resp[8192];
    ssize_t broadcast_total = 0;
    ssize_t bn;
    while ((bn = read(sock2, broadcast_resp + broadcast_total, sizeof(broadcast_resp) - 1 - (size_t)broadcast_total))
           > 0)
    {
        broadcast_total += bn;
    }
    close(sock2);
    broadcast_resp[broadcast_total] = '\0';
    CHECK(strstr(broadcast_resp, "objectLength") != NULL, "sendBroadcast HTTP request should return objectLength");
    CHECK(strstr(broadcast_resp, "inventoryHash") != NULL, "sendBroadcast HTTP request should return inventoryHash");

    void *raw = NULL;
    CHECK(bm_queue_pop(&broadcast_queue, &raw) == true, "sendBroadcast should push an item to broadcast_queue");
    if (raw != NULL)
    {
        struct bm_broadcast_item *item = raw;
        struct bm_object_header hdr;
        CHECK(bm_object_parse_header(item->object, item->object_len, &hdr) == 0,
              "sendBroadcast object header parses");
        CHECK(hdr.object_type == BM_OBJECT_BROADCAST, "sendBroadcast should push a type=broadcast object");
        free(item->object);
        free(item);
    }
    bm_queue_shutdown(&broadcast_queue);

    free(sender_for_http_address);

    server_stop = 1;
    pthread_join(server_thread, NULL);
    bm_queue_destroy(&broadcast_queue);

    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(object_pool_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
