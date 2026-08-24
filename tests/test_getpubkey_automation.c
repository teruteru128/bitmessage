/*
 * getpubkey要求の自動化(DESIGN.md §11)のend-to-endテスト。
 * 1. 送信側: sendMessageがpubkey_cache未登録の宛先を検出し、getpubkeyオブジェクトを
 *    broadcast_queueへ自動投入すること・pubkey_requestsへpending登録すること・
 *    cooldown中は再投入しないことを確認する(core/api_server.c、実HTTPリクエスト経由)。
 * 2. 受信側: 自分がkeyringでunlock済みのアドレス宛のgetpubkeyを受信したら、自分の
 *    pubkeyオブジェクトを組み立ててobject_pool.dbへ登録・broadcastすることを確認する
 *    (infra/object_sync.c、bm_object_sync_dispatch経由)。
 * 3. pubkey v4の受信時、pending登録した候補と突き合わせてpubkey_cacheへ登録し、
 *    pubkey_requestsから該当行を消すことを確認する。
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
#include "../src/core/pubkey_cache.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"

#define TEST_PORT 18443
#define TEST_IDENTITY_DB "test_getpubkey_automation_identity.db"
#define TEST_MESSAGES_DB "test_getpubkey_automation_messages.db"
#define TEST_OBJECT_POOL_DB "test_getpubkey_automation_pool.db"

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

static char *do_http_post(const char *host, int port, const char *user, const char *pass, const char *body)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        return NULL;
    }

    char auth_plain[256];
    snprintf(auth_plain, sizeof(auth_plain), "%s:%s", user, pass);
    /* base64エンコードは自前実装せず、api_server.cのbasic auth検証はconstant_time_equal前提の
     * デコードなので、ここではhttp_client.c相当の簡易実装を直接書く */
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char *in = (unsigned char *)auth_plain;
    size_t in_len = strlen(auth_plain);
    char auth_b64[512];
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3)
    {
        unsigned int n = in[i] << 16;
        if (i + 1 < in_len)
        {
            n |= in[i + 1] << 8;
        }
        if (i + 2 < in_len)
        {
            n |= in[i + 2];
        }
        auth_b64[o++] = b64_table[(n >> 18) & 0x3f];
        auth_b64[o++] = b64_table[(n >> 12) & 0x3f];
        auth_b64[o++] = (i + 1 < in_len) ? b64_table[(n >> 6) & 0x3f] : '=';
        auth_b64[o++] = (i + 2 < in_len) ? b64_table[n & 0x3f] : '=';
    }
    auth_b64[o] = '\0';

    char request[8192];
    int req_len = snprintf(request, sizeof(request),
                            "POST / HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n"
                            "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                            "Connection: close\r\n\r\n%s",
                            host, auth_b64, strlen(body), body);
    CHECK(write(sock, request, (size_t)req_len) == req_len, "writing the HTTP request should not short-write");

    char buf[65536];
    ssize_t total = 0;
    ssize_t n;
    while ((n = read(sock, buf + total, sizeof(buf) - 1 - (size_t)total)) > 0)
    {
        total += n;
    }
    close(sock);
    buf[total] = '\0';

    char *body_start = strstr(buf, "\r\n\r\n");
    if (body_start == NULL)
    {
        return NULL;
    }
    body_start += 4;
    char *result = malloc(strlen(body_start) + 1);
    strcpy(result, body_start);
    return result;
}

int main(void)
{
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    /* --- 1. 送信側: pubkey_cache未登録の宛先へのsendMessageがgetpubkeyを自動発行する --- */
    bm_queue_t broadcast_queue;
    bm_queue_init(&broadcast_queue);

    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = "testuser";
    config.password = "testpass";
    config.keyring = &kr;
    config.identity_db = identity_db;
    config.messages_db = messages_db;
    config.broadcast_queue = &broadcast_queue;
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;

    _Atomic sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args);
    usleep(200000);

    /* 送信者identity(unlock済み) */
    struct bm_generated_address sender_gen;
    CHECK(bm_address_generate_deterministic("getpubkey automation sender", 1, &sender_gen) == 0,
          "generate sender address");
    char *sender_address = bm_address_encode(4, 1, sender_gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(identity_db, sender_address, "sender", 4, 1,
                                      sender_gen.pub_signing, sender_gen.pub_encryption,
                                      sender_gen.priv_signing, sender_gen.priv_encryption,
                                      "sender pass", 1000, 1000) == 0,
          "create sender identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, sender_address, "sender pass") == 0, "unlock sender");

    /* 宛先: pubkey_cacheには一切登録しない、未知のアドレス */
    struct bm_generated_address target_gen;
    CHECK(bm_address_generate_deterministic("getpubkey automation target", 1, &target_gen) == 0,
          "generate target address");
    char *target_address = bm_address_encode(4, 1, target_gen.ripe, BM_RIPE_LEN);

    char req_body[1024];
    snprintf(req_body, sizeof(req_body),
             "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\",\"params\":[\"%s\",\"%s\",null,"
             "\"subj\",\"body\"],\"id\":1}",
             sender_address, target_address);
    char *resp = do_http_post("127.0.0.1", TEST_PORT, "testuser", "testpass", req_body);
    CHECK(resp != NULL, "sendMessage HTTP request (uncached recipient)");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL && bm_json_object_get(v, "error") != NULL,
              "sendMessage to uncached recipient should fail");
        bm_json_free(v);
        free(resp);
    }

    /* getpubkeyがbroadcast_queueへ1件投入されているはず */
    void *raw = NULL;
    CHECK(bm_queue_pop(&broadcast_queue, &raw) == true, "broadcast_queue should have a getpubkey item");
    if (raw != NULL)
    {
        struct bm_broadcast_item *item = raw;
        struct bm_object_header hdr;
        CHECK(bm_object_parse_header(item->object, item->object_len, &hdr) == 0,
              "auto-issued getpubkey object header parses");
        CHECK(hdr.object_type == BM_OBJECT_GETPUBKEY, "auto-issued object should be type=getpubkey");
        CHECK(hdr.version == 4, "auto-issued getpubkey should use the target's address version");
        if (hdr.object_type == BM_OBJECT_GETPUBKEY)
        {
            const unsigned char *tag = item->object + hdr.header_len;
            size_t tag_len = item->object_len - hdr.header_len;
            unsigned char expected_secret[32];
            unsigned char expected_tag[32];
            bm_address_derive_secret_and_tag(4, 1, target_gen.ripe, expected_secret, expected_tag);
            CHECK(tag_len == 32 && memcmp(tag, expected_tag, 32) == 0,
                  "auto-issued getpubkey tag matches the target address");
        }
        free(item->object);
        free(item);
    }

    /* pubkey_requestsへpending登録されているはず */
    CHECK(bm_pubkey_cache_has_recent_request(identity_db, target_gen.ripe, (int64_t)time(NULL), 600) != 0,
          "pubkey_requests should have a recent pending entry for the target");

    /* 直後にもう一度呼んでもcooldown中は再度getpubkeyをbroadcastしないはず */
    resp = do_http_post("127.0.0.1", TEST_PORT, "testuser", "testpass", req_body);
    CHECK(resp != NULL, "second sendMessage HTTP request");
    free(resp);
    bm_queue_shutdown(&broadcast_queue);
    CHECK(bm_queue_pop(&broadcast_queue, &raw) == false,
          "no second getpubkey should be broadcast within the cooldown window");

    server_stop = 1;
    pthread_join(server_thread, NULL);
    bm_queue_destroy(&broadcast_queue);
    free(sender_address);
    free(target_address);

    /* --- 2/3. 受信側: 自分のアドレス宛getpubkeyへの自応答、pubkey v4のpending照合 --- */
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);

    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);
    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, NULL, &kr, &registry, NULL);

    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);

    /* 2. receiver identity(v4、unlock済み)宛のgetpubkeyを受信させ、自応答を確認する */
    struct bm_generated_address recv_gen;
    CHECK(bm_address_generate_deterministic("getpubkey automation receiver", 1, &recv_gen) == 0,
          "generate receiver address");
    char *recv_address = bm_address_encode(4, 1, recv_gen.ripe, BM_RIPE_LEN);
    /* handle_incoming_getpubkey(object_sync.c)は自応答のPoWにこのidentity自身の
     * nonce_trials_per_byte/payload_length_extra_bytesを使う。§11のBM_PUBKEY_RESPONSE_TTL_SECONDS
     * (28日)は実ネットワーク難易度(1000,1000)だと実測20秒超かかる(実際のBitmessageの
     * アドレス作成時のpubkey告知も同程度時間がかかることが知られており設計としては妥当だが、
     * テストでは軽い難易度を使い実行時間を抑える)。 */
    CHECK(bm_keyring_create_identity(identity_db, recv_address, "receiver", 4, 1,
                                      recv_gen.pub_signing, recv_gen.pub_encryption,
                                      recv_gen.priv_signing, recv_gen.priv_encryption,
                                      "receiver pass", 50, 50) == 0,
          "create receiver identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, recv_address, "receiver pass") == 0, "unlock receiver");

    /* §11のPoW検証(受信側)はexpires_time-nowからttlを再計算し、ネットワーク既定の最低難易度
     * (1000,1000)を満たすか確認するため、expires_timeはnow+ttlにしPoW計算時のttl・難易度と
     * 一致させる必要がある */
    uint64_t gp_ttl = 3600;
    size_t gp_len = 0;
    unsigned char *gp_payload =
        bm_build_getpubkey(4, 1, recv_gen.ripe, (uint64_t)time(NULL) + gp_ttl, &gp_len);
    uint64_t gp_target = bm_pow_get_target(gp_len, gp_ttl, 1000, 1000);
    uint64_t gp_nonce = bm_pow_run(gp_payload, gp_len, gp_target);
    size_t gp_object_len = 8 + gp_len;
    unsigned char *gp_object = malloc(gp_object_len);
    for (int i = 0; i < 8; i++)
    {
        gp_object[i] = (unsigned char)((gp_nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(gp_object + 8, gp_payload, gp_len);
    free(gp_payload);

    struct bm_message gp_msg;
    memset(&gp_msg, 0, sizeof(gp_msg));
    memcpy(gp_msg.command, "object", 6);
    gp_msg.length = (uint32_t)gp_object_len;
    gp_msg.payload = gp_object;
    bm_object_sync_dispatch(conn, &gp_msg, &ctx);
    free(gp_object);

    /* object_pool.dbに新しいpubkey(自分のもの)が登録されているはず */
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(object_pool_db,
                        "SELECT payload FROM objects WHERE object_type = ?1 ORDER BY received_time DESC LIMIT 1;",
                        -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, BM_OBJECT_PUBKEY);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "object_pool.db should contain our self-issued pubkey response");
    if (sqlite3_column_bytes(stmt, 0) > 0)
    {
        unsigned char response[4096];
        int response_len = sqlite3_column_bytes(stmt, 0);
        memcpy(response, sqlite3_column_blob(stmt, 0), (size_t)response_len);
        sqlite3_finalize(stmt);

        struct bm_cached_pubkey parsed;
        int rc = bm_parse_pubkey_v4(response, (size_t)response_len, recv_gen.ripe, 4, 1, &parsed);
        CHECK(rc == 0, "self-issued pubkey response parses as valid v4 pubkey for our address");
        if (rc == 0)
        {
            CHECK(memcmp(parsed.signing_pubkey, recv_gen.pub_signing, 65) == 0,
                  "self-issued pubkey response signing key matches our identity");
            CHECK(memcmp(parsed.encryption_pubkey, recv_gen.pub_encryption, 65) == 0,
                  "self-issued pubkey response encryption key matches our identity");
        }
    }
    else
    {
        sqlite3_finalize(stmt);
    }

    /* 2b. §11 getpubkey応答のスロットリング: 同じ宛先へ2回目のgetpubkeyを送っても、
     * 新しいpubkey応答objectを作り直さず(=PoWを再計算せず)既存のものを再利用するはず */
    {
        sqlite3_stmt *count_stmt = NULL;
        sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1,
                            &count_stmt, NULL);
        sqlite3_bind_int(count_stmt, 1, BM_OBJECT_PUBKEY);
        CHECK(sqlite3_step(count_stmt) == SQLITE_ROW, "count pubkey objects before second request");
        int count_before = sqlite3_column_int(count_stmt, 0);
        sqlite3_finalize(count_stmt);
        CHECK(count_before == 1, "exactly 1 self-issued pubkey response should exist so far");

        uint64_t gp2_ttl = 3600;
        size_t gp2_len = 0;
        unsigned char *gp2_payload =
            bm_build_getpubkey(4, 1, recv_gen.ripe, (uint64_t)time(NULL) + gp2_ttl, &gp2_len);
        uint64_t gp2_target = bm_pow_get_target(gp2_len, gp2_ttl, 1000, 1000);
        uint64_t gp2_nonce = bm_pow_run(gp2_payload, gp2_len, gp2_target);
        size_t gp2_object_len = 8 + gp2_len;
        unsigned char *gp2_object = malloc(gp2_object_len);
        for (int i = 0; i < 8; i++)
        {
            gp2_object[i] = (unsigned char)((gp2_nonce >> (56 - 8 * i)) & 0xff);
        }
        memcpy(gp2_object + 8, gp2_payload, gp2_len);
        free(gp2_payload);

        struct bm_message gp2_msg;
        memset(&gp2_msg, 0, sizeof(gp2_msg));
        memcpy(gp2_msg.command, "object", 6);
        gp2_msg.length = (uint32_t)gp2_object_len;
        gp2_msg.payload = gp2_object;
        bm_object_sync_dispatch(conn, &gp2_msg, &ctx);
        free(gp2_object);

        sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1,
                            &count_stmt, NULL);
        sqlite3_bind_int(count_stmt, 1, BM_OBJECT_PUBKEY);
        CHECK(sqlite3_step(count_stmt) == SQLITE_ROW, "count pubkey objects after second request");
        int count_after = sqlite3_column_int(count_stmt, 0);
        sqlite3_finalize(count_stmt);
        CHECK(count_after == count_before,
              "a second getpubkey request for the same address should reuse the cached response, "
              "not build (and PoW) a new one");

        sqlite3_stmt *cache_stmt = NULL;
        sqlite3_prepare_v2(identity_db,
                            "SELECT expires_time FROM self_pubkey_response_cache WHERE ripe = ?1;", -1,
                            &cache_stmt, NULL);
        sqlite3_bind_blob(cache_stmt, 1, recv_gen.ripe, BM_RIPE_LEN, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(cache_stmt) == SQLITE_ROW,
              "self_pubkey_response_cache should have a row for the receiver's ripe");
        sqlite3_finalize(cache_stmt);
    }

    /* 3. pubkey v4のpending照合: 第三者向けのpending要求を登録してから、実物のv4 pubkeyを
     * 受信させ、pubkey_cacheへ登録されpubkey_requestsから消えることを確認する */
    struct bm_generated_address third_party_gen;
    CHECK(bm_address_generate_deterministic("getpubkey automation third party", 1, &third_party_gen) == 0,
          "generate third-party address");
    CHECK(bm_pubkey_cache_record_request(identity_db, third_party_gen.ripe, 4, 1, (int64_t)time(NULL)) == 0,
          "record pending request for third party");

    struct bm_identity_info third_party_id;
    memset(&third_party_id, 0, sizeof(third_party_id));
    third_party_id.address_version = 4;
    third_party_id.stream = 1;
    memcpy(third_party_id.pub_signing, third_party_gen.pub_signing, 65);
    memcpy(third_party_id.pub_encryption, third_party_gen.pub_encryption, 65);
    memcpy(third_party_id.priv_signing, third_party_gen.priv_signing, 32);
    third_party_id.nonce_trials_per_byte = 50;
    third_party_id.payload_length_extra_bytes = 50;

    /* オブジェクト自体の転送PoWはネットワーク既定の最低難易度で計算する(third_party_idの
     * nonce_trials_per_byte/payload_length_extra_bytesはpubkey payload内に埋め込まれる
     * 「このアドレス宛に送る際の要求難易度」であり、object自体のPoWとは別概念) */
    uint64_t tp_ttl = 3600;
    size_t tp_len = 0;
    unsigned char *tp_payload =
        bm_build_pubkey_v4(&third_party_id, third_party_gen.ripe, (uint64_t)time(NULL) + tp_ttl, &tp_len);
    uint64_t tp_target = bm_pow_get_target(tp_len, tp_ttl, 1000, 1000);
    uint64_t tp_nonce = bm_pow_run(tp_payload, tp_len, tp_target);
    size_t tp_object_len = 8 + tp_len;
    unsigned char *tp_object = malloc(tp_object_len);
    for (int i = 0; i < 8; i++)
    {
        tp_object[i] = (unsigned char)((tp_nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(tp_object + 8, tp_payload, tp_len);
    free(tp_payload);

    struct bm_message tp_msg;
    memset(&tp_msg, 0, sizeof(tp_msg));
    memcpy(tp_msg.command, "object", 6);
    tp_msg.length = (uint32_t)tp_object_len;
    tp_msg.payload = tp_object;
    bm_object_sync_dispatch(conn, &tp_msg, &ctx);
    free(tp_object);

    struct bm_cached_pubkey cached;
    CHECK(bm_pubkey_cache_lookup_by_ripe(identity_db, third_party_gen.ripe, &cached) == 0,
          "third-party v4 pubkey should now be cached (matched via pending request candidate)");
    CHECK(bm_pubkey_cache_has_recent_request(identity_db, third_party_gen.ripe, (int64_t)time(NULL), 600) == 0,
          "pending request should be cleared once the pubkey is cached");

    close(fds[0]);
    close(fds[1]);
    bm_fd_data_free(conn);
    bm_peer_registry_destroy(&registry);
    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(object_pool_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);
    free(recv_address);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
