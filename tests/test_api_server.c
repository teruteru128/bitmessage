/*
 * core/api_server.c のend-to-endテスト。実際にHTTPサーバーを起動し、生ソケットで
 * JSON-RPC 2.0リクエストを送って応答を検証する(curl等の外部プロセスに依存しない)。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/json.h"
#include "../src/core/address.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/messages_store.h"

#define TEST_PORT 18442
#define TEST_IDENTITY_DB "test_api_server_identity.db"
#define TEST_MESSAGES_DB "test_api_server_messages.db"

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

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

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

/* 生ソケットで1リクエストを送り、レスポンスボディをmalloc文字列で返す(NULLなら失敗) */
static char *do_request(const char *body, const char *auth_user, const char *auth_pass)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return NULL;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return NULL;
    }

    char request[8192];
    int req_len;
    if (auth_user != NULL)
    {
        char credentials[256];
        snprintf(credentials, sizeof(credentials), "%s:%s", auth_user, auth_pass);
        /* base64エンコード(テスト側でも簡易実装、EVP_EncodeBlockはOpenSSL依存が
         * このテストファイルにもあるので直接使う) */
        unsigned char encoded[512];
        extern int EVP_EncodeBlock(unsigned char *, const unsigned char *, int);
        int enc_len = EVP_EncodeBlock(encoded, (const unsigned char *)credentials, (int)strlen(credentials));
        encoded[enc_len] = '\0';
        req_len = snprintf(request, sizeof(request),
                            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                            "Content-Length: %zu\r\n\r\n%s",
                            encoded, strlen(body), body);
    }
    else
    {
        req_len = snprintf(request, sizeof(request),
                            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n\r\n%s",
                            strlen(body), body);
    }
    write(fd, request, (size_t)req_len);

    char *resp = malloc(65536);
    size_t resp_len = 0;
    for (;;)
    {
        ssize_t n = read(fd, resp + resp_len, 65536 - resp_len - 1);
        if (n <= 0)
        {
            break;
        }
        resp_len += (size_t)n;
    }
    resp[resp_len] = '\0';
    close(fd);

    if (strncmp(resp, "HTTP/1.1 200", 12) != 0)
    {
        free(resp);
        return NULL;
    }
    char *body_start = strstr(resp, "\r\n\r\n");
    if (body_start == NULL)
    {
        free(resp);
        return NULL;
    }
    char *result = malloc(strlen(body_start + 4) + 1);
    strcpy(result, body_start + 4);
    free(resp);
    return result;
}

static int is_unauthorized(const char *body, const char *auth_user, const char *auth_pass)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return 0;
    }

    char credentials[256];
    snprintf(credentials, sizeof(credentials), "%s:%s", auth_user, auth_pass);
    unsigned char encoded[512];
    extern int EVP_EncodeBlock(unsigned char *, const unsigned char *, int);
    int enc_len = EVP_EncodeBlock(encoded, (const unsigned char *)credentials, (int)strlen(credentials));
    encoded[enc_len] = '\0';

    char request[8192];
    int req_len = snprintf(request, sizeof(request),
                            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                            "Content-Length: %zu\r\n\r\n%s",
                            encoded, strlen(body), body);
    write(fd, request, (size_t)req_len);

    char resp[256];
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n <= 0)
    {
        return 0;
    }
    resp[n] = '\0';
    return strncmp(resp, "HTTP/1.1 401", 12) == 0;
}

int main(void)
{
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = "testuser";
    config.password = "testpass";
    config.keyring = &kr;
    config.identity_db = identity_db;
    config.messages_db = messages_db;

    volatile sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args); /* server_argsはスレッド側でfreeされる */
    usleep(200000); /* サーバー起動待ち */

    /* 認証なしでは拒否されること */
    CHECK(is_unauthorized("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":1}",
                           "wronguser", "wrongpass"),
          "wrong credentials should be rejected with 401");

    /* createDeterministicAddress */
    char *resp = do_request(
        "{\"jsonrpc\":\"2.0\",\"method\":\"createDeterministicAddress\","
        "\"params\":[\"api_server test passphrase\",4,1,1,\"test label\",\"store pass\"],\"id\":1}",
        "testuser", "testpass");
    CHECK(resp != NULL, "createDeterministicAddress HTTP request");
    char *created_address = NULL;
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL, "createDeterministicAddress response is valid JSON");
        if (v != NULL)
        {
            const char *addr = bm_json_as_string(bm_json_object_get(v, "result"));
            CHECK(addr != NULL && strncmp(addr, "BM-", 3) == 0, "createDeterministicAddress returns BM- address");
            if (addr != NULL)
            {
                created_address = malloc(strlen(addr) + 1);
                strcpy(created_address, addr);
            }
            bm_json_free(v);
        }
        free(resp);
    }

    CHECK(created_address != NULL, "have created_address for subsequent checks");
    if (created_address != NULL)
    {
        /* listAddresses: 作成したアドレスがunlocked=falseで見えること */
        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":2}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "listAddresses request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_ARRAY && result->item_count == 1,
                  "listAddresses returns 1 entry");
            if (result != NULL && result->item_count == 1)
            {
                bm_json_value_t *entry = bm_json_array_get(result, 0);
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "address")), created_address) == 0,
                      "listAddresses entry address matches");
                CHECK(bm_json_object_get(entry, "unlocked")->boolean == 0, "listAddresses entry starts locked");
            }
            bm_json_free(v);
            free(resp);
        }

        /* unlockAddress: 間違ったpassphraseではfalse */
        char req[512];
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"unlockAddress\",\"params\":[\"%s\",\"wrong pass\"],\"id\":3}",
                 created_address);
        resp = do_request(req, "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 0,
                  "unlockAddress with wrong passphrase returns false");
            bm_json_free(v);
            free(resp);
        }

        /* unlockAddress: 正しいpassphraseでtrue */
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"unlockAddress\",\"params\":[\"%s\",\"store pass\"],\"id\":4}",
                 created_address);
        resp = do_request(req, "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->boolean == 1, "unlockAddress with correct passphrase returns true");
            bm_json_free(v);
            free(resp);
        }

        /* deleteAddress */
        snprintf(req, sizeof(req), "{\"jsonrpc\":\"2.0\",\"method\":\"deleteAddress\",\"params\":[\"%s\"],\"id\":5}",
                 created_address);
        resp = do_request(req, "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->boolean == 1, "deleteAddress returns true");
            bm_json_free(v);
            free(resp);
        }

        /* 削除後、listAddressesは空になること */
        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":6}",
                           "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->item_count == 0, "listAddresses empty after delete");
            bm_json_free(v);
            free(resp);
        }

        free(created_address);
    }

    /* sendMessage: 送信者をAPI経由で作成・unlockし、受信者は(pubkey_cache未実装のため)
     * テスト側でローカルに鍵を導出してpub_encryptionを直接渡す */
    resp = do_request(
        "{\"jsonrpc\":\"2.0\",\"method\":\"createDeterministicAddress\","
        "\"params\":[\"api_server sendMessage sender\",4,1,1,\"sender\",\"senderpass\"],\"id\":10}",
        "testuser", "testpass");
    char *sender_address = NULL;
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        const char *addr = v != NULL ? bm_json_as_string(bm_json_object_get(v, "result")) : NULL;
        CHECK(addr != NULL, "create sender address for sendMessage test");
        if (addr != NULL)
        {
            sender_address = malloc(strlen(addr) + 1);
            strcpy(sender_address, addr);
        }
        bm_json_free(v);
        free(resp);
    }

    if (sender_address != NULL)
    {
        char unlock_req[256];
        snprintf(unlock_req, sizeof(unlock_req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"unlockAddress\",\"params\":[\"%s\",\"senderpass\"],\"id\":11}",
                 sender_address);
        resp = do_request(unlock_req, "testuser", "testpass");
        free(resp);

        struct bm_generated_address recv_gen;
        CHECK(bm_address_generate_deterministic("api_server sendMessage receiver", 1, &recv_gen) == 0,
              "generate receiver keys locally (no pubkey_cache yet)");
        char *recv_address = bm_address_encode(4, 1, recv_gen.ripe, BM_RIPE_LEN);
        char recv_pubenc_hex[131];
        hex_encode(recv_gen.pub_encryption, 65, recv_pubenc_hex);

        char send_req[1024];
        snprintf(send_req, sizeof(send_req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\","
                 "\"params\":[\"%s\",\"%s\",\"%s\",\"api test subject\",\"api test body\",3600,1],\"id\":12}",
                 sender_address, recv_address, recv_pubenc_hex);
        resp = do_request(send_req, "testuser", "testpass");
        CHECK(resp != NULL, "sendMessage HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL, "sendMessage returns a result object");
            if (result != NULL)
            {
                double obj_len = bm_json_as_number(bm_json_object_get(result, "objectLength"));
                CHECK(obj_len > 0, "sendMessage objectLength > 0");
                const char *inv_hash = bm_json_as_string(bm_json_object_get(result, "inventoryHash"));
                CHECK(inv_hash != NULL && strlen(inv_hash) == 64, "sendMessage inventoryHash is 32byte hex");
            }
            bm_json_free(v);
            free(resp);
        }

        /* cachePubkey + sendMessage(toPubEncryptionHex=null): pubkey_cache経由の送信 */
        char cache_req[1024];
        snprintf(cache_req, sizeof(cache_req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"cachePubkey\",\"params\":[\"%s\",\"%s\",\"%s\"],\"id\":14}",
                 recv_address, recv_pubenc_hex /* signingは省略テストなので同じ値を使い回して構わない */,
                 recv_pubenc_hex);
        resp = do_request(cache_req, "testuser", "testpass");
        CHECK(resp != NULL, "cachePubkey HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1,
                  "cachePubkey returns true");
            bm_json_free(v);
            free(resp);
        }

        char send_req_cached[1024];
        snprintf(send_req_cached, sizeof(send_req_cached),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\","
                 "\"params\":[\"%s\",\"%s\",null,\"cached subject\",\"cached body\",3600,1],\"id\":15}",
                 sender_address, recv_address);
        resp = do_request(send_req_cached, "testuser", "testpass");
        CHECK(resp != NULL, "sendMessage with null toPubEncryptionHex HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL, "sendMessage with cached pubkey succeeds (no error)");
            if (result != NULL)
            {
                double obj_len = bm_json_as_number(bm_json_object_get(result, "objectLength"));
                CHECK(obj_len > 0, "sendMessage(cached) objectLength > 0");
            }
            bm_json_free(v);
            free(resp);
        }

        free(recv_address);
    }

    /* getInboxMessages: messages_dbへ直接1件差し込み、API経由で正しく読めることを確認
     * (trial_decrypt自体はtests/test_trial_decrypt.cで既に検証済みなので、ここではAPI層の
     * クエリ・JSONシリアライズだけを対象にする) */
    {
        unsigned char msg_id[32];
        memset(msg_id, 0xab, sizeof(msg_id));
        CHECK(bm_messages_store_insert_inbox(messages_db, msg_id, "BM-toaddress", "BM-fromaddress",
                                              "inbox test subject", "inbox test body", 1234567890) == 0,
              "seed one inbox row directly");

        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getInboxMessages\",\"params\":[],\"id\":13}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "getInboxMessages HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_ARRAY && result->item_count == 1,
                  "getInboxMessages returns 1 entry");
            if (result != NULL && result->item_count == 1)
            {
                bm_json_value_t *entry = bm_json_array_get(result, 0);
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "toAddress")), "BM-toaddress") == 0,
                      "getInboxMessages toAddress");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "subject")), "inbox test subject") == 0,
                      "getInboxMessages subject");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "body")), "inbox test body") == 0,
                      "getInboxMessages body");
                const char *msg_id_hex = bm_json_as_string(bm_json_object_get(entry, "msgId"));
                CHECK(msg_id_hex != NULL && strncmp(msg_id_hex, "abababab", 8) == 0,
                      "getInboxMessages msgId hex matches");
            }
            bm_json_free(v);
            free(resp);
        }
    }

    free(sender_address);

    /* 存在しないメソッドはエラーを返す */
    resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"noSuchMethod\",\"params\":[],\"id\":7}",
                       "testuser", "testpass");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL && bm_json_object_get(v, "error") != NULL, "unknown method returns JSON-RPC error");
        bm_json_free(v);
        free(resp);
    }

    /* graceful shutdown: stop_flagを立ててから短時間(poll()の1秒タイムアウト程度)で
     * スレッドが終了することを確認する(§11) */
    struct timespec shutdown_start, shutdown_end;
    clock_gettime(CLOCK_MONOTONIC, &shutdown_start);
    server_stop = 1;
    pthread_join(server_thread, NULL);
    clock_gettime(CLOCK_MONOTONIC, &shutdown_end);
    double shutdown_seconds = (double)(shutdown_end.tv_sec - shutdown_start.tv_sec)
        + (double)(shutdown_end.tv_nsec - shutdown_start.tv_nsec) / 1e9;
    CHECK(shutdown_seconds < 3.0, "api_server should stop within a few seconds of stop_flag being set");
    printf("api_server graceful shutdown took %.3f seconds\n", shutdown_seconds);

    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
