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
#include <unistd.h>

#include "../src/common/json.h"
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

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, &config);
    pthread_detach(server_thread);
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
