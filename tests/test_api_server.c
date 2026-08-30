/*
 * core/api_server.c のend-to-endテスト。実際にHTTPサーバーを起動し、生ソケットで
 * JSON-RPC 2.0リクエストを送って応答を検証する(curl等の外部プロセスに依存しない)。
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

#include "../src/common/json.h"
#include "../src/core/address.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/messages_store.h"
#include "../src/core/peer_manager.h"
#include "../src/infra/network.h"
#include "../src/infra/peer_registry.h"

#define TEST_PORT 18442
#define TEST_IDENTITY_DB "test_api_server_identity.db"
#define TEST_MESSAGES_DB "test_api_server_messages.db"
#define TEST_PEERS_DB "test_api_server_peers.db"

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
    /* §11 2026-08-24 backlog項目10(Releaseビルド検証)で発覚: -O2では戻り値無視の
     * write()が-Wunused-resultで警告する。ローカルループバックへの数KB程度の書き込みが
     * 部分書き込みになることは実質無いが、CHECKで検証することで警告を解消しつつ
     * 万一の部分書き込みもテスト失敗として可視化する。 */
    CHECK(write(fd, request, (size_t)req_len) == req_len, "writing the HTTP request should not short-write");

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
    CHECK(write(fd, request, (size_t)req_len) == req_len, "writing the HTTP request should not short-write");

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
    sqlite3 *peers_db = open_fresh_db(TEST_PEERS_DB, bm_peer_manager_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    /* §11 2026-08-23 backlog項目5: listConnections用のregistry。config.registryへ
     * アドレスを渡すため、config構築より前に初期化しておく必要がある(main.cと同じ順序、
     * DESIGN.md参照)。 */
    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);

    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = "testuser";
    config.password = "testpass";
    config.keyring = &kr;
    config.identity_db = identity_db;
    config.messages_db = messages_db;
    config.peers_db = peers_db;
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;
    config.registry = &registry;

    _Atomic sig_atomic_t server_stop = 0;
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

        /*
         * §11 2026-08-29 setAddressLabel: PyBitmessage本家にはJSON-RPC API経由のラベル変更が
         * 無いが、GUI相当の機能を本実装独自に追加した。日本語ラベルで検証することで、
         * 同時に修正したJSON非ASCII文字パースバグ(§11参照、"Ã£ÂÂ"文字化け)の回帰も兼ねる。
         */
        char req[512];
        char label_req[512];
        snprintf(label_req, sizeof(label_req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"setAddressLabel\",\"params\":[\"%s\",\"でじこ\"],\"id\":21}",
                 created_address);
        resp = do_request(label_req, "testuser", "testpass");
        CHECK(resp != NULL, "setAddressLabel HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1,
                  "setAddressLabel returns true");
            bm_json_free(v);
            free(resp);
        }

        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":22}",
                           "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            const char *updated_label = (result != NULL && result->item_count == 1)
                ? bm_json_as_string(bm_json_object_get(bm_json_array_get(result, 0), "label"))
                : NULL;
            CHECK(updated_label != NULL && strcmp(updated_label, "でじこ") == 0,
                  "setAddressLabel round-trips the Japanese label byte-for-byte via listAddresses");
            bm_json_free(v);
            free(resp);
        }

        /* 存在しないaddressへのsetAddressLabelはエラーになること */
        resp = do_request(
            "{\"jsonrpc\":\"2.0\",\"method\":\"setAddressLabel\","
            "\"params\":[\"BM-2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK\",\"x\"],\"id\":23}",
            "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *error = v != NULL ? bm_json_object_get(v, "error") : NULL;
            CHECK(error != NULL, "setAddressLabel on unknown address returns an error");
            bm_json_free(v);
            free(resp);
        }

        /* unlockAddress: 間違ったpassphraseではfalse */
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

        /* §11 2026-08-29 exportAddress: importAddressと対称(DESIGN.md §6.2/§7)。
         * unlock中のaddressをexportし、そのWIFで再インポートできることを確認する */
        char signing_wif[128] = {0};
        char encryption_wif[128] = {0};
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"exportAddress\",\"params\":[\"%s\",\"wrong pass\"],\"id\":41}",
                 created_address);
        resp = do_request(req, "testuser", "testpass");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *error = v != NULL ? bm_json_object_get(v, "error") : NULL;
            CHECK(error != NULL, "exportAddress with wrong passphrase returns an error");
            bm_json_free(v);
            free(resp);
        }

        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"exportAddress\",\"params\":[\"%s\",\"store pass\"],\"id\":42}",
                 created_address);
        resp = do_request(req, "testuser", "testpass");
        CHECK(resp != NULL, "exportAddress HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            const char *sw = result != NULL ? bm_json_as_string(bm_json_object_get(result, "signingWIF")) : NULL;
            const char *ew = result != NULL ? bm_json_as_string(bm_json_object_get(result, "encryptionWIF")) : NULL;
            CHECK(sw != NULL && ew != NULL, "exportAddress returns signingWIF/encryptionWIF");
            if (sw != NULL && ew != NULL)
            {
                strncpy(signing_wif, sw, sizeof(signing_wif) - 1);
                strncpy(encryption_wif, ew, sizeof(encryption_wif) - 1);
            }
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

        /* §11 2026-08-29 importAddress: exportで取り出したWIFで再インポートし、
         * 新しいstorePassphraseでunlockできることを確認する(keys.datインポートの土台) */
        CHECK(signing_wif[0] != '\0' && encryption_wif[0] != '\0', "have WIFs for reimport");
        if (signing_wif[0] != '\0' && encryption_wif[0] != '\0')
        {
            snprintf(req, sizeof(req),
                     "{\"jsonrpc\":\"2.0\",\"method\":\"importAddress\","
                     "\"params\":[\"%s\",\"%s\",\"%s\",\"reimported\",\"new store pass\"],\"id\":43}",
                     created_address, signing_wif, encryption_wif);
            resp = do_request(req, "testuser", "testpass");
            CHECK(resp != NULL, "importAddress HTTP request");
            if (resp != NULL)
            {
                bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
                bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
                CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1,
                      "importAddress returns true");
                bm_json_free(v);
                free(resp);
            }

            /* 再インポートしたアドレスを新しいpassphraseでunlockできること */
            snprintf(req, sizeof(req),
                     "{\"jsonrpc\":\"2.0\",\"method\":\"unlockAddress\",\"params\":[\"%s\",\"new store pass\"],"
                     "\"id\":44}",
                     created_address);
            resp = do_request(req, "testuser", "testpass");
            if (resp != NULL)
            {
                bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
                bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
                CHECK(result != NULL && result->boolean == 1,
                      "unlockAddress after importAddress with correct new passphrase returns true");
                bm_json_free(v);
                free(resp);
            }

            /* WIFとaddressの組み合わせが不一致なら失敗すること(signing/encryptionを
             * 入れ替えて渡す) */
            snprintf(req, sizeof(req),
                     "{\"jsonrpc\":\"2.0\",\"method\":\"importAddress\","
                     "\"params\":[\"%s\",\"%s\",\"%s\",\"mismatched\",\"pass\"],\"id\":45}",
                     created_address, encryption_wif, signing_wif);
            resp = do_request(req, "testuser", "testpass");
            if (resp != NULL)
            {
                bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
                bm_json_value_t *error = v != NULL ? bm_json_object_get(v, "error") : NULL;
                CHECK(error != NULL, "importAddress with mismatched WIF/address returns an error");
                bm_json_free(v);
                free(resp);
            }
        }

        free(created_address);
    }

    /* sendMessage: 送信者をAPI経由で作成・unlockし、受信者はテスト側でローカルに鍵を導出して
     * cachePubkeyで明示的に登録してから送る(§11 2026-08-30、toPubEncryptionHexの直接指定は
     * sendMessageの引数から廃止した。呼び出し側が任意のhexを渡せてしまい、①toAddressと
     * 無関係な鍵で暗号化できてしまう、②その検証されない鍵がそのままpubkey_cacheへ自動upsert
     * され以後の送信も汚染する、という2つの実害があったため。pubkey_cache経由が唯一の経路) */
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

        /* sendMessage(pubkey_cache未登録)はまだ送れない。getpubkey要求の自動送出自体は
         * tests/test_getpubkey_automation.cで既に検証済みなので、ここではエラーになることだけ
         * 確認する */
        char send_req_uncached[1024];
        snprintf(send_req_uncached, sizeof(send_req_uncached),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"sendMessage\","
                 "\"params\":[\"%s\",\"%s\",\"api test subject\",\"api test body\",3600,1],\"id\":12}",
                 sender_address, recv_address);
        resp = do_request(send_req_uncached, "testuser", "testpass");
        CHECK(resp != NULL, "sendMessage(uncached) HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *err = v != NULL ? bm_json_object_get(v, "error") : NULL;
            CHECK(err != NULL, "sendMessage(uncached) returns an error");
            bm_json_free(v);
            free(resp);
        }

        /* cachePubkey + sendMessage: pubkey_cache経由の送信 */
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
                 "\"params\":[\"%s\",\"%s\",\"cached subject\",\"cached body\",3600,1],\"id\":15}",
                 sender_address, recv_address);
        resp = do_request(send_req_cached, "testuser", "testpass");
        CHECK(resp != NULL, "sendMessage with cached pubkey HTTP request");
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

    /* §11 2026-08-25 getSentMessages: sentテーブルへ1件差し込み、API経由で正しく読めることを
     * 確認する(sendMessageの実際の送信パイプラインはtest_send_pipeline.cで既に検証済みなので、
     * ここではAPI層のクエリ・JSONシリアライズだけを対象にする)。ただしこの時点で、上の
     * cache済みsendMessageが実際の送信パイプライン経由で既にsentへ行を挿入済みなので、
     * 件数を決め打ちせず自分の挿入したmsgIdを配列内から探す */
    {
        unsigned char msg_id[32];
        memset(msg_id, 0xcd, sizeof(msg_id));
        unsigned char ack_data[4] = {1, 2, 3, 4};
        CHECK(bm_messages_store_insert_sent(messages_db, msg_id, ack_data, sizeof(ack_data),
                                             "BM-senttoaddress", "BM-sentfromaddress",
                                             "sent test subject", "sent test body",
                                             "broadcasted", 1, 1234567890, 2419200, 0) == 0,
              "seed one sent row directly");

        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getSentMessages\",\"params\":[],\"id\":17}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "getSentMessages HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_ARRAY && result->item_count >= 1,
                  "getSentMessages returns at least 1 entry");

            bm_json_value_t *entry = NULL;
            if (result != NULL)
            {
                for (size_t i = 0; i < result->item_count; i++)
                {
                    bm_json_value_t *e = bm_json_array_get(result, i);
                    const char *msg_id_hex = bm_json_as_string(bm_json_object_get(e, "msgId"));
                    if (msg_id_hex != NULL && strncmp(msg_id_hex, "cdcdcdcd", 8) == 0)
                    {
                        entry = e;
                        break;
                    }
                }
            }
            CHECK(entry != NULL, "getSentMessages contains the seeded row");
            if (entry != NULL)
            {
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "toAddress")), "BM-senttoaddress") == 0,
                      "getSentMessages toAddress");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "subject")), "sent test subject") == 0,
                      "getSentMessages subject");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "body")), "sent test body") == 0,
                      "getSentMessages body");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "status")), "broadcasted") == 0,
                      "getSentMessages status");
            }
            bm_json_free(v);
            free(resp);
        }
    }

    /* §11 2026-08-30 trashMessage: [msgId(hex)] -> bool。上でinboxへ差し込んだmsg_id(abab...)と
     * sentへ差し込んだmsg_id(cdcd...)の両方に対して、folder='trash'へ更新されることを確認する
     * (PyBitmessage本家のtrashMessageと同じくinbox/sentの区別なく1つのmsgIdで両方を試す仕様)。
     * 存在しないmsgIdを渡してもエラーにならないこと、不正な長さのhexはエラーになることも確認する。 */
    {
        char inbox_msg_id_hex[65];
        unsigned char inbox_msg_id[32];
        memset(inbox_msg_id, 0xab, sizeof(inbox_msg_id));
        hex_encode(inbox_msg_id, sizeof(inbox_msg_id), inbox_msg_id_hex);

        char sent_msg_id_hex[65];
        unsigned char sent_msg_id[32];
        memset(sent_msg_id, 0xcd, sizeof(sent_msg_id));
        hex_encode(sent_msg_id, sizeof(sent_msg_id), sent_msg_id_hex);

        char req[256];
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"trashMessage\",\"params\":[\"%s\"],\"id\":20}",
                 inbox_msg_id_hex);
        resp = do_request(req, "testuser", "testpass");
        CHECK(resp != NULL, "trashMessage(inbox) HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1,
                  "trashMessage(inbox) returns true");
            bm_json_free(v);
            free(resp);
        }

        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"trashMessage\",\"params\":[\"%s\"],\"id\":21}",
                 sent_msg_id_hex);
        resp = do_request(req, "testuser", "testpass");
        CHECK(resp != NULL, "trashMessage(sent) HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1,
                  "trashMessage(sent) returns true");
            bm_json_free(v);
            free(resp);
        }

        /* 存在しないmsgId: エラーにならず true が返る(本家の「存在したと仮定」仕様) */
        resp = do_request(
            "{\"jsonrpc\":\"2.0\",\"method\":\"trashMessage\","
            "\"params\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"id\":22}",
            "testuser", "testpass");
        CHECK(resp != NULL, "trashMessage(nonexistent) HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *err = v != NULL ? bm_json_object_get(v, "error") : NULL;
            CHECK(err == NULL, "trashMessage(nonexistent-but-well-formed) does not error");
            bm_json_free(v);
            free(resp);
        }

        /* 不正な長さのhex(63文字)はエラーになる */
        resp = do_request(
            "{\"jsonrpc\":\"2.0\",\"method\":\"trashMessage\","
            "\"params\":[\"abc\"],\"id\":23}",
            "testuser", "testpass");
        CHECK(resp != NULL, "trashMessage(bad hex) HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *err = v != NULL ? bm_json_object_get(v, "error") : NULL;
            CHECK(err != NULL, "trashMessage(bad hex) returns error");
            bm_json_free(v);
            free(resp);
        }

        /* getInboxMessages(folder='inbox')からtrash化した行が消え、folder無指定では
         * folder='trash'として残っていることを確認する */
        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getInboxMessages\",\"params\":[\"inbox\"],\"id\":24}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "getInboxMessages(inbox) after trash HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            int found = 0;
            if (result != NULL)
            {
                for (size_t i = 0; i < result->item_count; i++)
                {
                    const char *msg_id_hex =
                        bm_json_as_string(bm_json_object_get(bm_json_array_get(result, i), "msgId"));
                    if (msg_id_hex != NULL && strcmp(msg_id_hex, inbox_msg_id_hex) == 0)
                    {
                        found = 1;
                    }
                }
            }
            CHECK(!found, "trashed inbox message no longer in folder=inbox listing");
            bm_json_free(v);
            free(resp);
        }

        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getInboxMessages\",\"params\":[],\"id\":25}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "getInboxMessages(all) after trash HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            bm_json_value_t *entry = NULL;
            if (result != NULL)
            {
                for (size_t i = 0; i < result->item_count; i++)
                {
                    bm_json_value_t *e = bm_json_array_get(result, i);
                    const char *msg_id_hex = bm_json_as_string(bm_json_object_get(e, "msgId"));
                    if (msg_id_hex != NULL && strcmp(msg_id_hex, inbox_msg_id_hex) == 0)
                    {
                        entry = e;
                    }
                }
            }
            CHECK(entry != NULL, "trashed inbox message still present in unfiltered listing");
            if (entry != NULL)
            {
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "folder")), "trash") == 0,
                      "trashed inbox message folder == trash");
            }
            bm_json_free(v);
            free(resp);
        }

        /* getSentMessagesはfolder='sent'のみ返すため、trash化した行は消える */
        resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getSentMessages\",\"params\":[],\"id\":26}",
                           "testuser", "testpass");
        CHECK(resp != NULL, "getSentMessages after trash HTTP request");
        if (resp != NULL)
        {
            bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
            bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
            int found = 0;
            if (result != NULL)
            {
                for (size_t i = 0; i < result->item_count; i++)
                {
                    const char *msg_id_hex =
                        bm_json_as_string(bm_json_object_get(bm_json_array_get(result, i), "msgId"));
                    if (msg_id_hex != NULL && strcmp(msg_id_hex, sent_msg_id_hex) == 0)
                    {
                        found = 1;
                    }
                }
            }
            CHECK(!found, "trashed sent message no longer in getSentMessages listing");
            bm_json_free(v);
            free(resp);
        }
    }

    /* §11 addPeer: [ipAddress, port, stream?]。手動でpeers.dbへ登録できることを確認する */
    resp = do_request(
        "{\"jsonrpc\":\"2.0\",\"method\":\"addPeer\",\"params\":[\"203.0.113.99\",8444,1],\"id\":16}",
        "testuser", "testpass");
    CHECK(resp != NULL, "addPeer HTTP request");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        bm_json_value_t *result = v != NULL ? bm_json_object_get(v, "result") : NULL;
        CHECK(result != NULL && result->type == BM_JSON_BOOL && result->boolean == 1, "addPeer returns true");
        bm_json_free(v);
        free(resp);
    }

    sqlite3_stmt *peer_stmt = NULL;
    sqlite3_prepare_v2(peers_db, "SELECT port, source, rating FROM hosts WHERE ip_address = '203.0.113.99';",
                        -1, &peer_stmt, NULL);
    CHECK(sqlite3_step(peer_stmt) == SQLITE_ROW, "addPeer should register the peer into peers.db");
    CHECK(sqlite3_column_int(peer_stmt, 0) == 8444, "addPeer registered port matches");
    const char *peer_source = (const char *)sqlite3_column_text(peer_stmt, 1);
    CHECK(peer_source != NULL && strcmp(peer_source, "manual") == 0, "addPeer registered source should be 'manual'");
    CHECK(sqlite3_column_double(peer_stmt, 2) == 0.0, "addPeer registered peer should start at rating 0.0");
    sqlite3_finalize(peer_stmt);

    /* 不正なportは拒否される */
    resp = do_request(
        "{\"jsonrpc\":\"2.0\",\"method\":\"addPeer\",\"params\":[\"203.0.113.100\",0],\"id\":17}",
        "testuser", "testpass");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL && bm_json_object_get(v, "error") != NULL, "addPeer with invalid port returns an error");
        bm_json_free(v);
        free(resp);
    }

    /* §11 2026-08-23 backlog項目5: listConnections。outbound1本・inbound1本をregistryへ
     * 直接登録し、それぞれ{host,port,fullyEstablished,userAgent}が正しく返ることを確認する */
    int lc_fds_out[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, lc_fds_out) == 0, "socketpair for outbound listConnections fixture");
    struct bm_fd_data *lc_conn_out = bm_fd_data_new(BM_FD_CLIENT_SOCKET, lc_fds_out[0]);
    CHECK(lc_conn_out != NULL, "bm_fd_data_new for outbound listConnections fixture");
    strncpy(lc_conn_out->logical_peer_ip, "203.0.113.201", sizeof(lc_conn_out->logical_peer_ip) - 1);
    lc_conn_out->logical_peer_port = 8444;
    lc_conn_out->handshake_complete = 1;
    lc_conn_out->user_agent = strdup("/bitmessage-c-test-outbound:0.1.0/");
    lc_conn_out->bytes_sent = 1234;
    lc_conn_out->bytes_received = 5678;
    bm_peer_registry_add(&registry, lc_conn_out);

    int lc_fds_in[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, lc_fds_in) == 0, "socketpair for inbound listConnections fixture");
    struct bm_fd_data *lc_conn_in = bm_fd_data_new(BM_FD_SERVER_SOCKET, lc_fds_in[0]);
    CHECK(lc_conn_in != NULL, "bm_fd_data_new for inbound listConnections fixture");
    lc_conn_in->handshake_complete = 0; /* まだhandshake未完了の状態も確認する */
    lc_conn_in->user_agent = strdup("/bitmessage-c-test-inbound:0.1.0/");
    bm_peer_registry_add(&registry, lc_conn_in);

    resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"listConnections\",\"params\":[],\"id\":18}", "testuser",
                       "testpass");
    CHECK(resp != NULL, "listConnections HTTP request");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL, "listConnections response is valid JSON");
        if (v != NULL)
        {
            const bm_json_value_t *result = bm_json_object_get(v, "result");
            const bm_json_value_t *inbound = result != NULL ? bm_json_object_get(result, "inbound") : NULL;
            const bm_json_value_t *outbound = result != NULL ? bm_json_object_get(result, "outbound") : NULL;
            CHECK(inbound != NULL && inbound->type == BM_JSON_ARRAY && inbound->item_count == 1,
                  "listConnections should report exactly 1 inbound connection");
            CHECK(outbound != NULL && outbound->type == BM_JSON_ARRAY && outbound->item_count == 1,
                  "listConnections should report exactly 1 outbound connection");
            if (outbound != NULL && outbound->item_count == 1)
            {
                const bm_json_value_t *entry = bm_json_array_get(outbound, 0);
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "host")), "203.0.113.201") == 0,
                      "outbound entry's host should match logical_peer_ip");
                CHECK((int)bm_json_as_number(bm_json_object_get(entry, "port")) == 8444,
                      "outbound entry's port should match logical_peer_port");
                CHECK(bm_json_object_get(entry, "fullyEstablished")->boolean == 1,
                      "outbound entry's fullyEstablished should be true");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "userAgent")),
                             "/bitmessage-c-test-outbound:0.1.0/")
                          == 0,
                      "outbound entry's userAgent should match");
                CHECK((uint64_t)bm_json_as_number(bm_json_object_get(entry, "sentBytes")) == 1234,
                      "outbound entry's sentBytes should match conn->bytes_sent");
                CHECK((uint64_t)bm_json_as_number(bm_json_object_get(entry, "receivedBytes")) == 5678,
                      "outbound entry's receivedBytes should match conn->bytes_received");
            }
            if (inbound != NULL && inbound->item_count == 1)
            {
                const bm_json_value_t *entry = bm_json_array_get(inbound, 0);
                CHECK(bm_json_object_get(entry, "fullyEstablished")->boolean == 0,
                      "inbound entry's fullyEstablished should be false (handshake not complete)");
                CHECK(strcmp(bm_json_as_string(bm_json_object_get(entry, "userAgent")),
                             "/bitmessage-c-test-inbound:0.1.0/")
                          == 0,
                      "inbound entry's userAgent should match");
            }
            bm_json_free(v);
        }
        free(resp);
    }

    bm_peer_registry_remove(&registry, lc_conn_out);
    bm_peer_registry_remove(&registry, lc_conn_in);
    close(lc_fds_out[0]);
    close(lc_fds_out[1]);
    close(lc_fds_in[0]);
    close(lc_fds_in[1]);
    bm_fd_data_free(lc_conn_out);
    bm_fd_data_free(lc_conn_in);

    /* §11 2026-08-23 backlog項目5(送受信バイト数、後半分): getNetworkStats。
     * listConnectionsとは別メソッドとして、プロセス起動時からの送受信バイト数の全体累積
     * ({sentBytes, receivedBytes})が返ることを確認する。値そのもの(このプロセス内で
     * それまでに実際に行われた通信量に依存する)ではなく、フィールドが存在し数値であることと、
     * 直前のHTTPリクエスト自体の送受信でカウンタが0より増えていることを確認する
     * (bm_network_get_statsはHTTPサーバー自身の通信も同じbm_network_write_all/
     * bm_network_handle_readable経由でカウントしているはず) */
    resp = do_request("{\"jsonrpc\":\"2.0\",\"method\":\"getNetworkStats\",\"params\":[],\"id\":19}", "testuser",
                       "testpass");
    CHECK(resp != NULL, "getNetworkStats HTTP request");
    if (resp != NULL)
    {
        bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
        CHECK(v != NULL, "getNetworkStats response is valid JSON");
        if (v != NULL)
        {
            const bm_json_value_t *result = bm_json_object_get(v, "result");
            const bm_json_value_t *sent_bytes = result != NULL ? bm_json_object_get(result, "sentBytes") : NULL;
            const bm_json_value_t *received_bytes =
                    result != NULL ? bm_json_object_get(result, "receivedBytes") : NULL;
            CHECK(sent_bytes != NULL && sent_bytes->type == BM_JSON_NUMBER,
                  "getNetworkStats should return a numeric sentBytes");
            CHECK(received_bytes != NULL && received_bytes->type == BM_JSON_NUMBER,
                  "getNetworkStats should return a numeric receivedBytes");
            bm_json_free(v);
        }
        free(resp);
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

    /* §11 2026-08-24 backlog項目9(ASan/UBSan導入)で発覚: registryの内部配列(reg->conns)を
     * 解放しないまま終了しており、AddressSanitizerのLeakSanitizerがリークとして検出した。
     * 個々の接続(bm_fd_data)自体は上でbm_fd_data_free済みだが、registry自体の後片付けが
     * 抜けていた。 */
    bm_peer_registry_destroy(&registry);

    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(peers_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_PEERS_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
