/*
 * core/api_server.c のHTTPトランスポート層およびJSON-RPC 2.0ディスパッチ層のテスト。
 *
 * §11 2026-09-15 自前HTTP実装+自前JSONパーサ(common/json.c)からlibmicrohttpd + cJSONへ
 * 移行したのに合わせて新設。既存のtests/test_api_server.cが「各RPCメソッドが期待通りの
 * 結果を返すか」を検証するのに対し、こちらは「HTTPとしてどう振る舞うか」「JSON-RPC 2.0の
 * メッセージ仕様をどこまで満たしているか」を検証する。
 *
 * 検証観点:
 *  1. 移行の動機になった旧実装の欠陥が実際に直っていること
 *     - 何も送らない接続がaccept loopを占有しない(旧実装ではread()にタイムアウトが無く、
 *       認証すら要らずにRPCサーバー全体を無期限停止できた)
 *     - 深いネストのJSONでプロセスが落ちない(旧自前パーサは再帰深さ無制限でスタック
 *       オーバーフローした。深さ10万で実際にSIGSEGVすることを移行前に確認済み)
 *     - Transfer-Encoding: chunkedで送れる(旧実装はContent-Length必須だった)
 *  2. 新たに実装したJSON-RPC 2.0のバッチリクエストと通知(notification)
 *  3. 仕様準拠のエラーコード(-32700/-32600/-32601)
 *  4. keep-aliveで1接続に複数リクエストを流せること(HTTP/1.1の既定動作)
 */

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/logging.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"

#define TEST_PORT 18445
#define TEST_IDENTITY_DB "test_api_transport_identity.db"
#define TEST_USER "testuser"
#define TEST_PASS "testpass"

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

static char g_auth_b64[352];

struct http_response
{
    int status;
    char *body; /* malloc、NUL終端。body_lenが0でも空文字列が入る */
    size_t body_len;
};

static void http_response_free(struct http_response *r)
{
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
}

static int connect_server(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return -1;
    }
    /* テストが固まらないように受信タイムアウトを必ず入れる。サーバー側の不具合で応答が
     * 来なくなった場合もハングではなく失敗として可視化したい */
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/*
 * 1件のHTTPレスポンスを読み取る。keep-alive下ではEOFまで読む方式が使えないので、
 * ヘッダ終端(\r\n\r\n)まで読んでからContent-Lengthの分だけ本文を読む。
 * 成功時0、失敗時-1。
 */
static int read_http_response(int fd, struct http_response *out)
{
    memset(out, 0, sizeof(*out));
    size_t cap = 65536;
    size_t len = 0;
    char *buf = malloc(cap);
    ssize_t header_end = -1;

    while (header_end < 0)
    {
        if (len + 4096 > cap)
        {
            cap *= 2;
            buf = realloc(buf, cap);
        }
        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n <= 0)
        {
            free(buf);
            return -1;
        }
        len += (size_t)n;
        buf[len] = '\0';
        char *p = strstr(buf, "\r\n\r\n");
        if (p != NULL)
        {
            header_end = (ssize_t)(p - buf) + 4;
        }
    }

    if (strncmp(buf, "HTTP/1.1 ", 9) != 0)
    {
        free(buf);
        return -1;
    }
    out->status = atoi(buf + 9);

    /* Content-Lengthを探す(ヘッダ部だけを対象にする) */
    long content_length = 0;
    for (ssize_t i = 0; i < header_end; i++)
    {
        if (strncasecmp(buf + i, "Content-Length:", 15) == 0)
        {
            content_length = strtol(buf + i + 15, NULL, 10);
            break;
        }
    }

    size_t body_have = len - (size_t)header_end;
    size_t body_need = (size_t)content_length;
    if (body_have < body_need)
    {
        if ((size_t)header_end + body_need + 1 > cap)
        {
            cap = (size_t)header_end + body_need + 1;
            buf = realloc(buf, cap);
        }
        while (body_have < body_need)
        {
            ssize_t n = read(fd, buf + (size_t)header_end + body_have, body_need - body_have);
            if (n <= 0)
            {
                free(buf);
                return -1;
            }
            body_have += (size_t)n;
        }
    }

    out->body = malloc(body_need + 1);
    memcpy(out->body, buf + header_end, body_need);
    out->body[body_need] = '\0';
    out->body_len = body_need;
    free(buf);
    return 0;
}

/* 生のリクエストバイト列をそのまま送って1レスポンスを受ける(接続はcloseする) */
static int send_raw(const char *raw, size_t raw_len, struct http_response *out)
{
    int fd = connect_server();
    if (fd < 0)
    {
        return -1;
    }
    size_t written = 0;
    while (written < raw_len)
    {
        ssize_t n = write(fd, raw + written, raw_len - written);
        if (n <= 0)
        {
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    int rc = read_http_response(fd, out);
    close(fd);
    return rc;
}

/* JSON-RPCボディをPOSTする(Connection: close、認証あり) */
static int post_json(const char *body, struct http_response *out)
{
    size_t cap = strlen(body) + 1024;
    char *raw = malloc(cap);
    int raw_len = snprintf(raw, cap,
                            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                            "Content-Type: application/json\r\nConnection: close\r\n"
                            "Content-Length: %zu\r\n\r\n%s",
                            g_auth_b64, strlen(body), body);
    int rc = send_raw(raw, (size_t)raw_len, out);
    free(raw);
    return rc;
}

/* 応答JSONのerror.codeを取り出す(取れなければ0) */
static int error_code_of(const cJSON *resp)
{
    const cJSON *err = cJSON_GetObjectItemCaseSensitive(resp, "error");
    const cJSON *code = cJSON_GetObjectItemCaseSensitive(err, "code");
    return cJSON_IsNumber(code) ? (int)code->valuedouble : 0;
}

int main(void)
{
    /* BM_LOG_LEVELを効かせる(既定はINFO)。api_server.cはMHDの内部エラーログを
     * bm_log経由のDEBUGへ流すので、トランスポート層を調べたいときは
     * BM_LOG_LEVEL=debugで実行するとMHD側の診断も一緒に見える */
    bm_log_init();

    char credentials[256];
    snprintf(credentials, sizeof(credentials), "%s:%s", TEST_USER, TEST_PASS);
    unsigned char encoded[352];
    int enc_len = EVP_EncodeBlock(encoded, (const unsigned char *)credentials, (int)strlen(credentials));
    encoded[enc_len] = '\0';
    snprintf(g_auth_b64, sizeof(g_auth_b64), "%s", (const char *)encoded);

    unlink(TEST_IDENTITY_DB);
    sqlite3 *identity_db = NULL;
    if (sqlite3_open(TEST_IDENTITY_DB, &identity_db) != SQLITE_OK
        || bm_identity_store_init_schema(identity_db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", TEST_IDENTITY_DB);
        return EXIT_FAILURE;
    }

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_api_server_config config;
    memset(&config, 0, sizeof(config));
    config.bind_address = "127.0.0.1";
    config.port = TEST_PORT;
    config.username = TEST_USER;
    config.password = TEST_PASS;
    config.keyring = &kr;
    config.identity_db = identity_db;
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;

    _Atomic sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args);
    usleep(200000); /* サーバー起動待ち */

    struct http_response resp;

    /* --- 1. バッチリクエスト(JSON-RPC 2.0 Specification §6) --- */
    if (post_json("[{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":1},"
                   "{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\",\"params\":[],\"id\":\"two\"},"
                   "{\"jsonrpc\":\"2.0\",\"method\":\"noSuchMethod\",\"params\":[],\"id\":3}]",
                   &resp)
        == 0)
    {
        CHECK(resp.status == 200, "batch request returns 200");
        cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
        CHECK(cJSON_IsArray(v), "batch response is a JSON array");
        CHECK(cJSON_GetArraySize(v) == 3, "batch response has one entry per request");
        if (cJSON_GetArraySize(v) == 3)
        {
            cJSON *r0 = cJSON_GetArrayItem(v, 0);
            cJSON *r1 = cJSON_GetArrayItem(v, 1);
            cJSON *r2 = cJSON_GetArrayItem(v, 2);
            cJSON *id0 = cJSON_GetObjectItemCaseSensitive(r0, "id");
            cJSON *id1 = cJSON_GetObjectItemCaseSensitive(r1, "id");
            CHECK(cJSON_IsNumber(id0) && (int)id0->valuedouble == 1, "batch keeps numeric id");
            CHECK(cJSON_IsString(id1) && strcmp(id1->valuestring, "two") == 0, "batch keeps string id");
            CHECK(cJSON_GetObjectItemCaseSensitive(r0, "result") != NULL, "batch entry 0 succeeded");
            CHECK(cJSON_GetObjectItemCaseSensitive(r1, "result") != NULL, "batch entry 1 succeeded");
            /* 1件のエラーが他のエントリを巻き込まないこと */
            CHECK(error_code_of(r2) == -32601, "unknown method inside a batch returns -32601 for that entry only");
        }
        cJSON_Delete(v);
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "batch request should get a response");
    }

    /* --- 2. 通知(idメンバなし)には応答を返さない(仕様§4.1) --- */
    if (post_json("{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\",\"params\":[]}", &resp) == 0)
    {
        CHECK(resp.status == 204, "a single notification gets 204 No Content");
        CHECK(resp.body_len == 0, "a notification response has an empty body");
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "notification request should get a response");
    }

    /* 全て通知のバッチも同様に何も返さない(仕様§6) */
    if (post_json("[{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\"},"
                   "{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\"}]",
                   &resp)
        == 0)
    {
        CHECK(resp.status == 204, "an all-notification batch gets 204 No Content");
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "all-notification batch should get a response");
    }

    /* 通知と通常リクエストの混在バッチは、通常リクエストの分だけ返す */
    if (post_json("[{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\"},"
                   "{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"id\":9}]",
                   &resp)
        == 0)
    {
        cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
        CHECK(cJSON_IsArray(v) && cJSON_GetArraySize(v) == 1,
              "a mixed batch omits notification entries from the response array");
        cJSON_Delete(v);
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "mixed batch should get a response");
    }

    /* --- 3. 仕様準拠のエラーコード --- */
    /* 空配列は仕様上Invalid Requestで、配列ではなく単一の応答オブジェクトを返す */
    if (post_json("[]", &resp) == 0)
    {
        cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
        CHECK(cJSON_IsObject(v), "an empty batch replies with a single response object, not an array");
        CHECK(error_code_of(v) == -32600, "an empty batch returns -32600 Invalid Request");
        cJSON_Delete(v);
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "empty batch should get a response");
    }

    if (post_json("{not json at all", &resp) == 0)
    {
        cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
        CHECK(error_code_of(v) == -32700, "malformed JSON returns -32700 Parse error");
        cJSON_Delete(v);
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "malformed JSON should get a response");
    }

    if (post_json("{\"jsonrpc\":\"2.0\",\"params\":[],\"id\":1}", &resp) == 0)
    {
        cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
        CHECK(error_code_of(v) == -32600, "a request without a method returns -32600 Invalid Request");
        cJSON_Delete(v);
        http_response_free(&resp);
    }
    else
    {
        CHECK(0, "request without method should get a response");
    }

    /* バッチ件数の上限(BM_JSONRPC_MAX_BATCH_SIZE=256)を超えたら受け付けない */
    {
        size_t n = 257;
        size_t cap = n * 64 + 16;
        char *big = malloc(cap);
        size_t used = 0;
        used += (size_t)snprintf(big + used, cap - used, "[");
        for (size_t i = 0; i < n; i++)
        {
            used += (size_t)snprintf(big + used, cap - used,
                                      "%s{\"jsonrpc\":\"2.0\",\"method\":\"lockAllAddresses\",\"id\":%zu}",
                                      i == 0 ? "" : ",", i);
        }
        used += (size_t)snprintf(big + used, cap - used, "]");
        if (post_json(big, &resp) == 0)
        {
            cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
            CHECK(error_code_of(v) == -32600, "an over-sized batch is rejected with -32600");
            cJSON_Delete(v);
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "over-sized batch should get a response");
        }
        free(big);
    }

    /* --- 4. 深いネストでプロセスが落ちない(旧自前パーサはここでスタックオーバーフローした) --- */
    {
        size_t depth = 100000;
        char *nested = malloc(depth + 1);
        memset(nested, '[', depth);
        nested[depth] = '\0';
        if (post_json(nested, &resp) == 0)
        {
            cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
            CHECK(error_code_of(v) == -32700, "deeply nested JSON is rejected as a parse error, not a crash");
            cJSON_Delete(v);
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "deeply nested JSON should get a response");
        }
        free(nested);
        /* 同じプロセスがまだ生きていて次のリクエストに応答できること(=落ちていないこと) */
        if (post_json("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":99}", &resp) == 0)
        {
            CHECK(resp.status == 200, "the server is still alive after a deeply nested request");
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "the server should still answer after a deeply nested request");
        }
    }

    /* --- 5. Transfer-Encoding: chunked(旧実装はContent-Length必須で受けられなかった) --- */
    {
        const char *part1 = "{\"jsonrpc\":\"2.0\",\"method\":\"list";
        const char *part2 = "Addresses\",\"params\":[],\"id\":7}";
        char raw[2048];
        int raw_len = snprintf(raw, sizeof(raw),
                                "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                                "Content-Type: application/json\r\nConnection: close\r\n"
                                "Transfer-Encoding: chunked\r\n\r\n"
                                "%zx\r\n%s\r\n%zx\r\n%s\r\n0\r\n\r\n",
                                g_auth_b64, strlen(part1), part1, strlen(part2), part2);
        if (send_raw(raw, (size_t)raw_len, &resp) == 0)
        {
            CHECK(resp.status == 200, "a chunked request is accepted");
            cJSON *v = cJSON_ParseWithLength(resp.body, resp.body_len);
            CHECK(cJSON_GetObjectItemCaseSensitive(v, "result") != NULL,
                  "a chunked request is dispatched to the right method");
            cJSON_Delete(v);
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "chunked request should get a response");
        }
    }

    /* --- 6. keep-alive: 1接続で2リクエストを続けて処理できる --- */
    {
        int fd = connect_server();
        CHECK(fd >= 0, "connecting for the keep-alive check");
        if (fd >= 0)
        {
            const char *body = "{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":11}";
            char raw[1024];
            int raw_len = snprintf(raw, sizeof(raw),
                                    "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                                    "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                                    g_auth_b64, strlen(body), body);
            int ok = 1;
            for (int i = 0; i < 2 && ok; i++)
            {
                ok = (write(fd, raw, (size_t)raw_len) == raw_len) && (read_http_response(fd, &resp) == 0);
                if (ok)
                {
                    CHECK(resp.status == 200, "each keep-alive request gets its own 200");
                    http_response_free(&resp);
                }
            }
            CHECK(ok, "two requests should succeed on one persistent connection");
            close(fd);
        }
    }

    /* --- 7. 認証前DoSの解消: 何も送らない接続がサーバーを占有しない --- */
    {
        /*
         * 旧実装ではここでaccept loopがread()にブロックされ、以降の全リクエストが
         * 無期限に待たされた(認証より手前なので資格情報も不要だった)。MHDは接続を
         * ノンブロッキングで多重化するので、放置された接続があっても他のリクエストは
         * 通常通り処理される。
         */
        int idle_fds[8];
        for (int i = 0; i < 8; i++)
        {
            idle_fds[i] = connect_server(); /* 接続だけして1バイトも送らない */
        }
        /* ヘッダを途中まで送って止まる接続も混ぜる(旧実装の\r\n\r\n待ちに相当) */
        int partial_fd = connect_server();
        if (partial_fd >= 0)
        {
            const char *partial = "POST / HTTP/1.1\r\nHost: localhost\r\n";
            CHECK(write(partial_fd, partial, strlen(partial)) > 0, "writing a partial request header");
        }

        time_t started = time(NULL);
        int ok = post_json("{\"jsonrpc\":\"2.0\",\"method\":\"listAddresses\",\"params\":[],\"id\":12}", &resp) == 0;
        time_t elapsed = time(NULL) - started;
        CHECK(ok && resp.status == 200, "a normal request still succeeds while idle connections are held open");
        CHECK(elapsed < 3, "a normal request is not delayed by idle connections");
        if (ok)
        {
            http_response_free(&resp);
        }

        for (int i = 0; i < 8; i++)
        {
            if (idle_fds[i] >= 0)
            {
                close(idle_fds[i]);
            }
        }
        if (partial_fd >= 0)
        {
            close(partial_fd);
        }
    }

    /* --- 8. POST以外は405、資格情報なしは401(旧実装からの互換) --- */
    {
        char raw[1024];
        int raw_len = snprintf(raw, sizeof(raw),
                                "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n"
                                "Connection: close\r\n\r\n",
                                g_auth_b64);
        if (send_raw(raw, (size_t)raw_len, &resp) == 0)
        {
            CHECK(resp.status == 405, "GET is rejected with 405");
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "GET should get a response");
        }

        raw_len = snprintf(raw, sizeof(raw),
                            "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                            "Content-Length: 2\r\n\r\n{}");
        if (send_raw(raw, (size_t)raw_len, &resp) == 0)
        {
            CHECK(resp.status == 401, "a request without credentials is rejected with 401");
            http_response_free(&resp);
        }
        else
        {
            CHECK(0, "unauthenticated request should get a response");
        }
    }

    server_stop = 1;
    pthread_join(server_thread, NULL);

    bm_keyring_lock_all(&kr);
    sqlite3_close(identity_db);
    unlink(TEST_IDENTITY_DB);

    if (failures == 0)
    {
        printf("test_api_transport: all checks passed\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "test_api_transport: %d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
