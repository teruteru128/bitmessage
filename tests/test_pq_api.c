/*
 * §11 2026-11-04 項目55の段4: ポスト量子拡張(v5)のアドレスをJSON-RPC APIで扱えること
 * (core/api_server.c)のテスト。DESIGN-PQ.md §9.1のフェーズ2。
 *
 * 背景: v5のidentityはv4以前とは別の表(pq_identities)と別のkeyringのリストに持つ(段3)。
 * APIの各操作は、アドレス文字列の形(version 5)でv5を見分けて振り分ける。実行時フラグ
 * ([pq] enabled、config->pq_enabled)が無効なら、v5を扱う操作は明示的なエラーにする。
 *
 * 検証観点(フラグ有効):
 * 1. createDeterministicAddressのversion 5で53文字のv5アドレスが作られること
 * 2. listAddressesにv5が出ること(作成直後はunlocked=false)
 * 3. unlockAddress: 誤ったpassphraseではfalse、正しければtrueで、一覧もunlocked=trueになること
 * 4. unlockAddresses: v4とv5が混ざっていても両方unlockされ、存在しないv5は
 *    "address not found"になること(結果は要求の並び)
 * 5. setAddressLabelがv5のラベルを変えること
 * 6. exportAddressはv5を明示的に断ること
 * 7. lockAllAddressesの後、unlockAllAddressesでv5もunlockされること
 * 8. deleteAddressでv5の行が消えること
 * 検証観点(フラグ無効): createDeterministicAddress(version 5)・unlockAddress・unlockAddressesが
 * v5について「post-quantum (v5) support is disabled」のエラーを返すこと。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/pq_identity_store.h"
#include "../src/pq/address_v5.h"

#define TEST_PORT_ENABLED 18454
#define TEST_PORT_DISABLED 18455
#define TEST_IDENTITY_DB "test_pq_api_identity.db"
#define STORE_PASS "pq api store pass"

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

static int current_port;

/* JSON-RPCを1本送り、応答全体(mallocした文字列)を返す */
static char *rpc(const char *method, const char *params_json)
{
    char body[4096];
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":1}", method,
             params_json);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {30, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)current_port);
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
    size_t cap = 65536;
    size_t total = 0;
    char *buf = malloc(cap);
    ssize_t n;
    while (total + 1 < cap && (n = read(sock, buf + total, cap - 1 - total)) > 0)
    {
        total += (size_t)n;
    }
    close(sock);
    buf[total] = '\0';
    return buf;
}

/* 応答の"result":"..."の文字列を取り出す(無ければ空文字列) */
static void result_string(const char *resp, char *out, size_t out_size)
{
    out[0] = '\0';
    const char *p = resp != NULL ? strstr(resp, "\"result\":\"") : NULL;
    if (p == NULL)
    {
        return;
    }
    p += strlen("\"result\":\"");
    const char *end = strchr(p, '"');
    if (end == NULL || (size_t)(end - p) >= out_size)
    {
        return;
    }
    memcpy(out, p, (size_t)(end - p));
    out[end - p] = '\0';
}

static int contains(const char *resp, const char *needle)
{
    return resp != NULL && strstr(resp, needle) != NULL;
}

/* listAddressesの応答から、addressの要素のlabel/unlockedを確かめる */
static int listed_as(const char *address, const char *label, int unlocked)
{
    char *resp = rpc("listAddresses", "[]");
    char needle[512];
    snprintf(needle, sizeof(needle), "{\"address\":\"%s\",\"label\":\"%s\",\"enabled\":true,\"unlocked\":%s", address,
             label, unlocked ? "true" : "false");
    int ok = contains(resp, needle);
    free(resp);
    return ok;
}

struct server
{
    struct bm_api_server_config config;
    _Atomic sig_atomic_t stop;
    pthread_t thread;
};

static void server_start(struct server *s, sqlite3 *db, bm_keyring_t *kr, int port, int pq_enabled)
{
    memset(&s->config, 0, sizeof(s->config));
    s->config.bind_address = "127.0.0.1";
    s->config.port = port;
    s->config.username = NULL; /* 認証なし(テスト用) */
    s->config.keyring = kr;
    s->config.identity_db = db;
    s->config.default_nonce_trials_per_byte = 1000;
    s->config.default_payload_length_extra_bytes = 1000;
    s->config.pq_enabled = pq_enabled;
    s->stop = 0;
    struct bm_api_server_thread_args *args = malloc(sizeof(*args));
    args->config = &s->config;
    args->stop_flag = &s->stop;
    pthread_create(&s->thread, NULL, bm_api_server_thread, args);
    usleep(200000);
    current_port = port;
}

static void server_stop(struct server *s)
{
    s->stop = 1;
    pthread_join(s->thread, NULL);
}

int main(void)
{
    unlink(TEST_IDENTITY_DB);
    sqlite3 *db = NULL;
    if (sqlite3_open(TEST_IDENTITY_DB, &db) != SQLITE_OK || bm_identity_store_init_schema(db) != 0)
    {
        fprintf(stderr, "failed to open db\n");
        return EXIT_FAILURE;
    }
    bm_keyring_t kr;
    bm_keyring_init(&kr);

    static struct server enabled;
    server_start(&enabled, db, &kr, TEST_PORT_ENABLED, 1);

    /* 1. 作成 */
    char *resp = rpc("createDeterministicAddress", "[\"pq api passphrase\",5,1,1,\"pqlabel\",\"" STORE_PASS "\"]");
    char v5[BM_KEYRING_MAX_ADDRESS_LEN];
    result_string(resp, v5, sizeof(v5));
    CHECK(strncmp(v5, "BM-", 3) == 0 && strlen(v5) == 53, "createDeterministicAddress version 5 returns a v5 address");
    free(resp);
    resp = rpc("createDeterministicAddress", "[\"pq api v4 passphrase\",4,1,1,\"v4label\",\"" STORE_PASS "\"]");
    char v4[BM_KEYRING_MAX_ADDRESS_LEN];
    result_string(resp, v4, sizeof(v4));
    CHECK(strncmp(v4, "BM-", 3) == 0 && strlen(v4) < 40, "createDeterministicAddress version 4 still works");
    free(resp);

    /* 2. 一覧 */
    CHECK(listed_as(v5, "pqlabel", 0), "v5 identity is listed, locked");

    /* 3. unlockAddress */
    char params[1024];
    snprintf(params, sizeof(params), "[\"%s\",\"wrong pass\"]", v5);
    resp = rpc("unlockAddress", params);
    CHECK(contains(resp, "\"result\":false"), "unlockAddress with a wrong passphrase returns false");
    free(resp);
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", v5, STORE_PASS);
    resp = rpc("unlockAddress", params);
    CHECK(contains(resp, "\"result\":true"), "unlockAddress unlocks the v5 identity");
    free(resp);
    CHECK(listed_as(v5, "pqlabel", 1), "listAddresses shows the v5 identity as unlocked");

    /* 4. unlockAddresses(v4とv5と、存在しないv5) */
    snprintf(params, sizeof(params), "[\"%s\"]", v5);
    resp = rpc("lockAddress", params);
    CHECK(contains(resp, "\"result\":true"), "lockAddress locks the v5 identity");
    free(resp);
    static struct bm_pqv5_identity other;
    CHECK(bm_pqv5_identity_generate_deterministic("not stored", 1, 0, 1, &other) == 0, "generate a v5 not stored");
    char *missing = bm_pqv5_address_encode(5, 1, other.id);
    snprintf(params, sizeof(params), "[[\"%s\",\"%s\",\"%s\"],\"%s\"]", v4, v5, missing, STORE_PASS);
    resp = rpc("unlockAddresses", params);
    char expect_v4[256], expect_v5[256], expect_missing[256];
    snprintf(expect_v4, sizeof(expect_v4), "{\"address\":\"%s\",\"unlocked\":true}", v4);
    snprintf(expect_v5, sizeof(expect_v5), "{\"address\":\"%s\",\"unlocked\":true}", v5);
    snprintf(expect_missing, sizeof(expect_missing), "{\"address\":\"%s\",\"unlocked\":false,\"error\":\"address not found\"}",
             missing);
    CHECK(contains(resp, expect_v4) && contains(resp, expect_v5), "unlockAddresses unlocks both v4 and v5");
    CHECK(contains(resp, expect_missing), "unlockAddresses reports a missing v5 address as not found");
    const char *p4 = resp != NULL ? strstr(resp, expect_v4) : NULL;
    const char *p5 = resp != NULL ? strstr(resp, expect_v5) : NULL;
    const char *pm = resp != NULL ? strstr(resp, expect_missing) : NULL;
    CHECK(p4 != NULL && p5 != NULL && pm != NULL && p4 < p5 && p5 < pm, "unlockAddresses keeps the request order");
    free(resp);

    /* 5. setAddressLabel */
    snprintf(params, sizeof(params), "[\"%s\",\"renamed\"]", v5);
    resp = rpc("setAddressLabel", params);
    CHECK(contains(resp, "\"result\":true"), "setAddressLabel accepts a v5 address");
    free(resp);
    CHECK(listed_as(v5, "renamed", 1), "the v5 label is changed");

    /* 6. exportAddress */
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", v5, STORE_PASS);
    resp = rpc("exportAddress", params);
    CHECK(contains(resp, "does not support v5"), "exportAddress refuses v5 explicitly");
    free(resp);

    /* 7. lockAll → unlockAll */
    resp = rpc("lockAllAddresses", "[]");
    free(resp);
    CHECK(listed_as(v5, "renamed", 0), "lockAllAddresses also locks v5");
    resp = rpc("unlockAllAddresses", "[\"" STORE_PASS "\"]");
    CHECK(contains(resp, expect_v5), "unlockAllAddresses also unlocks v5");
    free(resp);

    /* 8. deleteAddress */
    snprintf(params, sizeof(params), "[\"%s\"]", v5);
    resp = rpc("deleteAddress", params);
    CHECK(contains(resp, "\"result\":true"), "deleteAddress accepts a v5 address");
    free(resp);
    struct bm_pq_identity_row *row = malloc(sizeof(*row));
    CHECK(bm_pq_identity_store_load(db, v5, row) != 0, "the v5 row is deleted");
    free(row);
    resp = rpc("listAddresses", "[]");
    CHECK(!contains(resp, v5) && contains(resp, v4), "the v5 identity is no longer listed (v4 remains)");
    free(resp);

    server_stop(&enabled);

    /* フラグ無効 */
    static struct server disabled;
    server_start(&disabled, db, &kr, TEST_PORT_DISABLED, 0);
    resp = rpc("createDeterministicAddress", "[\"pq api passphrase\",5,1,1,\"x\",\"" STORE_PASS "\"]");
    CHECK(contains(resp, "post-quantum (v5) support is disabled"), "version 5 is refused when the flag is off");
    free(resp);
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", missing, STORE_PASS);
    resp = rpc("unlockAddress", params);
    CHECK(contains(resp, "post-quantum (v5) support is disabled"), "unlockAddress refuses v5 when the flag is off");
    free(resp);
    snprintf(params, sizeof(params), "[[\"%s\",\"%s\"],\"%s\"]", v4, missing, STORE_PASS);
    resp = rpc("unlockAddresses", params);
    CHECK(contains(resp, "post-quantum (v5) support is disabled"),
          "unlockAddresses refuses a list containing v5 when the flag is off");
    free(resp);
    server_stop(&disabled);

    free(missing);
    bm_keyring_destroy(&kr);
    sqlite3_close(db);
    unlink(TEST_IDENTITY_DB);

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_pq_api: all checks passed\n");
    return EXIT_SUCCESS;
}
