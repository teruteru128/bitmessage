/*
 * §11 2026-09-24 項目45 v3アドレスを兄弟のv4へ寄せる移行API(convertAddressToV4 /
 * convertV3AddressesToV4)のテスト。
 *
 * 背景: 同じ鍵ペアから作ったv3とv4のアドレスはripeが共通で、受信したmsgの宛先がどちらだったかは
 * ワイヤー上で区別できない。v3とv4を両方持っていると受信ボックスの宛先がunlock順で決まって
 * しまうため、v3をやめてv4に一本化する操作を用意した。鍵のラップはAAD(とvault方式では
 * HKDFのinfo)にアドレス文字列を使っているので、v3行のwrapped鍵をコピーするのではなく、
 * 一度復号してv4のアドレスでラップし直す必要がある。
 *
 * 検証観点(実HTTPリクエスト経由):
 * 1. scrypt方式・unlock済み・chan・label/難易度付きのv3を変換すると、それらを引き継いだv4が
 *    作られ、同じpassphraseでunlock/exportでき(鍵が同一)、v4がunlock状態・v3は削除かつ
 *    keyringからも外れ、inboxのto_address・sentのfrom_addressがv4に書き換わること
 * 2. vault方式のv3で、兄弟のv4が既にある(labelは空)場合、v4は作り直さず(created=false)、
 *    空のlabelだけv3から補われ、v3が削除されること
 * 3. v4アドレス・存在しないアドレス・passphrase違いはそれぞれエラーになること
 * 4. v4を用意した後に中断した(v3が残った)状態から、同じv3をもう一度変換すると完了すること
 * 5. 一括版はlimit件(成功件数)で止まってremainingを返し、passphraseが合わない行は失敗として
 *    報告しつつ読み飛ばして先の行を変換できること(失敗行が先頭に残っても詰まらないこと)
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

#include <openssl/crypto.h>

#include "../src/common/json.h"
#include "../src/core/address.h"
#include "../src/core/api_server.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"

#define TEST_PORT 18448
#define TEST_IDENTITY_DB "test_convert_v3_to_v4_identity.db"
#define TEST_MESSAGES_DB "test_convert_v3_to_v4_messages.db"
#define PASS "convert pass"

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

/* test_getpubkey_automation.cと同じ最小限のHTTPクライアント */
static char *do_http_post(const char *body)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
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

    /* "testuser:testpass"のbase64 */
    char request[8192];
    int req_len = snprintf(request, sizeof(request),
                           "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=\r\n"
                           "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                           "Connection: close\r\n\r\n%s",
                           strlen(body), body);
    CHECK(write(sock, request, (size_t)req_len) == req_len, "writing the HTTP request should not short-write");

    static char buf[1 << 20];
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

/* JSON-RPC応答全体をパースして返す(呼び出し側でbm_json_free) */
static bm_json_value_t *rpc(const char *method, const char *params_json)
{
    char body[2048];
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":1}", method,
             params_json);
    char *resp = do_http_post(body);
    CHECK(resp != NULL, "HTTP request");
    if (resp == NULL)
    {
        return NULL;
    }
    bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
    free(resp);
    CHECK(v != NULL, "parse JSON-RPC response");
    return v;
}

static const char *error_message(const bm_json_value_t *resp)
{
    bm_json_value_t *err = resp != NULL ? bm_json_object_get(resp, "error") : NULL;
    return err != NULL ? bm_json_as_string(bm_json_object_get(err, "message")) : NULL;
}

static int json_true(const bm_json_value_t *v)
{
    return v != NULL && v->type == BM_JSON_BOOL && v->boolean;
}

struct twin
{
    struct bm_generated_address gen;
    char v3[64];
    char v4[64];
};

static void make_twin(const char *seed, struct twin *t)
{
    CHECK(bm_address_generate_deterministic(seed, 1, &t->gen) == 0, "generate address");
    char *v3 = bm_address_encode(3, 1, t->gen.ripe, BM_RIPE_LEN);
    char *v4 = bm_address_encode(4, 1, t->gen.ripe, BM_RIPE_LEN);
    snprintf(t->v3, sizeof(t->v3), "%s", v3 != NULL ? v3 : "");
    snprintf(t->v4, sizeof(t->v4), "%s", v4 != NULL ? v4 : "");
    free(v3);
    free(v4);
}

/* vault方式で保存する(importAddress相当) */
static void store_vault(sqlite3 *db, const struct twin *t, const char *address, int version, const char *label)
{
    CHECK(bm_keyring_import_identity(db, address, label, version, 1, t->gen.pub_signing, t->gen.pub_encryption,
                                     t->gen.priv_signing, t->gen.priv_encryption, PASS, 1000, 1000) == 0,
          "store vault identity");
}

static int identity_exists(sqlite3 *db, const char *address)
{
    struct bm_identity_row row;
    int rc = bm_identity_store_load(db, address, &row);
    OPENSSL_cleanse(&row, sizeof(row));
    return rc == 0;
}

static int count_rows(sqlite3 *db, const char *sql, const char *address)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    int n = (sqlite3_step(stmt) == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return n;
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
    config.default_nonce_trials_per_byte = 1000;
    config.default_payload_length_extra_bytes = 1000;

    _Atomic sig_atomic_t server_stop = 0;
    struct bm_api_server_thread_args *server_args = malloc(sizeof(*server_args));
    server_args->config = &config;
    server_args->stop_flag = &server_stop;
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, bm_api_server_thread, server_args);
    usleep(200000);

    char params[512];

    /* --- 1. scrypt方式・unlock済み・chan・label/難易度付きのv3を単体変換 --- */
    struct twin a;
    make_twin("convert v3 scrypt", &a);
    CHECK(bm_keyring_create_identity(identity_db, a.v3, "label A", 3, 1, a.gen.pub_signing, a.gen.pub_encryption,
                                     a.gen.priv_signing, a.gen.priv_encryption, PASS, 2000, 3000) == 0,
          "create scrypt v3");
    CHECK(bm_keyring_mark_as_chan(identity_db, a.v3) == 0, "mark v3 as chan");
    CHECK(bm_keyring_unlock(&kr, identity_db, a.v3, PASS) == 0, "unlock v3");
    unsigned char msg_id[32];
    memset(msg_id, 0xa1, sizeof(msg_id));
    CHECK(bm_messages_store_insert_inbox(messages_db, msg_id, a.v3, "BM-sender", "subj", "body", 1) == 0,
          "insert inbox row addressed to v3");
    unsigned char ack[32];
    memset(ack, 0xb2, sizeof(ack));
    CHECK(bm_messages_store_insert_sent(messages_db, msg_id, ack, sizeof(ack), "BM-recipient", a.v3, "subj", "body",
                                        "msgsent", 1, 1, 3600, 0) == 0,
          "insert sent row from v3");

    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", a.v3, PASS);
    bm_json_value_t *resp = rpc("convertAddressToV4", params);
    bm_json_value_t *result = resp != NULL ? bm_json_object_get(resp, "result") : NULL;
    CHECK(result != NULL && result->type == BM_JSON_OBJECT, "convertAddressToV4 succeeds");
    if (result != NULL && result->type == BM_JSON_OBJECT)
    {
        const char *v4 = bm_json_as_string(bm_json_object_get(result, "v4Address"));
        CHECK(v4 != NULL && strcmp(v4, a.v4) == 0, "v4Address is the v4 sibling of the same ripe");
        CHECK(json_true(bm_json_object_get(result, "created")), "created=true when v4 did not exist");
    }
    bm_json_free(resp);

    struct bm_identity_row row;
    CHECK(bm_identity_store_load(identity_db, a.v4, &row) == 0, "v4 row exists");
    CHECK(row.address_version == 4 && row.stream == 1, "v4 row has version 4 / stream 1");
    CHECK(strcmp(row.label, "label A") == 0, "label is carried over");
    CHECK(row.is_chan == 1, "chan flag is carried over");
    CHECK(row.nonce_trials_per_byte == 2000 && row.payload_length_extra_bytes == 3000,
          "difficulty is carried over");
    CHECK(strcmp(row.kdf_algo, "scrypt") == 0, "wrap method follows the v3 row (scrypt)");
    OPENSSL_cleanse(&row, sizeof(row));
    CHECK(!identity_exists(identity_db, a.v3), "v3 row is deleted");

    struct bm_unlocked_identity found;
    CHECK(bm_keyring_find_by_address(&kr, a.v4, &found), "v4 is unlocked because v3 was");
    CHECK(!bm_keyring_find_by_address(&kr, a.v3, &found), "v3 is removed from the keyring");
    OPENSSL_cleanse(&found, sizeof(found));

    unsigned char exp_sig[32];
    unsigned char exp_enc[32];
    CHECK(bm_keyring_export(identity_db, a.v4, PASS, exp_sig, exp_enc) == 0, "v4 exports with the same passphrase");
    CHECK(memcmp(exp_sig, a.gen.priv_signing, 32) == 0 && memcmp(exp_enc, a.gen.priv_encryption, 32) == 0,
          "v4 holds the same private keys");
    OPENSSL_cleanse(exp_sig, sizeof(exp_sig));
    OPENSSL_cleanse(exp_enc, sizeof(exp_enc));

    CHECK(count_rows(messages_db, "SELECT COUNT(*) FROM inbox WHERE to_address = ?1;", a.v4) == 1,
          "inbox to_address is rewritten to v4");
    CHECK(count_rows(messages_db, "SELECT COUNT(*) FROM sent WHERE from_address = ?1;", a.v4) == 1,
          "sent from_address is rewritten to v4");
    CHECK(count_rows(messages_db, "SELECT COUNT(*) FROM inbox WHERE to_address = ?1;", a.v3) == 0,
          "no inbox row points at v3 anymore");

    /* --- 2. vault方式のv3、兄弟のv4(labelは空)が既にある --- */
    struct twin b;
    make_twin("convert v3 vault existing v4", &b);
    store_vault(identity_db, &b, b.v4, 4, "");
    store_vault(identity_db, &b, b.v3, 3, "label B");
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", b.v3, PASS);
    resp = rpc("convertAddressToV4", params);
    result = resp != NULL ? bm_json_object_get(resp, "result") : NULL;
    CHECK(result != NULL && result->type == BM_JSON_OBJECT, "convert with an existing v4 succeeds");
    if (result != NULL && result->type == BM_JSON_OBJECT)
    {
        bm_json_value_t *created = bm_json_object_get(result, "created");
        CHECK(created != NULL && created->type == BM_JSON_BOOL && !created->boolean,
              "created=false when v4 already existed");
    }
    bm_json_free(resp);
    CHECK(bm_identity_store_load(identity_db, b.v4, &row) == 0 && strcmp(row.label, "label B") == 0,
          "empty v4 label is filled from v3");
    OPENSSL_cleanse(&row, sizeof(row));
    CHECK(!identity_exists(identity_db, b.v3), "v3 row is deleted");

    /* --- 3. エラー --- */
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", b.v4, PASS);
    resp = rpc("convertAddressToV4", params);
    const char *msg = error_message(resp);
    CHECK(msg != NULL && strstr(msg, "not a v3 address") != NULL, "converting a v4 address is an error");
    bm_json_free(resp);

    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", a.v3, PASS);
    resp = rpc("convertAddressToV4", params);
    msg = error_message(resp);
    CHECK(msg != NULL && strstr(msg, "address not found") != NULL, "converting an unknown address is an error");
    bm_json_free(resp);

    struct twin w;
    make_twin("convert v3 other passphrase", &w);
    CHECK(bm_keyring_create_identity(identity_db, w.v3, "", 3, 1, w.gen.pub_signing, w.gen.pub_encryption,
                                     w.gen.priv_signing, w.gen.priv_encryption, "other pass", 1000, 1000) == 0,
          "create v3 with another passphrase");
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", w.v3, PASS);
    resp = rpc("convertAddressToV4", params);
    msg = error_message(resp);
    CHECK(msg != NULL && strstr(msg, "wrong passphrase") != NULL, "wrong passphrase is an error");
    bm_json_free(resp);
    CHECK(identity_exists(identity_db, w.v3) && !identity_exists(identity_db, w.v4),
          "a failed conversion leaves v3 as is and creates no v4");

    /* --- 4. v4を用意した後で中断した状態からの再実行 --- */
    struct twin r;
    make_twin("convert v3 resume", &r);
    store_vault(identity_db, &r, r.v3, 3, "label R");
    struct bm_keyring_convert_session session;
    bm_keyring_convert_session_init(&session, PASS);
    char v4_out[BM_KEYRING_MAX_ADDRESS_LEN];
    int created = 0;
    CHECK(bm_keyring_ensure_v4_sibling(&kr, identity_db, r.v3, &session, v4_out, &created) == 0 && created == 1,
          "prepare v4 only (simulating an interruption before v3 is deleted)");
    bm_keyring_convert_session_clear(&session);
    CHECK(identity_exists(identity_db, r.v3) && identity_exists(identity_db, r.v4), "both exist mid-way");
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", r.v3, PASS);
    resp = rpc("convertAddressToV4", params);
    result = resp != NULL ? bm_json_object_get(resp, "result") : NULL;
    CHECK(result != NULL && result->type == BM_JSON_OBJECT, "re-running the conversion succeeds");
    bm_json_free(resp);
    CHECK(!identity_exists(identity_db, r.v3) && identity_exists(identity_db, r.v4), "re-run finishes the job");

    /* --- 5. 一括版: passphrase違いの行(w)が残っていてもlimit件まで先へ進む --- */
    struct twin bulk[3];
    for (int i = 0; i < 3; i++)
    {
        char seed[64];
        snprintf(seed, sizeof(seed), "convert v3 bulk %d", i);
        make_twin(seed, &bulk[i]);
        store_vault(identity_db, &bulk[i], bulk[i].v3, 3, "");
    }
    snprintf(params, sizeof(params), "[\"%s\",2]", PASS);
    resp = rpc("convertV3AddressesToV4", params);
    result = resp != NULL ? bm_json_object_get(resp, "result") : NULL;
    CHECK(result != NULL && result->type == BM_JSON_OBJECT, "convertV3AddressesToV4 succeeds");
    if (result != NULL && result->type == BM_JSON_OBJECT)
    {
        bm_json_value_t *converted = bm_json_object_get(result, "converted");
        bm_json_value_t *failed = bm_json_object_get(result, "failed");
        CHECK(converted != NULL && converted->item_count == 2, "limit=2 converts exactly 2");
        CHECK(failed != NULL && failed->item_count == 1, "the other-passphrase row is reported as failed");
        if (failed != NULL && failed->item_count == 1)
        {
            const char *fa = bm_json_as_string(bm_json_object_get(bm_json_array_get(failed, 0), "v3Address"));
            CHECK(fa != NULL && strcmp(fa, w.v3) == 0, "the failed row is the other-passphrase one");
        }
        CHECK(bm_json_as_number(bm_json_object_get(result, "remaining")) == 2,
              "remaining counts the failed row and the one not yet processed");
    }
    bm_json_free(resp);

    snprintf(params, sizeof(params), "[\"%s\"]", PASS);
    resp = rpc("convertV3AddressesToV4", params);
    result = resp != NULL ? bm_json_object_get(resp, "result") : NULL;
    if (result != NULL && result->type == BM_JSON_OBJECT)
    {
        bm_json_value_t *converted = bm_json_object_get(result, "converted");
        CHECK(converted != NULL && converted->item_count == 1, "the second call converts the last one");
        CHECK(bm_json_as_number(bm_json_object_get(result, "remaining")) == 1, "only the failing row remains");
    }
    else
    {
        CHECK(0, "second convertV3AddressesToV4 succeeds");
    }
    bm_json_free(resp);
    for (int i = 0; i < 3; i++)
    {
        CHECK(!identity_exists(identity_db, bulk[i].v3) && identity_exists(identity_db, bulk[i].v4),
              "every bulk row ends up as v4");
    }

    snprintf(params, sizeof(params), "[\"%s\",0]", PASS);
    resp = rpc("convertV3AddressesToV4", params);
    msg = error_message(resp);
    CHECK(msg != NULL && strstr(msg, "limit") != NULL, "limit=0 is rejected");
    bm_json_free(resp);

    server_stop = 1;
    pthread_join(server_thread, NULL);
    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);

    if (failures == 0)
    {
        printf("OK: convert v3 to v4\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return EXIT_FAILURE;
}
