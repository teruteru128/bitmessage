/*
 * core/pubkey_cache.c のテスト。
 * message_builder.cのbm_build_pubkey_v2/v3/v4で組み立てたobjectをbm_parse_pubkey_v2/v3/v4で
 * パースし直し、フィールドが一致することを確認する(build/parseの往復)。
 * さらにDB(identity.db)へのupsert/lookup、改竄検出も検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/message_builder.h"
#include "../src/core/pubkey_cache.h"

#define TEST_DB_PATH "test_pubkey_cache_identity.db"

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

static void make_identity(const char *passphrase, struct bm_identity_info *out_id,
                           unsigned char out_ripe[20])
{
    struct bm_generated_address gen;
    if (bm_address_generate_deterministic(passphrase, 1, &gen) != 0)
    {
        fprintf(stderr, "FATAL: generate_deterministic failed\n");
        exit(EXIT_FAILURE);
    }
    memset(out_id, 0, sizeof(*out_id));
    out_id->address_version = 4;
    out_id->stream = 1;
    memcpy(out_id->pub_signing, gen.pub_signing, 65);
    memcpy(out_id->pub_encryption, gen.pub_encryption, 65);
    memcpy(out_id->priv_signing, gen.priv_signing, 32);
    out_id->nonce_trials_per_byte = 1000;
    out_id->payload_length_extra_bytes = 1000;
    out_id->does_ack = 1;
    memcpy(out_ripe, gen.ripe, 20);
}

static void check_matches(const struct bm_identity_info *id, const struct bm_cached_pubkey *parsed,
                           const char *label)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "%s: signing_pubkey matches", label);
    CHECK(memcmp(id->pub_signing, parsed->signing_pubkey, 65) == 0, msg);
    snprintf(msg, sizeof(msg), "%s: encryption_pubkey matches", label);
    CHECK(memcmp(id->pub_encryption, parsed->encryption_pubkey, 65) == 0, msg);
    snprintf(msg, sizeof(msg), "%s: behavior_bitfield reflects doesAck", label);
    CHECK(parsed->behavior_bitfield == 1, msg);
}

static void test_pubkey_v2(void)
{
    struct bm_identity_info id;
    unsigned char ripe[20];
    make_identity("pubkey_cache test v2", &id, ripe);
    id.address_version = 2;

    size_t obj_len = 0;
    unsigned char *obj = bm_build_pubkey_v2(&id, 1234567890, &obj_len);
    CHECK(obj != NULL, "bm_build_pubkey_v2");
    /* nonce抜きのpayloadなので、パーサに渡す前にダミーnonce(8byte)を先頭に付与する
     * (v1のPoW前payloadはnonceを含まないが、object全体としてパースするには必要) */
    unsigned char *object = malloc(8 + obj_len);
    memset(object, 0, 8);
    memcpy(object + 8, obj, obj_len);
    free(obj);

    struct bm_cached_pubkey parsed;
    int rc = bm_parse_pubkey_v2(object, 8 + obj_len, &parsed);
    CHECK(rc == 0, "bm_parse_pubkey_v2");
    if (rc == 0)
    {
        check_matches(&id, &parsed, "v2");
        CHECK(parsed.address_version == 2, "v2 address_version");
        CHECK(memcmp(parsed.ripe, ripe, 20) == 0, "v2 ripe matches original");
    }
    free(object);

    if (failures == 0)
    {
        printf("OK: pubkey v2 build -> parse round-trip\n");
    }
}

static void test_pubkey_v3(void)
{
    struct bm_identity_info id;
    unsigned char ripe[20];
    make_identity("pubkey_cache test v3", &id, ripe);
    id.address_version = 3;

    size_t obj_len = 0;
    unsigned char *obj = bm_build_pubkey_v3(&id, 1234567890, &obj_len);
    CHECK(obj != NULL, "bm_build_pubkey_v3");
    unsigned char *object = malloc(8 + obj_len);
    memset(object, 0, 8);
    memcpy(object + 8, obj, obj_len);
    free(obj);

    struct bm_cached_pubkey parsed;
    int rc = bm_parse_pubkey_v3(object, 8 + obj_len, &parsed);
    CHECK(rc == 0, "bm_parse_pubkey_v3 (signature verification)");
    if (rc == 0)
    {
        check_matches(&id, &parsed, "v3");
        CHECK(parsed.nonce_trials_per_byte == 1000, "v3 nonceTrialsPerByte");
        CHECK(parsed.payload_length_extra_bytes == 1000, "v3 payloadLengthExtraBytes");
        CHECK(memcmp(parsed.ripe, ripe, 20) == 0, "v3 ripe matches original");
    }

    /* 改竄検出: 署名部の1byteを反転させたら失敗すること */
    object[8 + obj_len - 1] ^= 0xff;
    struct bm_cached_pubkey tampered;
    rc = bm_parse_pubkey_v3(object, 8 + obj_len, &tampered);
    CHECK(rc != 0, "tampered v3 signature should fail verification");

    free(object);

    if (failures == 0)
    {
        printf("OK: pubkey v3 build -> parse round-trip, tamper detection\n");
    }
}

static void test_pubkey_v4(void)
{
    struct bm_identity_info id;
    unsigned char ripe[20];
    make_identity("pubkey_cache test v4", &id, ripe);
    id.address_version = 4;

    size_t obj_len = 0;
    unsigned char *obj = bm_build_pubkey_v4(&id, ripe, 1234567890, &obj_len);
    CHECK(obj != NULL, "bm_build_pubkey_v4");
    unsigned char *object = malloc(8 + obj_len);
    memset(object, 0, 8);
    memcpy(object + 8, obj, obj_len);
    free(obj);

    /* 別のアドレス宛だと仮定すると(tagが合わないので)失敗すること */
    unsigned char wrong_ripe[20];
    memset(wrong_ripe, 0x42, sizeof(wrong_ripe));
    struct bm_cached_pubkey wrong_result;
    int rc = bm_parse_pubkey_v4(object, 8 + obj_len, wrong_ripe, 4, 1, &wrong_result);
    CHECK(rc != 0, "v4 parse with wrong candidate ripe should fail (tag mismatch)");

    struct bm_cached_pubkey parsed;
    rc = bm_parse_pubkey_v4(object, 8 + obj_len, ripe, 4, 1, &parsed);
    CHECK(rc == 0, "bm_parse_pubkey_v4 with correct candidate");
    if (rc == 0)
    {
        check_matches(&id, &parsed, "v4");
        CHECK(memcmp(parsed.ripe, ripe, 20) == 0, "v4 ripe matches candidate");
    }

    free(object);

    if (failures == 0)
    {
        printf("OK: pubkey v4 build -> parse round-trip (tag matching, decrypt, signature verify)\n");
    }
}

static void test_db_roundtrip(void)
{
    unlink(TEST_DB_PATH);
    sqlite3 *db = NULL;
    if (sqlite3_open(TEST_DB_PATH, &db) != SQLITE_OK || bm_identity_store_init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", TEST_DB_PATH);
        exit(EXIT_FAILURE);
    }

    struct bm_identity_info id;
    unsigned char ripe[20];
    make_identity("pubkey_cache test db roundtrip", &id, ripe);

    struct bm_cached_pubkey entry;
    memset(&entry, 0, sizeof(entry));
    memcpy(entry.ripe, ripe, 20);
    entry.address_version = 4;
    entry.stream = 1;
    entry.behavior_bitfield = 1;
    memcpy(entry.signing_pubkey, id.pub_signing, 65);
    memcpy(entry.encryption_pubkey, id.pub_encryption, 65);
    entry.nonce_trials_per_byte = 1000;
    entry.payload_length_extra_bytes = 1000;

    CHECK(bm_pubkey_cache_upsert(db, &entry, 1111111111) == 0, "upsert pubkey_cache entry");

    struct bm_cached_pubkey looked_up;
    CHECK(bm_pubkey_cache_lookup_by_ripe(db, ripe, &looked_up) == 0, "lookup by ripe");
    CHECK(memcmp(looked_up.signing_pubkey, id.pub_signing, 65) == 0, "looked up signing_pubkey matches");
    CHECK(looked_up.nonce_trials_per_byte == 1000, "looked up nonceTrialsPerByte matches");

    unsigned char unknown_ripe[20];
    memset(unknown_ripe, 0xee, sizeof(unknown_ripe));
    struct bm_cached_pubkey not_found;
    CHECK(bm_pubkey_cache_lookup_by_ripe(db, unknown_ripe, &not_found) != 0, "lookup of unknown ripe fails");

    CHECK(bm_pubkey_cache_mark_used_personally(db, ripe) == 0, "mark used_personally");

    /* upsert再実行(更新)しても行数は増えないこと */
    entry.behavior_bitfield = 0;
    CHECK(bm_pubkey_cache_upsert(db, &entry, 2222222222) == 0, "upsert again (update)");
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, "SELECT COUNT(*), used_personally FROM pubkey_cache;", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    int used = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    CHECK(count == 1, "upsert does not duplicate rows");
    CHECK(used == 1, "used_personally survives upsert (not reset by update)");

    sqlite3_close(db);
    unlink(TEST_DB_PATH);

    if (failures == 0)
    {
        printf("OK: pubkey_cache DB upsert/lookup/mark_used_personally\n");
    }
}

int main(void)
{
    test_pubkey_v2();
    test_pubkey_v3();
    test_pubkey_v4();
    test_db_roundtrip();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
