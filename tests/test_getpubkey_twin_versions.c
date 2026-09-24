/*
 * §11 2026-09-24 同じ鍵ペアから作ったv3とv4のアドレス(以下「兄弟」、ripeが共通)が両方unlock
 * されている状態での、getpubkeyへの自応答のテスト。
 *
 * 背景: handle_incoming_getpubkey(infra/object_sync.c)はv2/v3の要求をripeだけで引いており、
 * 応答objectのキャッシュ(self_pubkey_response_cache)もripeだけをキーにしていた。そのため
 * 兄弟が共存すると、
 *   - keyringの並び(unlock順)次第で、v3の要求にv4のidentityが当たってv4形式のpubkeyを返す
 *   - v4の要求に対して、直前に作ったv3のpubkey objectのinvを再broadcastして済ませる(逆も)
 * という取り違えが起き、どちらかのversionのアドレス宛に送ろうとしている相手がpubkeyを
 * 入手できなくなっていた。
 *
 * 検証観点:
 * 1. bm_keyring_find_by_ripe_versionが、ripeが同じでもversion/streamで兄弟を区別すること
 * 2. 兄弟が両方unlockされている場合、unlock順(どちらがkeyringの先頭か)によらず、
 *    v3の要求にはv3のpubkeyを、v4の要求にはv4のpubkeyを返し、それぞれのキャッシュが
 *    独立して効くこと(2回目の要求では新しいobjectを作らない)
 * 3. v4だけがunlockされている場合(v3をconvertV3AddressesToV4でv4へ寄せた後の状態)、v3の要求には
 *    v4の鍵から作ったv3形式のpubkeyで応答し、そのキャッシュも効くこと。v2の要求や、streamが
 *    違うv3の要求には応答しないこと(本家processgetpubkeyからの意図的な逸脱、DESIGN.md §11
 *    項目45参照)
 * 4. 要求のstreamがidentityのstreamと違えば応答しないこと
 * 5. self_pubkey_response_cacheの旧スキーマ(ripe単独がPRIMARY KEY)を持つDBに対して
 *    bm_identity_store_init_schemaを呼ぶと、新スキーマで作り直されること(再実行しても
 *    新スキーマの行は消えないこと)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/address.h"
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

#define TEST_IDENTITY_DB "test_getpubkey_twin_versions_identity.db"
#define TEST_MESSAGES_DB "test_getpubkey_twin_versions_messages.db"
#define TEST_OBJECT_POOL_DB "test_getpubkey_twin_versions_pool.db"
#define TEST_MIGRATION_DB "test_getpubkey_twin_versions_migration.db"

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
    sqlite3 *object_pool_db;
    bm_keyring_t kr;
    struct bm_peer_registry registry;
    struct bm_object_sync_ctx ctx;
    int fds[2];
    struct bm_fd_data *conn;
};

static void env_open(struct env *e)
{
    e->identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    e->messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    e->object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    bm_keyring_init(&e->kr);
    bm_peer_registry_init(&e->registry);
    bm_object_sync_ctx_init(&e->ctx, e->object_pool_db, e->identity_db, e->messages_db, NULL, &e->kr,
                            &e->registry, NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, e->fds) == 0, "socketpair");
    e->conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, e->fds[0]);
}

static void env_close(struct env *e)
{
    close(e->fds[0]);
    close(e->fds[1]);
    bm_fd_data_free(e->conn);
    bm_peer_registry_destroy(&e->registry);
    bm_keyring_destroy(&e->kr);
    sqlite3_close(e->identity_db);
    sqlite3_close(e->messages_db);
    sqlite3_close(e->object_pool_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);
}

/* genの鍵で、指定versionのidentityを作ってunlockする。応答PoWを軽くするため難易度は50,50
 * (test_getpubkey_automation.cと同じ理由) */
static void add_identity(struct env *e, const struct bm_generated_address *gen, int version, int stream)
{
    char *address = bm_address_encode((uint64_t)version, (uint64_t)stream, gen->ripe, BM_RIPE_LEN);
    CHECK(address != NULL, "encode address");
    if (address == NULL)
    {
        return;
    }
    CHECK(bm_keyring_create_identity(e->identity_db, address, "twin", version, stream, gen->pub_signing,
                                      gen->pub_encryption, gen->priv_signing, gen->priv_encryption, "twin pass",
                                      50, 50) == 0,
          "create identity");
    CHECK(bm_keyring_unlock(&e->kr, e->identity_db, address, "twin pass") == 0, "unlock identity");
    free(address);
}

/* genのripe宛のgetpubkey(version/stream指定)を受信させる */
static void receive_getpubkey(struct env *e, const struct bm_generated_address *gen, uint64_t version,
                              uint64_t stream)
{
    uint64_t ttl = 3600;
    size_t len = 0;
    unsigned char *payload = bm_build_getpubkey(version, stream, gen->ripe, (uint64_t)time(NULL) + ttl, &len);
    uint64_t target = bm_pow_get_target(len, ttl, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, len, target);
    size_t object_len = 8 + len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, len);
    free(payload);

    struct bm_message msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.command, "object", 6);
    msg.length = (uint32_t)object_len;
    msg.payload = object;
    bm_object_sync_dispatch(e->conn, &msg, &e->ctx);
    free(object);
}

/* object_pool.db内のpubkey objectを、指定versionの形式でgenの鍵としてパースできる数を数える
 * (version<0なら形式を問わず全pubkey objectを数える) */
static int count_pubkeys(struct env *e, const struct bm_generated_address *gen, int version)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e->object_pool_db, "SELECT payload FROM objects WHERE object_type = ?1;", -1, &stmt,
                       NULL);
    sqlite3_bind_int(stmt, 1, BM_OBJECT_PUBKEY);
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const unsigned char *obj = sqlite3_column_blob(stmt, 0);
        size_t obj_len = (size_t)sqlite3_column_bytes(stmt, 0);
        if (version < 0)
        {
            count++;
            continue;
        }
        struct bm_object_header hdr;
        if (bm_object_parse_header(obj, obj_len, &hdr) != 0 || hdr.version != (uint64_t)version)
        {
            continue;
        }
        struct bm_cached_pubkey parsed;
        int rc = -1;
        if (version == 3)
        {
            rc = bm_parse_pubkey_v3(obj, obj_len, &parsed);
        }
        else if (version == 4)
        {
            rc = bm_parse_pubkey_v4(obj, obj_len, gen->ripe, 4, hdr.stream, &parsed);
        }
        if (rc == 0 && memcmp(parsed.signing_pubkey, gen->pub_signing, 65) == 0
            && memcmp(parsed.encryption_pubkey, gen->pub_encryption, 65) == 0)
        {
            count++;
        }
    }
    sqlite3_finalize(stmt);
    return count;
}

static void test_find_by_ripe_version(void)
{
    struct env e;
    env_open(&e);
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic("getpubkey twin find", 1, &gen) == 0, "generate address");
    add_identity(&e, &gen, 4, 1);
    add_identity(&e, &gen, 3, 1);

    struct bm_unlocked_identity found;
    CHECK(bm_keyring_find_by_ripe_version(&e.kr, gen.ripe, 3, 1, &found) && found.address_version == 3,
          "find_by_ripe_version(3) returns the v3 twin");
    CHECK(bm_keyring_find_by_ripe_version(&e.kr, gen.ripe, 4, 1, &found) && found.address_version == 4,
          "find_by_ripe_version(4) returns the v4 twin");
    CHECK(!bm_keyring_find_by_ripe_version(&e.kr, gen.ripe, 2, 1, &found),
          "find_by_ripe_version(2) finds nothing (no v2 identity)");
    CHECK(!bm_keyring_find_by_ripe_version(&e.kr, gen.ripe, 3, 2, &found),
          "find_by_ripe_version with a different stream finds nothing");
    env_close(&e);
}

/* v4_first: v4を先にunlockする(=v3がkeyringの先頭になる)か、その逆か */
static void test_twins_answered_per_version(int v4_first)
{
    struct env e;
    env_open(&e);
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic("getpubkey twin answer", 1, &gen) == 0, "generate address");
    if (v4_first)
    {
        add_identity(&e, &gen, 4, 1);
        add_identity(&e, &gen, 3, 1);
    }
    else
    {
        add_identity(&e, &gen, 3, 1);
        add_identity(&e, &gen, 4, 1);
    }

    receive_getpubkey(&e, &gen, 4, 1);
    CHECK(count_pubkeys(&e, &gen, 4) == 1, "v4 getpubkey is answered with a v4 pubkey");
    CHECK(count_pubkeys(&e, &gen, -1) == 1, "exactly one pubkey object after the v4 request");

    receive_getpubkey(&e, &gen, 3, 1);
    CHECK(count_pubkeys(&e, &gen, 3) == 1,
          "v3 getpubkey is answered with a v3 pubkey, not the cached v4 one or a new v4 one");
    CHECK(count_pubkeys(&e, &gen, -1) == 2, "exactly two pubkey objects after the v3 request");

    /* それぞれのキャッシュが独立して効き、2回目は新しいobjectを作らない */
    receive_getpubkey(&e, &gen, 4, 1);
    receive_getpubkey(&e, &gen, 3, 1);
    CHECK(count_pubkeys(&e, &gen, -1) == 2, "repeated requests reuse the per-version cached responses");

    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e.identity_db,
                       "SELECT COUNT(*) FROM self_pubkey_response_cache WHERE ripe = ?1 AND stream = 1;", -1,
                       &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, gen.ripe, BM_RIPE_LEN, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 2,
          "self_pubkey_response_cache holds one row per version for the shared ripe");
    sqlite3_finalize(stmt);
    env_close(&e);
}

static void test_v3_request_without_v3_identity(void)
{
    struct env e;
    env_open(&e);
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic("getpubkey twin v4 only", 1, &gen) == 0, "generate address");
    add_identity(&e, &gen, 4, 1);

    receive_getpubkey(&e, &gen, 3, 1);
    CHECK(count_pubkeys(&e, &gen, 3) == 1,
          "v3 getpubkey is answered with a v3 pubkey built from the v4 identity's keys");
    CHECK(count_pubkeys(&e, &gen, -1) == 1, "exactly one pubkey object after the v3 request");

    receive_getpubkey(&e, &gen, 3, 1);
    CHECK(count_pubkeys(&e, &gen, -1) == 1, "a repeated v3 request reuses the cached v3 response");

    receive_getpubkey(&e, &gen, 2, 1);
    receive_getpubkey(&e, &gen, 3, 2);
    CHECK(count_pubkeys(&e, &gen, -1) == 1, "v2 requests and v3 requests on another stream are not answered");

    receive_getpubkey(&e, &gen, 4, 1);
    CHECK(count_pubkeys(&e, &gen, 4) == 1, "v4 getpubkey is still answered");
    env_close(&e);
}

static void test_stream_mismatch(void)
{
    struct env e;
    env_open(&e);
    struct bm_generated_address gen;
    CHECK(bm_address_generate_deterministic("getpubkey twin stream", 1, &gen) == 0, "generate address");
    add_identity(&e, &gen, 3, 1);

    receive_getpubkey(&e, &gen, 3, 2);
    CHECK(count_pubkeys(&e, &gen, -1) == 0, "v3 getpubkey on a different stream is not answered");
    env_close(&e);
}

static void test_cache_schema_migration(void)
{
    unlink(TEST_MIGRATION_DB);
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(TEST_MIGRATION_DB, &db) == SQLITE_OK, "open migration db");
    CHECK(sqlite3_exec(db,
                       "CREATE TABLE self_pubkey_response_cache (ripe BLOB PRIMARY KEY, object_hash BLOB NOT NULL, "
                       "expires_time INTEGER NOT NULL);"
                       "INSERT INTO self_pubkey_response_cache VALUES (zeroblob(20), zeroblob(32), 9999999999);",
                       NULL, NULL, NULL)
              == SQLITE_OK,
          "create old-schema cache table");

    CHECK(bm_identity_store_init_schema(db) == 0, "init_schema over an old-schema db");
    CHECK(sqlite3_exec(db, "SELECT address_version, stream FROM self_pubkey_response_cache LIMIT 0;", NULL, NULL,
                       NULL)
              == SQLITE_OK,
          "cache table is recreated with address_version/stream columns");

    unsigned char ripe[20] = {0};
    unsigned char hash3[32];
    unsigned char hash4[32];
    memset(hash3, 3, sizeof(hash3));
    memset(hash4, 4, sizeof(hash4));
    unsigned char out[32];
    CHECK(bm_pubkey_cache_get_self_response(db, ripe, 3, 1, 0, out) == 0, "old rows are gone after migration");
    CHECK(bm_pubkey_cache_set_self_response(db, ripe, 3, 1, hash3, 9999999999) == 0, "set v3 response");
    CHECK(bm_pubkey_cache_set_self_response(db, ripe, 4, 1, hash4, 9999999999) == 0, "set v4 response");

    /* 新スキーマのDBに対する再実行は何も消さない */
    CHECK(bm_identity_store_init_schema(db) == 0, "init_schema again");
    CHECK(bm_pubkey_cache_get_self_response(db, ripe, 3, 1, 0, out) == 1 && memcmp(out, hash3, 32) == 0,
          "v3 cached response survives re-init and is not overwritten by v4");
    CHECK(bm_pubkey_cache_get_self_response(db, ripe, 4, 1, 0, out) == 1 && memcmp(out, hash4, 32) == 0,
          "v4 cached response survives re-init");
    CHECK(bm_pubkey_cache_get_self_response(db, ripe, 4, 2, 0, out) == 0, "different stream is a separate key");

    sqlite3_close(db);
    unlink(TEST_MIGRATION_DB);
}

int main(void)
{
    test_find_by_ripe_version();
    test_twins_answered_per_version(1);
    test_twins_answered_per_version(0);
    test_v3_request_without_v3_identity();
    test_stream_mismatch();
    test_cache_schema_migration();

    if (failures == 0)
    {
        printf("OK: getpubkey twin versions\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return EXIT_FAILURE;
}
