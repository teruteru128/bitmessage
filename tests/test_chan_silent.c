/*
 * §11 2026-11-07 項目62: chanのアドレスに対するふるまいを本家に揃えたことのテスト。
 *
 * 背景: 本家(dcbcc4a2)はchanのアドレス宛てのgetpubkeyに応答せず(class_objectProcessor.py
 * l.257-261)、chan宛てのmsgに埋め込まれたackも発行しない(l.728-734)。この実装は実行時に
 * is_chanを見ておらず、どちらも処理していた。応答するとPoWを無駄に使い、アドレスやパスフレーズを
 * 知る者がメンバーのオンライン状況を探れる。
 *
 * 検証観点(実際にbm_object_sync_dispatchへobjectを流す):
 * 1. 対照: 通常のアドレスはgetpubkeyに応答し、埋め込まれたackを取り込むこと(テストが
 *    無反応を「正しい」と誤認していないことの確認)
 * 2. unlockしたchanのアドレス宛てのgetpubkeyに応答しないこと(v4、v3、v4のみunlock時のv3要求)
 * 3. 一括unlock(vault方式)でもフラグがkeyringへ反映されること
 * 4. v3からv4への変換で、chanフラグが作成・既存未unlock・既存unlock済みの3経路ともkeyringへ
 *    反映されること(DBのフラグだけでなく、再起動を待たずに効くこと)
 * 5. chan宛てのmsgはinboxへ入り、埋め込まれたackは取り込まれないこと
 */

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/message_builder.h"
#include "../src/core/messages_store.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"

#define TEST_IDENTITY_DB "test_chan_silent_identity.db"
#define TEST_MESSAGES_DB "test_chan_silent_messages.db"
#define TEST_OBJECT_POOL_DB "test_chan_silent_pool.db"
#define PASS "chan silent pass"
#define OBJECT_TTL 3600

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

struct twin
{
    struct bm_generated_address gen;
    char v3[64];
    char v4[64];
};

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

static void env_open(struct env *e)
{
    e->identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    e->messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    e->object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    bm_keyring_init(&e->kr);
    bm_peer_registry_init(&e->registry);
    bm_object_sync_ctx_init(&e->ctx, e->object_pool_db, e->identity_db, e->messages_db, NULL, &e->kr, &e->registry,
                            NULL);
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

/* 応答PoWを軽くするため難易度は50,50(test_getpubkey_twin_versions.cと同じ理由) */
static void store_identity(struct env *e, const struct twin *t, const char *address, int version, int is_chan)
{
    CHECK(bm_keyring_create_identity(e->identity_db, address, "label", version, 1, t->gen.pub_signing,
                                     t->gen.pub_encryption, t->gen.priv_signing, t->gen.priv_encryption, PASS, 50,
                                     50)
              == 0,
          "create identity");
    if (is_chan)
    {
        CHECK(bm_keyring_mark_as_chan(e->identity_db, address) == 0, "mark as chan");
    }
}

static void unlock(struct env *e, const char *address)
{
    CHECK(bm_keyring_unlock(&e->kr, e->identity_db, address, PASS) == 0, "unlock identity");
}

/* payload(nonce抜き)へ実ネットワークの最低難易度でPoWし、nonce付きのobjectを返す */
static unsigned char *pow_object(const unsigned char *payload, size_t len, size_t *out_len)
{
    uint64_t target = bm_pow_get_target(len, OBJECT_TTL, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, len, target);
    unsigned char *object = malloc(8 + len);
    if (object == NULL)
    {
        fprintf(stderr, "out of memory\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, len);
    *out_len = 8 + len;
    return object;
}

static void dispatch_object(struct env *e, const unsigned char *object, size_t object_len)
{
    struct bm_message msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.command, "object", 6);
    msg.length = (uint32_t)object_len;
    msg.payload = (unsigned char *)object;
    bm_object_sync_dispatch(e->conn, &msg, &e->ctx);
}

static void receive_getpubkey(struct env *e, const struct twin *t, uint64_t version)
{
    size_t len = 0;
    unsigned char *payload = bm_build_getpubkey(version, 1, t->gen.ripe, (uint64_t)time(NULL) + OBJECT_TTL, &len);
    size_t object_len = 0;
    unsigned char *object = pow_object(payload, len, &object_len);
    free(payload);
    dispatch_object(e, object, object_len);
    free(object);
}

static int count_pubkeys(struct env *e)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e->object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, BM_OBJECT_PUBKEY);
    int count = (sqlite3_step(stmt) == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return count;
}

/* getpubkeyを受信させ、新しいpubkey objectが増えた数を返す */
static int pubkeys_after_getpubkey(struct env *e, const struct twin *t, uint64_t version)
{
    int before = count_pubkeys(e);
    receive_getpubkey(e, t, version);
    return count_pubkeys(e) - before;
}

static int count_inbox(struct env *e, const char *to_address)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e->messages_db, "SELECT COUNT(*) FROM inbox WHERE to_address = ?1;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, to_address, -1, SQLITE_TRANSIENT);
    int count = (sqlite3_step(stmt) == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return count;
}

static void test_getpubkey(void)
{
    struct env e;
    env_open(&e);

    /* 1. 対照: 通常のアドレスは応答する */
    struct twin normal;
    make_twin("chan silent normal", &normal);
    store_identity(&e, &normal, normal.v4, 4, 0);
    unlock(&e, normal.v4);
    CHECK(pubkeys_after_getpubkey(&e, &normal, 4) == 1, "a normal address answers getpubkey");

    /* 2. chanのアドレスは応答しない。v3の要求でv4の兄弟の鍵を使うフォールバック(項目45)も同じ */
    struct twin chan_v4;
    make_twin("chan silent v4", &chan_v4);
    store_identity(&e, &chan_v4, chan_v4.v4, 4, 1);
    unlock(&e, chan_v4.v4);
    CHECK(pubkeys_after_getpubkey(&e, &chan_v4, 4) == 0, "a v4 chan does not answer v4 getpubkey");
    CHECK(pubkeys_after_getpubkey(&e, &chan_v4, 3) == 0, "a v4 chan does not answer v3 getpubkey for its sibling");

    struct twin chan_v3;
    make_twin("chan silent v3", &chan_v3);
    store_identity(&e, &chan_v3, chan_v3.v3, 3, 1);
    unlock(&e, chan_v3.v3);
    CHECK(pubkeys_after_getpubkey(&e, &chan_v3, 3) == 0, "a v3 chan does not answer v3 getpubkey");

    /* 3. 一括unlock(vault方式)でもフラグが反映される */
    struct twin chan_vault;
    make_twin("chan silent vault", &chan_vault);
    CHECK(bm_keyring_import_identity(e.identity_db, chan_vault.v4, "label", 4, 1, chan_vault.gen.pub_signing,
                                     chan_vault.gen.pub_encryption, chan_vault.gen.priv_signing,
                                     chan_vault.gen.priv_encryption, PASS, 50, 50)
              == 0,
          "import vault identity");
    CHECK(bm_keyring_mark_as_chan(e.identity_db, chan_vault.v4) == 0, "mark vault identity as chan");
    const char *addresses[1] = {chan_vault.v4};
    struct bm_unlock_all_entry result;
    CHECK(bm_keyring_unlock_addresses(&e.kr, e.identity_db, PASS, addresses, 1, &result) == 0 && result.unlocked == 1,
          "bulk unlock vault identity");
    CHECK(pubkeys_after_getpubkey(&e, &chan_vault, 4) == 0, "a bulk-unlocked chan does not answer getpubkey");

    env_close(&e);
}

static void test_convert(void)
{
    struct env e;
    env_open(&e);
    struct bm_keyring_convert_session session;
    bm_keyring_convert_session_init(&session, PASS);
    char v4_address[BM_KEYRING_MAX_ADDRESS_LEN];
    int created = 0;

    /* 4-a. v4を新しく作る経路 */
    struct twin created_twin;
    make_twin("chan silent convert created", &created_twin);
    store_identity(&e, &created_twin, created_twin.v3, 3, 1);
    unlock(&e, created_twin.v3);
    CHECK(bm_keyring_ensure_v4_sibling(&e.kr, e.identity_db, created_twin.v3, &session, v4_address, &created) == 0
              && created == 1,
          "convert creates the v4 sibling");
    CHECK(pubkeys_after_getpubkey(&e, &created_twin, 4) == 0, "a converted chan does not answer getpubkey");

    /* 4-b. 未unlockのv4(chanフラグ無し)が既にある経路 */
    struct twin locked_twin;
    make_twin("chan silent convert locked", &locked_twin);
    store_identity(&e, &locked_twin, locked_twin.v3, 3, 1);
    store_identity(&e, &locked_twin, locked_twin.v4, 4, 0);
    unlock(&e, locked_twin.v3);
    CHECK(bm_keyring_ensure_v4_sibling(&e.kr, e.identity_db, locked_twin.v3, &session, v4_address, &created) == 0
              && created == 0,
          "convert reuses the locked v4 sibling");
    CHECK(pubkeys_after_getpubkey(&e, &locked_twin, 4) == 0, "the flag reaches a v4 unlocked by the conversion");

    /* 4-c. unlock済みのv4(chanフラグ無し)が既にある経路。再起動を待たずに効くこと */
    struct twin unlocked_twin;
    make_twin("chan silent convert unlocked", &unlocked_twin);
    store_identity(&e, &unlocked_twin, unlocked_twin.v3, 3, 1);
    store_identity(&e, &unlocked_twin, unlocked_twin.v4, 4, 0);
    unlock(&e, unlocked_twin.v3);
    unlock(&e, unlocked_twin.v4);
    CHECK(bm_keyring_ensure_v4_sibling(&e.kr, e.identity_db, unlocked_twin.v3, &session, v4_address, &created) == 0
              && created == 0,
          "convert reuses the unlocked v4 sibling");
    CHECK(bm_keyring_lock(&e.kr, unlocked_twin.v3) == 0, "lock the v3 sibling as the caller of convert does");
    CHECK(pubkeys_after_getpubkey(&e, &unlocked_twin, 4) == 0, "the flag reaches an already unlocked v4");

    bm_keyring_convert_session_clear(&session);
    env_close(&e);
}

/* senderからtoへ、PoW済みのackを埋め込んだmsgを受信させる。戻り値はackのobjectが取り込まれたか */
static int receive_msg_with_ack(struct env *e, const struct bm_generated_address *sender, const struct twin *to)
{
    uint64_t expires_time = (uint64_t)time(NULL) + OBJECT_TTL;

    size_t ack_body_len = 0;
    unsigned char *ack_body = bm_build_ack_object(1, 1, &ack_body_len);
    size_t ack_payload_len = 8 + ack_body_len;
    unsigned char *ack_payload = malloc(ack_payload_len);
    if (ack_body == NULL || ack_payload == NULL)
    {
        fprintf(stderr, "failed to build the ack\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < 8; i++)
    {
        ack_payload[i] = (unsigned char)((expires_time >> (56 - 8 * i)) & 0xff);
    }
    memcpy(ack_payload + 8, ack_body, ack_body_len);
    free(ack_body);

    size_t ack_object_len = 0;
    unsigned char *ack_object = pow_object(ack_payload, ack_payload_len, &ack_object_len);
    free(ack_payload);
    unsigned char ack_hash[32];
    bm_inventory_hash(ack_object, ack_object_len, ack_hash);
    size_t packet_len = 0;
    unsigned char *packet = bm_create_packet("object", ack_object, ack_object_len, &packet_len);
    free(ack_object);

    struct bm_identity_info from;
    memset(&from, 0, sizeof(from));
    from.address_version = 4;
    from.stream = 1;
    memcpy(from.pub_signing, sender->pub_signing, 65);
    memcpy(from.pub_encryption, sender->pub_encryption, 65);
    memcpy(from.priv_signing, sender->priv_signing, 32);
    from.nonce_trials_per_byte = 1000;
    from.payload_length_extra_bytes = 1000;
    from.does_ack = 1;

    size_t msg_len = 0;
    unsigned char *msg_payload = bm_build_msg(&from, 1, to->gen.ripe, to->gen.pub_encryption, "subject", "body", packet,
                                              packet_len, expires_time, &msg_len);
    free(packet);
    OPENSSL_cleanse(&from, sizeof(from));
    CHECK(msg_payload != NULL, "build msg");
    size_t object_len = 0;
    unsigned char *object = pow_object(msg_payload, msg_len, &object_len);
    free(msg_payload);
    dispatch_object(e, object, object_len);
    free(object);

    return bm_object_store_has(e->object_pool_db, ack_hash);
}

static void test_ack(void)
{
    struct env e;
    env_open(&e);
    struct bm_generated_address sender;
    CHECK(bm_address_generate_deterministic("chan silent sender", 1, &sender) == 0, "generate sender");

    /* 1. 対照: 通常のアドレス宛てのackは取り込む */
    struct twin normal;
    make_twin("chan silent ack normal", &normal);
    store_identity(&e, &normal, normal.v4, 4, 0);
    unlock(&e, normal.v4);
    CHECK(receive_msg_with_ack(&e, &sender, &normal), "the ack of a msg to a normal address is stored");
    CHECK(count_inbox(&e, normal.v4) == 1, "a msg to a normal address reaches the inbox");

    /* 5. chan宛てのackは取り込まないが、投稿そのものはinboxへ入る */
    struct twin chan;
    make_twin("chan silent ack chan", &chan);
    store_identity(&e, &chan, chan.v4, 4, 1);
    unlock(&e, chan.v4);
    CHECK(!receive_msg_with_ack(&e, &sender, &chan), "the ack of a msg to a chan is not stored");
    CHECK(count_inbox(&e, chan.v4) == 1, "a msg to a chan still reaches the inbox");

    env_close(&e);
}

int main(void)
{
    test_getpubkey();
    test_convert();
    test_ack();

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_chan_silent: OK\n");
    return EXIT_SUCCESS;
}
