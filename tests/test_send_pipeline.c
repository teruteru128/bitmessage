/*
 * core/send_pipeline.c のend-to-endテスト。
 * 2つのidentity(送信者・受信者)を作成し、send_pipelineで送信 -> sentテーブルへの記録を確認
 * -> 受信者のkeyringでtrial_decryptし、内容とackPayloadの整合性(§5.5)まで検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pubkey_cache.h"
#include "../src/core/send_pipeline.h"
#include "../src/core/trial_decrypt.h"

#define TEST_IDENTITY_DB "test_send_pipeline_identity.db"
#define TEST_MESSAGES_DB "test_send_pipeline_messages.db"

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

static char *create_and_unlock(sqlite3 *identity_db, bm_keyring_t *kr, const char *seed_passphrase,
                                const char *store_passphrase, struct bm_generated_address *out_gen)
{
    CHECK(bm_address_generate_deterministic(seed_passphrase, 1, out_gen) == 0, "generate address");
    char *address = bm_address_encode(4, 1, out_gen->ripe, BM_RIPE_LEN);
    CHECK(address != NULL, "encode address");
    CHECK(bm_keyring_create_identity(identity_db, address, "test", 4, 1,
                                      out_gen->pub_signing, out_gen->pub_encryption,
                                      out_gen->priv_signing, out_gen->priv_encryption,
                                      store_passphrase, 50, 50) == 0,
          "create_identity");
    CHECK(bm_keyring_unlock(kr, identity_db, address, store_passphrase) == 0, "unlock identity");
    return address;
}

int main(void)
{
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_generated_address sender_gen;
    char *sender_address = create_and_unlock(identity_db, &kr, "send_pipeline test sender",
                                              "sender storage passphrase", &sender_gen);

    struct bm_generated_address recv_gen;
    char *recv_address = create_and_unlock(identity_db, &kr, "send_pipeline test receiver",
                                            "receiver storage passphrase", &recv_gen);

    const char *subject = "send_pipeline test";
    const char *body = "does send_pipeline actually produce a decryptable object?";

    /* §11 2026-08-31 ユーザー指摘: is_selfの判定をto_ripe==from_id.ripe(fromAddressとtoAddressが
     * 全く同一)だけでなく、toAddressがidentity.dbに存在する(=このノードが持つ別のidentityでも
     * ある)かどうかで見るよう修正した。recv_addressはこの下でidentity_dbにcreate_and_unlock
     * 済みのため、以後のsend_pipeline呼び出しは常にis_self経路(ack省略/msgsentnoackexpected/
     * inboxへの即時ループバック)を通る。pubkey_cacheへの事前登録は不要になった
     * (identity.dbのencryption_pubkeyがそのまま使われるため)。 */
    unsigned char *object = NULL;
    size_t object_len = 0;
    int rc = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                            subject, body,
                                            /*ttl_seconds=*/60, /*ack_stealth_level=*/1,
                                            NULL, (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                            &object, &object_len);
    CHECK(rc == 0, "bm_send_pipeline_send_message");
    CHECK(object != NULL && object_len > 0, "produced object should be non-empty");

    /* sentテーブルに1行記録されているか。recv_addressはidentity_db内の別identityなので
     * is_self経路(§11 2026-08-31)を通り、status='msgsentnoackexpected'になる */
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT to_address, from_address, subject, status FROM sent;", -1, &stmt, NULL);
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        row_count++;
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 0), recv_address) == 0, "sent.to_address");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 1), sender_address) == 0, "sent.from_address");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 2), subject) == 0, "sent.subject");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 3), "msgsentnoackexpected") == 0, "sent.status");
    }
    sqlite3_finalize(stmt);
    CHECK(row_count == 1, "sent table should have exactly 1 row");

    /* is_self経路はack自体を生成しない(§11 2026-08-31、PyBitmessage本家準拠)ため、
     * sent.ack_dataは長さ0で記録されるはず */
    sqlite3_prepare_v2(messages_db, "SELECT ack_data FROM sent WHERE to_address = ?1;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "fetch ack_data from sent");
    CHECK(sqlite3_column_bytes(stmt, 0) == 0, "sent.ack_data should be empty for is_self send");
    sqlite3_finalize(stmt);

    /* 受信者のkeyringでトライアル復号する(送信者もkeyringに入っているが、toRipe不一致で
     * 送信者自身の鍵では復号成功してもfailするはず、受信者の鍵でのみ成功する) */
    struct bm_decoded_msg decoded;
    rc = bm_trial_decrypt_msg(&kr, object, object_len, &decoded);
    CHECK(rc == 0, "bm_trial_decrypt_msg on send_pipeline output");

    if (rc == 0)
    {
        CHECK(strcmp(decoded.to_address, recv_address) == 0, "decoded.to_address");
        CHECK(strcmp(decoded.from_address, sender_address) == 0, "decoded.from_address");
        CHECK(strcmp(decoded.subject, subject) == 0, "decoded.subject");
        CHECK(strcmp(decoded.body, body) == 0, "decoded.body");
        CHECK(decoded.ack_payload_len == 0 && decoded.ack_payload == NULL,
              "decoded ack_payload should be absent for is_self send");

        printf("OK: send_pipeline -> trial_decrypt (is_self, ack省略) まで確認\n");
        bm_decoded_msg_free(&decoded);
    }

    /* §11 2026-08-31: is_self送信は送信直後にmessages.dbのinboxへ直接ループバックされるはず
     * (ネットワーク往復を待たない、PyBitmessage本家helper_inbox.insert()相当) */
    sqlite3_prepare_v2(messages_db,
                        "SELECT to_address, from_address, subject, body FROM inbox WHERE to_address = ?1;",
                        -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "is_self send should be looped back into inbox immediately");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 0), recv_address) == 0, "inbox.to_address");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 1), sender_address) == 0, "inbox.from_address");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 2), subject) == 0, "inbox.subject");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 3), body) == 0, "inbox.body");
    sqlite3_finalize(stmt);

    /* §11 2026-08-31: is_self判定はidentity.db在籍だけで決まり、keyringでunlock中かどうかは
     * 無関係(bm_identity_store_loadはunlock不要でDB内の平文encryption_pubkeyを直接読む)。
     * recv_addressをlockした状態でも同じis_self経路(ack省略・inboxループバック)が機能する
     * ことを確認する(ユーザー指摘: to_ripe==from_id.ripeだけを見ていた旧実装は、fromと別の
     * 自分のidentity宛を捕捉できていなかった。その修正がunlock状態に依存しないことも担保する)。 */
    CHECK(bm_keyring_lock(&kr, recv_address) == 0, "lock receiver before locked-recipient send test");

    unsigned char *object_locked_recv = NULL;
    size_t object_locked_recv_len = 0;
    int rc_locked_recv = bm_send_pipeline_send_message(
        &kr, identity_db, messages_db, sender_address, recv_address,
        "locked recv subject", "locked recv body", 60, 1,
        NULL, (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS,
        &object_locked_recv, &object_locked_recv_len);
    CHECK(rc_locked_recv == 0, "is_self send should succeed even when the recipient identity is locked");
    free(object_locked_recv);

    /* subject列はBLOB(messages_store.cのスキーマ)なので、TEXTでbindすると型affinityの
     * 違いでSQL上の"="が一致しない(SQLiteの比較ルールでBLOB<>TEXTは常に不一致になる)。
     * insert_inbox自身がsubjectをbind_blobしているのに合わせ、ここもbind_blobで比較する。 */
    static const char *locked_recv_subject = "locked recv subject";
    sqlite3_prepare_v2(messages_db,
                        "SELECT COUNT(*) FROM inbox WHERE to_address = ?1 AND subject = ?2;",
                        -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, locked_recv_subject, (int)strlen(locked_recv_subject), SQLITE_TRANSIENT);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "query inbox count for locked-recipient send");
    CHECK(sqlite3_column_int(stmt, 0) == 1, "locked-recipient is_self send should still loop back into inbox");
    sqlite3_finalize(stmt);

    /* pubkey_cacheフォールバック: cacheに無ければ失敗し、事前にbm_pubkey_cache_upsertして
     * おけば成功する(§2.3, core/pubkey_cache.c)。まだ一度も送っていない別の宛先を使う。 */
    struct bm_generated_address recv2_gen;
    CHECK(bm_address_generate_deterministic("send_pipeline test receiver 2", 1, &recv2_gen) == 0,
          "generate second receiver address");
    char *recv2_address = bm_address_encode(4, 1, recv2_gen.ripe, BM_RIPE_LEN);
    CHECK(recv2_address != NULL, "encode second receiver address");

    unsigned char *object_no_pubkey = NULL;
    size_t object_no_pubkey_len = 0;
    int rc_no_cache = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv2_address,
                                                     subject, body, 60, 1,
                                                     NULL, (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                                     &object_no_pubkey, &object_no_pubkey_len);
    CHECK(rc_no_cache != 0, "sendMessage should fail when pubkey_cache is empty");

    struct bm_cached_pubkey cached;
    memset(&cached, 0, sizeof(cached));
    memcpy(cached.ripe, recv2_gen.ripe, BM_RIPE_LEN);
    cached.address_version = 4;
    cached.stream = 1;
    memcpy(cached.signing_pubkey, recv2_gen.pub_signing, 65);
    memcpy(cached.encryption_pubkey, recv2_gen.pub_encryption, 65);
    cached.nonce_trials_per_byte = 1000;
    cached.payload_length_extra_bytes = 1000;
    CHECK(bm_pubkey_cache_upsert(identity_db, &cached, 1234567890) == 0, "seed pubkey_cache for receiver");

    unsigned char *object_from_cache = NULL;
    size_t object_from_cache_len = 0;
    int rc_from_cache = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv2_address,
                                                       subject, body, 60, 1,
                                                       NULL, (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                                       &object_from_cache, &object_from_cache_len);
    CHECK(rc_from_cache == 0, "sendMessage should succeed once pubkey_cache is populated");
    CHECK(object_from_cache != NULL && object_from_cache_len > 0, "cache-derived object non-empty");
    free(object_from_cache);

    if (failures == 0)
    {
        printf("OK: pubkey_cache fallback in send_pipeline (fails empty, succeeds once cached)\n");
    }

    free(object);
    free(sender_address);
    free(recv_address);
    free(recv2_address);
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
