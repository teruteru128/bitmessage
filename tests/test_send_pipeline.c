/*
 * core/send_pipeline.c のend-to-endテスト。
 * 2つのidentity(送信者・受信者)を作成し、send_pipelineで送信 -> sentテーブルへの記録を確認
 * -> 受信者のkeyringでtrial_decryptし、内容とackPayloadの整合性(§5.5)まで検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pubkey_cache.h"
#include "../src/core/send_pipeline.h"
#include "../src/core/trial_decrypt.h"
#include "../src/infra/object.h"
#include "../src/infra/protocol.h"

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

    unsigned char *object = NULL;
    size_t object_len = 0;
    int rc = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                            recv_gen.pub_encryption, subject, body,
                                            /*ttl_seconds=*/60, /*ack_stealth_level=*/1,
                                            &object, &object_len);
    CHECK(rc == 0, "bm_send_pipeline_send_message");
    CHECK(object != NULL && object_len > 0, "produced object should be non-empty");

    /* sentテーブルに1行記録されているか */
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT to_address, from_address, subject, status FROM sent;", -1, &stmt, NULL);
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        row_count++;
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 0), recv_address) == 0, "sent.to_address");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 1), sender_address) == 0, "sent.from_address");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 2), subject) == 0, "sent.subject");
        CHECK(strcmp((const char *)sqlite3_column_text(stmt, 3), "sent") == 0, "sent.status");
    }
    sqlite3_finalize(stmt);
    CHECK(row_count == 1, "sent table should have exactly 1 row");

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

        /* ackPayload(msgへ平文埋め込みされたfullAckPayload、§5.5)は完成したP2P "object"パケット
         * (24byteヘッダ込み)であり、それをパースした中身(nonce付きobjectバイト列)がsentテーブルの
         * ack_dataと一致するはず(sent.ack_dataはack_data、埋め込み側はack_dataをbm_create_packetで
         * さらに包んだack_packet、send_pipeline.c参照)。 */
        struct bm_message *ack_msg = NULL;
        size_t ack_consumed = 0;
        enum bm_parse_result ack_parse_rc =
            bm_parse_message(decoded.ack_payload, decoded.ack_payload_len, &ack_msg, &ack_consumed);
        CHECK(ack_parse_rc == BM_PARSE_OK, "ack_payload should parse as a complete P2P message");
        CHECK(ack_consumed == decoded.ack_payload_len, "ack_payload should be exactly one P2P message");
        CHECK(ack_msg != NULL && strncmp(ack_msg->command, "object", 12) == 0,
              "ack_payload's P2P command should be \"object\"");

        sqlite3_prepare_v2(messages_db, "SELECT ack_data FROM sent WHERE to_address = ?1;", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(stmt) == SQLITE_ROW, "fetch ack_data from sent");
        const void *ack_data = sqlite3_column_blob(stmt, 0);
        int ack_data_len = sqlite3_column_bytes(stmt, 0);
        if (ack_msg != NULL)
        {
            CHECK((size_t)ack_data_len == ack_msg->length, "sent.ack_data length matches ack_payload's inner object");
            CHECK(ack_data_len > 0 && memcmp(ack_data, ack_msg->payload, (size_t)ack_data_len) == 0,
                  "sent.ack_data content matches ack_payload's inner object");

            /* sent.ack_data(nonce込み)の共通ヘッダも正しくパースできる(§5.0)ことを確認 */
            struct bm_object_header ack_hdr;
            CHECK(bm_object_parse_header(ack_msg->payload, ack_msg->length, &ack_hdr) == 0,
                  "sent.ack_data should parse as a valid object header");
        }
        sqlite3_finalize(stmt);
        bm_free_message(ack_msg);

        printf("OK: send_pipeline -> trial_decrypt -> ack_data一致まで確認\n");
        bm_decoded_msg_free(&decoded);
    }

    /* pubkey_cacheフォールバック: to_pub_encryption=NULLで呼ぶと、cacheに無ければ失敗し、
     * 事前にbm_pubkey_cache_upsertしておけば成功する(§2.3, core/pubkey_cache.c) */
    unsigned char *object_no_pubkey = NULL;
    size_t object_no_pubkey_len = 0;
    int rc_no_cache = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                                     NULL, subject, body, 60, 1,
                                                     &object_no_pubkey, &object_no_pubkey_len);
    CHECK(rc_no_cache != 0, "sendMessage with NULL pubkey should fail when cache is empty");

    struct bm_cached_pubkey cached;
    memset(&cached, 0, sizeof(cached));
    memcpy(cached.ripe, recv_gen.ripe, BM_RIPE_LEN);
    cached.address_version = 4;
    cached.stream = 1;
    memcpy(cached.signing_pubkey, recv_gen.pub_signing, 65);
    memcpy(cached.encryption_pubkey, recv_gen.pub_encryption, 65);
    cached.nonce_trials_per_byte = 1000;
    cached.payload_length_extra_bytes = 1000;
    CHECK(bm_pubkey_cache_upsert(identity_db, &cached, 1234567890) == 0, "seed pubkey_cache for receiver");

    unsigned char *object_from_cache = NULL;
    size_t object_from_cache_len = 0;
    int rc_from_cache = bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                                       NULL, subject, body, 60, 1,
                                                       &object_from_cache, &object_from_cache_len);
    CHECK(rc_from_cache == 0, "sendMessage with NULL pubkey should succeed once cached");
    CHECK(object_from_cache != NULL && object_from_cache_len > 0, "cache-derived object non-empty");
    free(object_from_cache);

    if (failures == 0)
    {
        printf("OK: pubkey_cache fallback in send_pipeline (fails empty, succeeds once cached)\n");
    }

    free(object);
    free(sender_address);
    free(recv_address);
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
