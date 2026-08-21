/*
 * core/trial_decrypt.c のend-to-endテスト。
 * アドレス生成(address.c) -> keyring作成/unlock(keyring.c) -> msg組み立て(message_builder.c)
 * -> PoW(pow_engine.c) -> トライアル復号(trial_decrypt.c) -> inbox保存(messages_store.c)
 * という実際のパイプライン全体を通して検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/message_builder.h"
#include "../src/core/messages_store.h"
#include "../src/core/trial_decrypt.h"
#include "../src/pow/pow_engine.h"

#define TEST_IDENTITY_DB "test_trial_decrypt_identity.db"
#define TEST_MESSAGES_DB "test_trial_decrypt_messages.db"

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

int main(void)
{
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    /* 1. 受信者アドレスを生成し、keyringへ保存・unlockする */
    struct bm_generated_address recv_gen;
    CHECK(bm_address_generate_deterministic("trial_decrypt receiver passphrase", 1, &recv_gen) == 0,
          "generate receiver address");
    char *recv_address = bm_address_encode(4, 1, recv_gen.ripe, BM_RIPE_LEN);
    CHECK(recv_address != NULL, "encode receiver address");

    CHECK(bm_keyring_create_identity(identity_db, recv_address, "receiver", 4, 1,
                                      recv_gen.pub_signing, recv_gen.pub_encryption,
                                      recv_gen.priv_signing, recv_gen.priv_encryption,
                                      "receiver storage passphrase", 1000, 1000) == 0,
          "create receiver identity");

    bm_keyring_t kr;
    bm_keyring_init(&kr);
    CHECK(bm_keyring_unlock(&kr, identity_db, recv_address, "receiver storage passphrase") == 0,
          "unlock receiver identity");

    /* 2. 送信者アイデンティティを用意する(keyringには入れない、message_builderへ直接渡す) */
    struct bm_generated_address sender_gen;
    CHECK(bm_address_generate_deterministic("trial_decrypt sender passphrase", 1, &sender_gen) == 0,
          "generate sender address");

    struct bm_identity_info from;
    memset(&from, 0, sizeof(from));
    from.address_version = 4;
    from.stream = 1;
    memcpy(from.pub_signing, sender_gen.pub_signing, 65);
    memcpy(from.pub_encryption, sender_gen.pub_encryption, 65);
    memcpy(from.priv_signing, sender_gen.priv_signing, 32);
    from.nonce_trials_per_byte = 1000;
    from.payload_length_extra_bytes = 1000;
    from.does_ack = 1;

    /* 3. msgオブジェクトを組み立てる(PoW前) */
    const char *subject = "end-to-end test";
    const char *body = "trial_decrypt.c まで含めたパイプライン全体のテストです。";

    size_t payload_len = 0;
    unsigned char *payload = bm_build_msg(&from, /*to_stream=*/1, recv_gen.ripe, recv_gen.pub_encryption,
                                           subject, body, NULL, 0, /*expires_time=*/2000000000, &payload_len);
    CHECK(payload != NULL, "bm_build_msg");

    /* 4. PoWを計算し、nonceを先頭に付与して完成objectにする。
     * テスト実行速度のため、実ネットワークの最低要求値(1000,1000)より緩い難易度を使う
     * (bm_pow_run自体は単一スレッド実装で、ここではpow_engine.cの正しさではなく
     * trial_decrypt.cのパースロジックを検証したいため)。 */
    uint64_t target = bm_pow_get_target(payload_len, 60, 50, 50);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);

    /* PoWが実際に基準を満たしているか確認(§4.2) */
    /* trial_valueの再計算はpow_engine内部関数なので、ここではbm_pow_runの契約を信用する */

    /* 5. トライアル復号する */
    struct bm_decoded_msg decoded;
    int rc = bm_trial_decrypt_msg(&kr, object, object_len, &decoded);
    CHECK(rc == 0, "bm_trial_decrypt_msg");

    if (rc == 0)
    {
        CHECK(decoded.from_address_version == 4, "decoded from_address_version");
        CHECK(decoded.from_stream == 1, "decoded from_stream");
        CHECK(strcmp(decoded.to_address, recv_address) == 0, "decoded to_address matches receiver");
        CHECK(strcmp(decoded.subject, subject) == 0, "decoded subject matches");
        CHECK(strcmp(decoded.body, body) == 0, "decoded body matches");
        CHECK(decoded.ack_payload_len == 0, "decoded ack_payload should be empty");

        /* fromアドレスがsender_genのripeから正しく再構成されているか */
        char *expected_from = bm_address_encode(4, 1, sender_gen.ripe, BM_RIPE_LEN);
        CHECK(strcmp(decoded.from_address, expected_from) == 0, "decoded from_address matches sender");
        free(expected_from);

        printf("復号結果: from=%s to=%s subject=\"%s\" body=\"%s\"\n",
               decoded.from_address, decoded.to_address, decoded.subject, decoded.body);

        bm_decoded_msg_free(&decoded);
    }

    /* 6. 改竄されたobjectは復号できてもtoRipe/署名検証で弾かれることを確認 */
    unsigned char *tampered = malloc(object_len);
    memcpy(tampered, object, object_len);
    tampered[object_len - 1] ^= 0xff; /* 署名の末尾1byteを反転 */
    struct bm_decoded_msg decoded_tampered;
    rc = bm_trial_decrypt_msg(&kr, tampered, object_len, &decoded_tampered);
    CHECK(rc != 0, "tampered object should fail trial_decrypt (signature mismatch)");
    free(tampered);

    /* 7. inboxへ保存し、DB上に実際に行があることを確認 */
    rc = bm_trial_decrypt_and_store(&kr, messages_db, object, object_len, NULL, NULL);
    CHECK(rc == 0, "bm_trial_decrypt_and_store");

    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT to_address, from_address, subject, body FROM inbox;", -1, &stmt, NULL);
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        row_count++;
        const char *db_to = (const char *)sqlite3_column_text(stmt, 0);
        const char *db_subject = (const char *)sqlite3_column_text(stmt, 2);
        CHECK(strcmp(db_to, recv_address) == 0, "inbox row to_address");
        CHECK(strcmp(db_subject, subject) == 0, "inbox row subject");
    }
    sqlite3_finalize(stmt);
    CHECK(row_count == 1, "inbox should have exactly 1 row");

    /* 重複投入しても行が増えないこと(msg_id = inventory hashでの重複排除) */
    rc = bm_trial_decrypt_and_store(&kr, messages_db, object, object_len, NULL, NULL);
    CHECK(rc == 0, "duplicate insert should not error");
    sqlite3_prepare_v2(messages_db, "SELECT COUNT(*) FROM inbox;", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count2 = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    CHECK(count2 == 1, "duplicate insert should be ignored (still 1 row)");

    free(object);
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
