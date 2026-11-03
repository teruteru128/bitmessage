/*
 * §11 2026-11-04 アドレス文字列の固定長バッファをBM_ADDRESS_STR_MAX(64)へ揃えたことのテスト
 * (src/common/address_limits.h)。
 *
 * 背景: identity_store/keyring/messages_store/trial_decrypt/broadcast_decryptの各構造体は
 * アドレスをchar[40]で持っていた。ポスト量子拡張のv5アドレスは53〜54文字
 * (DESIGN-PQ.md §4.3)で収まらず、snprintf/strncpyで黙って途中で切れる。フェーズ2
 * (受信側、DESIGN-PQ.md §9.1)の前提として、DBに入れて読み戻したときに切れないことを
 * 確かめる。v5アドレスそのものを作るとbm_pq(OpenSSL 3.5以降)に依存するので、ここでは
 * 同じ長さのダミー文字列を使う(各ストアはアドレスの中身を検証しない)。
 *
 * 検証観点: 54文字のアドレスが、identity.dbのidentity行・messages.dbのinbox・sent・
 * 再送候補・購読の各経路で、書いて読み戻しても完全に一致すること。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/common/address_limits.h"
#include "../src/core/identity_store.h"
#include "../src/core/messages_store.h"

#define TEST_IDENTITY_DB "test_address_width_identity.db"
#define TEST_MESSAGES_DB "test_address_width_messages.db"

/* "BM-" + 51文字 = 54文字(v5アドレスのnull_bytes=0のときの長さ) */
#define LONG_ADDRESS_A "BM-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define LONG_ADDRESS_B "BM-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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

int main(void)
{
    CHECK(strlen(LONG_ADDRESS_A) == 54, "test address has the v5 length");
    CHECK(strlen(LONG_ADDRESS_A) < BM_ADDRESS_STR_MAX, "v5 length fits in BM_ADDRESS_STR_MAX");

    /* identity.db */
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    struct bm_identity_row row;
    memset(&row, 0, sizeof(row));
    snprintf(row.address, sizeof(row.address), "%s", LONG_ADDRESS_A);
    snprintf(row.label, sizeof(row.label), "%s", "width");
    row.enabled = 1;
    row.address_version = 4;
    row.stream = 1;
    snprintf(row.kdf_algo, sizeof(row.kdf_algo), "%s", "scrypt");
    snprintf(row.kdf_params, sizeof(row.kdf_params), "%s", "{}");
    row.nonce_trials_per_byte = 1000;
    row.payload_length_extra_bytes = 1000;
    CHECK(bm_identity_store_insert(identity_db, &row) == 0, "insert identity with a 54-char address");
    struct bm_identity_row loaded;
    CHECK(bm_identity_store_load(identity_db, LONG_ADDRESS_A, &loaded) == 0, "load identity by the full address");
    CHECK(strcmp(loaded.address, LONG_ADDRESS_A) == 0, "identity address is not truncated");
    struct bm_identity_summary *ids = NULL;
    size_t id_count = 0;
    CHECK(bm_identity_store_list(identity_db, &ids, &id_count) == 0 && id_count == 1, "list identities");
    CHECK(id_count == 1 && strcmp(ids[0].address, LONG_ADDRESS_A) == 0, "listed identity address is not truncated");
    free(ids);
    sqlite3_close(identity_db);
    unlink(TEST_IDENTITY_DB);

    /* messages.db */
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    unsigned char msg_id[32];
    memset(msg_id, 0x11, sizeof(msg_id));
    CHECK(bm_messages_store_insert_inbox(messages_db, msg_id, LONG_ADDRESS_A, LONG_ADDRESS_B, "s", "b", 1000) == 0,
          "insert inbox row");
    struct bm_inbox_message *inbox = NULL;
    size_t inbox_count = 0;
    CHECK(bm_messages_store_list_inbox(messages_db, NULL, &inbox, &inbox_count) == 0 && inbox_count == 1,
          "list inbox");
    CHECK(inbox_count == 1 && strcmp(inbox[0].to_address, LONG_ADDRESS_A) == 0
              && strcmp(inbox[0].from_address, LONG_ADDRESS_B) == 0,
          "inbox addresses are not truncated");
    bm_inbox_message_list_free(inbox, inbox_count);

    unsigned char sent_id[32];
    memset(sent_id, 0x22, sizeof(sent_id));
    static const unsigned char ack[1] = {0};
    CHECK(bm_messages_store_insert_sent(messages_db, sent_id, ack, 1, LONG_ADDRESS_B, LONG_ADDRESS_A, "s", "b",
                                        "sent", 1, 1000, 300, 2000)
              == 0,
          "insert sent row");
    struct bm_sent_message *sent = NULL;
    size_t sent_count = 0;
    CHECK(bm_messages_store_list_sent(messages_db, &sent, &sent_count) == 0 && sent_count == 1, "list sent");
    CHECK(sent_count == 1 && strcmp(sent[0].to_address, LONG_ADDRESS_B) == 0
              && strcmp(sent[0].from_address, LONG_ADDRESS_A) == 0,
          "sent addresses are not truncated");
    bm_sent_message_list_free(sent, sent_count);

    struct bm_sent_resend_candidate *cands = NULL;
    size_t cand_count = 0;
    CHECK(bm_messages_store_list_resend_candidates(messages_db, 3000, 5, &cands, &cand_count) == 0
              && cand_count == 1,
          "list resend candidates");
    CHECK(cand_count == 1 && strcmp(cands[0].to_address, LONG_ADDRESS_B) == 0
              && strcmp(cands[0].from_address, LONG_ADDRESS_A) == 0,
          "resend candidate addresses are not truncated");
    bm_sent_resend_candidate_list_free(cands, cand_count);

    CHECK(bm_messages_store_add_subscription(messages_db, LONG_ADDRESS_B, "sub") == 0, "add subscription");
    struct bm_subscription *subs = NULL;
    size_t sub_count = 0;
    CHECK(bm_messages_store_list_subscriptions(messages_db, &subs, &sub_count) == 0 && sub_count == 1,
          "list subscriptions");
    CHECK(sub_count == 1 && strcmp(subs[0].address, LONG_ADDRESS_B) == 0, "subscription address is not truncated");
    bm_subscription_list_free(subs);

    sqlite3_close(messages_db);
    unlink(TEST_MESSAGES_DB);

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_address_width: all checks passed\n");
    return EXIT_SUCCESS;
}
