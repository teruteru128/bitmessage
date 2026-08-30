/*
 * §11 chan仕様のend-to-endテスト。
 * chanは暗号的には通常のdeterministic addressと全く同じもの: 同じpassphraseから
 * bm_address_generate_deterministicを呼べば誰でも同一のアドレス・鍵ペアを導出できる
 * ("参加"は単なるローカルな鍵導出+is_chanフラグに過ぎない)。
 * 2つの独立したidentity.db/keyring("メンバーA"「メンバーB」)を用意し、
 * 1. 同じpassphraseからのjoinが同一アドレスになること
 * 2. メンバーAがchanアドレス宛(=自分自身宛)にpubkey_cache未登録のままsendMessageできること
 *    (§11のself-send fallbackの検証)
 * 3. メンバーBがその投稿をtrial_decryptで復号できること(共有鍵によるグループチャット動作)
 * 4. §11 2026-08-25: join-chan(=unlock)する「前」に既にobject_pool.dbへ届いていた
 *    chan宛msgオブジェクト(過去ログ)を、unlock後にbm_object_sync_backfill_trial_decrypt
 *    で拾えること(通常の受信フローはobjectを新規受信した瞬間にしかtrial_decryptを試みない
 *    ため、そのままではchan参加前の投稿がinboxに現れない問題への対応)
 * を確認する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/send_pipeline.h"
#include "../src/core/trial_decrypt.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"

#define TEST_IDENTITY_DB_A "test_chan_identity_a.db"
#define TEST_MESSAGES_DB_A "test_chan_messages_a.db"
#define TEST_IDENTITY_DB_B "test_chan_identity_b.db"
#define TEST_MESSAGES_DB_B "test_chan_messages_b.db"
#define TEST_OBJECT_POOL_DB_B "test_chan_object_pool_b.db"

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
    const char *chan_passphrase = "test chan: general discussion";

    /* --- 1. 独立した2回のjoinが同一アドレス・鍵になること --- */
    struct bm_generated_address gen_a;
    CHECK(bm_address_generate_deterministic(chan_passphrase, 1, &gen_a) == 0, "member A derives chan keys");
    struct bm_generated_address gen_b;
    CHECK(bm_address_generate_deterministic(chan_passphrase, 1, &gen_b) == 0, "member B derives chan keys");

    CHECK(memcmp(gen_a.ripe, gen_b.ripe, BM_RIPE_LEN) == 0, "same passphrase -> same ripe");
    CHECK(memcmp(gen_a.pub_signing, gen_b.pub_signing, 65) == 0, "same passphrase -> same signing pubkey");
    CHECK(memcmp(gen_a.pub_encryption, gen_b.pub_encryption, 65) == 0,
          "same passphrase -> same encryption pubkey");
    CHECK(memcmp(gen_a.priv_signing, gen_b.priv_signing, 32) == 0, "same passphrase -> same signing privkey");
    CHECK(memcmp(gen_a.priv_encryption, gen_b.priv_encryption, 32) == 0,
          "same passphrase -> same encryption privkey");

    char *chan_address_a = bm_address_encode(4, 1, gen_a.ripe, BM_RIPE_LEN);
    char *chan_address_b = bm_address_encode(4, 1, gen_b.ripe, BM_RIPE_LEN);
    CHECK(chan_address_a != NULL && chan_address_b != NULL && strcmp(chan_address_a, chan_address_b) == 0,
          "both members join the same chan address");

    /* --- メンバーAをidentity_db_a/keyring_aへ、メンバーBをidentity_db_b/keyring_bへ登録
     * (別プロセス/別クライアントを模す。実際にはjoinChan APIがこのcreate_identity+
     * mark_as_chanをまとめて行う) --- */
    sqlite3 *identity_db_a = open_fresh_db(TEST_IDENTITY_DB_A, bm_identity_store_init_schema);
    sqlite3 *messages_db_a = open_fresh_db(TEST_MESSAGES_DB_A, bm_messages_store_init_schema);
    sqlite3 *identity_db_b = open_fresh_db(TEST_IDENTITY_DB_B, bm_identity_store_init_schema);

    bm_keyring_t kr_a;
    bm_keyring_init(&kr_a);
    bm_keyring_t kr_b;
    bm_keyring_init(&kr_b);

    CHECK(bm_keyring_create_identity(identity_db_a, chan_address_a, "test chan (A)", 4, 1,
                                      gen_a.pub_signing, gen_a.pub_encryption,
                                      gen_a.priv_signing, gen_a.priv_encryption,
                                      "storepass-a", 1000, 1000) == 0,
          "member A joins the chan");
    CHECK(bm_keyring_mark_as_chan(identity_db_a, chan_address_a) == 0, "mark member A's identity as chan");
    CHECK(bm_keyring_unlock(&kr_a, identity_db_a, chan_address_a, "storepass-a") == 0, "unlock member A");

    CHECK(bm_keyring_create_identity(identity_db_b, chan_address_b, "test chan (B)", 4, 1,
                                      gen_b.pub_signing, gen_b.pub_encryption,
                                      gen_b.priv_signing, gen_b.priv_encryption,
                                      "storepass-b", 1000, 1000) == 0,
          "member B joins the chan");
    CHECK(bm_keyring_mark_as_chan(identity_db_b, chan_address_b) == 0, "mark member B's identity as chan");
    CHECK(bm_keyring_unlock(&kr_b, identity_db_b, chan_address_b, "storepass-b") == 0, "unlock member B");

    /* --- 2. is_chanフラグがlistで返ること --- */
    struct bm_identity_summary *list = NULL;
    size_t list_count = 0;
    CHECK(bm_identity_store_list(identity_db_a, &list, &list_count) == 0, "list member A's identities");
    CHECK(list_count == 1 && list[0].is_chan == 1, "member A's chan identity has is_chan=1");
    free(list);

    /* --- 3. メンバーAがchanアドレス宛(自分自身宛)にpubkey_cache未登録のままsendMessage
     * できること(§11のself-send fallback) --- */
    int64_t now = (int64_t)time(NULL);
    unsigned char *object = NULL;
    size_t object_len = 0;
    int rc = bm_send_pipeline_send_message(&kr_a, identity_db_a, messages_db_a, chan_address_a, chan_address_a,
                                            "chan post", "hello, chan!", 3600, 1,
                                            NULL, now + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                            &object, &object_len);
    CHECK(rc == 0, "member A can post to the chan (self-addressed send) without a cached pubkey");

    /* --- 4. メンバーBがtrial_decryptで復号できること(共有鍵によるグループチャット動作) --- */
    if (rc == 0)
    {
        struct bm_decoded_msg decoded;
        int decrypt_rc = bm_trial_decrypt_msg(&kr_b, object, object_len, &decoded);
        CHECK(decrypt_rc == 0, "member B decrypts member A's chan post using the shared chan key");
        if (decrypt_rc == 0)
        {
            CHECK(strcmp(decoded.to_address, chan_address_a) == 0, "decoded.to_address is the chan address");
            CHECK(strcmp(decoded.from_address, chan_address_a) == 0, "decoded.from_address is the chan address");
            CHECK(strcmp(decoded.subject, "chan post") == 0, "decoded subject matches");
            CHECK(strcmp(decoded.body, "hello, chan!") == 0, "decoded body matches");
            bm_decoded_msg_free(&decoded);
        }
    }
    free(object);

    /* --- 5. join-chan(unlock)前に届いていた過去ログのバックフィル --- */
    sqlite3 *messages_db_b = open_fresh_db(TEST_MESSAGES_DB_B, bm_messages_store_init_schema);
    sqlite3 *object_pool_db_b = open_fresh_db(TEST_OBJECT_POOL_DB_B, bm_object_store_init_schema);

    unsigned char *object2 = NULL;
    size_t object2_len = 0;
    int64_t now2 = (int64_t)time(NULL);
    int rc2 = bm_send_pipeline_send_message(&kr_a, identity_db_a, messages_db_a, chan_address_a, chan_address_a,
                                             "before B joined", "backlog message", 3600, 1,
                                             NULL, now2 + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                             &object2, &object2_len);
    CHECK(rc2 == 0, "member A posts a second chan message (backlog, before B joins)");

    if (rc2 == 0)
    {
        /* まだBがchanをunlockしていない間に通常の受信フロー(object_sync.c)がobject_pool.dbへ
         * 保存だけしてtrial_decryptに失敗する状況を再現する(該当鍵がkeyringに無い) */
        unsigned char hash2[32];
        bm_inventory_hash(object2, object2_len, hash2);
        CHECK(bm_object_store_insert(object_pool_db_b, hash2, (int)BM_OBJECT_MSG, 1, object2, object2_len,
                                      now2 + 3600, now2) == 0,
              "backlog object is stored in member B's object_pool.db while B is still locked");

        bm_keyring_t kr_b_late;
        bm_keyring_init(&kr_b_late);
        CHECK(bm_trial_decrypt_and_store(&kr_b_late, messages_db_b, object2, object2_len, NULL, NULL) != 0,
              "sanity: before unlocking, trial_decrypt still fails for member B");

        CHECK(bm_keyring_unlock(&kr_b_late, identity_db_b, chan_address_b, "storepass-b") == 0,
              "member B joins/unlocks the chan identity after the backlog message was received");

        int decrypted = bm_object_sync_backfill_trial_decrypt(object_pool_db_b, messages_db_b, &kr_b_late);
        CHECK(decrypted == 1, "backfill decrypts exactly the 1 backlog message after unlock");

        struct bm_inbox_message *inbox_list = NULL;
        size_t inbox_count = 0;
        CHECK(bm_messages_store_list_inbox(messages_db_b, NULL, &inbox_list, &inbox_count) == 0,
              "list member B's inbox after backfill");
        CHECK(inbox_count == 1 && strcmp(inbox_list[0].subject, "before B joined") == 0
                  && strcmp(inbox_list[0].body, "backlog message") == 0,
              "backfilled message appears in member B's inbox with correct content");
        bm_inbox_message_list_free(inbox_list, inbox_count);

        /* 再実行してもinbox側はmsg_idユニーク制約でIGNOREされ、重複挿入されないこと */
        CHECK(bm_object_sync_backfill_trial_decrypt(object_pool_db_b, messages_db_b, &kr_b_late) == 1,
              "re-running backfill still trial-decrypts successfully (idempotent at this layer)");
        CHECK(bm_messages_store_list_inbox(messages_db_b, NULL, &inbox_list, &inbox_count) == 0
                  && inbox_count == 1,
              "re-running backfill does not duplicate the inbox entry");
        bm_inbox_message_list_free(inbox_list, inbox_count);

        bm_keyring_destroy(&kr_b_late);
    }
    free(object2);

    sqlite3_close(messages_db_b);
    sqlite3_close(object_pool_db_b);
    unlink(TEST_MESSAGES_DB_B);
    unlink(TEST_OBJECT_POOL_DB_B);

    free(chan_address_a);
    free(chan_address_b);
    bm_keyring_destroy(&kr_a);
    bm_keyring_destroy(&kr_b);
    sqlite3_close(identity_db_a);
    sqlite3_close(messages_db_a);
    sqlite3_close(identity_db_b);
    unlink(TEST_IDENTITY_DB_A);
    unlink(TEST_MESSAGES_DB_A);
    unlink(TEST_IDENTITY_DB_B);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
