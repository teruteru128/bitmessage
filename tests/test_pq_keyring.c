/*
 * §11 2026-11-04 項目55の段3: v5(ポスト量子)identityのidentity.dbへの保存
 * (core/pq_identity_store.c)とkeyring(core/pq_keyring.c)のテスト。DESIGN-PQ.md §9.3。
 *
 * 背景: v5の秘密鍵は展開済みの鍵ブロブ(6.5KB)ではなく成分seed(160byte)だけを、v4以前と
 * 同じKEK(行ごとのscrypt、AES-256-GCM、AAD=アドレス)でラップして保存する。公開鍵は平文で
 * 保存し、unlock時にアドレスのidと照合する。展開済みの秘密鍵は初めて使うときに作る。
 *
 * 検証観点:
 * 1. 作成した行が読み戻せ、v5の一覧に出ること(v4以前の一覧には混ざらないこと)
 * 2. 誤ったpassphraseではunlockできず、正しいpassphraseでunlockでき、アドレス・tagで
 *    引けること。tagはbm_pqv5_derive_secret_and_tagの後半と一致すること
 * 3. 同じアドレスを2回unlockしても1件のままであること
 * 4. 遅延展開した秘密鍵が、生成時のidentityの秘密鍵と完全に一致すること(2回目はキャッシュ)
 * 5. bm_keyring_lock(v4以前と共通の入口)でv5もlockでき、lock後は秘密鍵を取れないこと。
 *    bm_keyring_lock_allでも外れること
 * 6. 改竄の検出: 平文の公開鍵の書き換え、ラップ済みseedの書き換えはunlockで弾かれること。
 *    seedと公開鍵が別々のidentityのもの(行の中身はidと整合しGCMも通る)だと、展開の時点で
 *    公開鍵の不一致として弾かれ、アドレスと違う鍵が使われないこと
 */

#define _GNU_SOURCE /* memmem */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/pq_identity_store.h"
#include "../src/core/pq_keyring.h"
#include "../src/pq/address_v5.h"

#define TEST_IDENTITY_DB "test_pq_keyring_identity.db"
#define PASS "pq keyring pass"

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

static size_t count_pq_unlocked(bm_keyring_t *kr)
{
    size_t n = 0;
    pthread_rwlock_rdlock(&kr->lock);
    for (struct bm_unlocked_pq_identity *cur = kr->pq_head; cur != NULL; cur = cur->next)
    {
        n++;
    }
    pthread_rwlock_unlock(&kr->lock);
    return n;
}

/* identity.dbのv5の行のBLOB列(sig_pkかwrapped_seeds)の中ほどの1bitを反転させる */
static void flip_middle_bit(sqlite3 *db, const char *address, const char *column)
{
    char sql[256];
    struct bm_pq_identity_row *row = malloc(sizeof(*row));
    if (bm_pq_identity_store_load(db, address, row) != 0)
    {
        free(row);
        return;
    }
    unsigned char *blob = NULL;
    size_t len = 0;
    if (strcmp(column, "sig_pk") == 0)
    {
        blob = row->sig_pk;
        len = BM_PQV5_SIG_PK_LEN;
    }
    else
    {
        blob = row->wrapped_seeds;
        len = BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN;
    }
    blob[len / 2] ^= 0x01; /* nonceやタグではなく本体の中ほどを書き換える */
    snprintf(sql, sizeof(sql), "UPDATE pq_identities SET %s = ?1 WHERE address = ?2;", column);
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, blob, (int)len, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, address, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(row);
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

    static struct bm_pqv5_identity gen;
    CHECK(bm_pqv5_identity_generate_deterministic("pq keyring test", 1, 0, BM_PQV5_DEFAULT_NULL_BYTES, &gen) == 0,
          "generate v5 identity");

    /* 1. 作成と一覧 */
    char address[BM_KEYRING_MAX_ADDRESS_LEN];
    CHECK(bm_pq_keyring_create_identity(db, &gen, "pq label", PASS, 1000, 1000, 1700000000, address) == 0,
          "create v5 identity");
    CHECK(strncmp(address, "BM-", 3) == 0 && strlen(address) == 53, "created address is a 53-char v5 address");
    CHECK(bm_pq_keyring_create_identity(db, &gen, "dup", PASS, 1000, 1000, 1700000000, NULL) != 0,
          "creating the same address twice fails");

    struct bm_pq_identity_row *row = malloc(sizeof(*row));
    CHECK(bm_pq_identity_store_load(db, address, row) == 0, "load the stored row");
    CHECK(strcmp(row->label, "pq label") == 0 && row->address_version == 5 && row->stream == 1
              && strcmp(row->kdf_algo, "scrypt") == 0 && row->created_time == 1700000000,
          "stored row fields");
    CHECK(memcmp(row->id, gen.id, BM_PQV5_ID_LEN) == 0 && memcmp(row->sig_pk, gen.sig_pk, BM_PQV5_SIG_PK_LEN) == 0
              && memcmp(row->kem_pk, gen.kem_pk, BM_PQV5_KEM_PK_LEN) == 0,
          "stored public keys and id");
    CHECK(memmem(row->wrapped_seeds, BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN, gen.seeds.mldsa_xi, 32) == NULL,
          "seeds are not stored in plaintext");
    free(row);

    struct bm_identity_summary *list = NULL;
    size_t count = 0;
    CHECK(bm_pq_identity_store_list(db, &list, &count) == 0 && count == 1 && strcmp(list[0].address, address) == 0,
          "v5 identity is listed");
    free(list);
    CHECK(bm_identity_store_list(db, &list, &count) == 0 && count == 0, "v5 identity is not in the v4 list");
    free(list);

    /* 2. unlockと検索 */
    CHECK(bm_pq_keyring_unlock(&kr, db, address, "wrong pass", 1700000100) != 0, "wrong passphrase is rejected");
    CHECK(!bm_pq_keyring_find_by_address(&kr, address, NULL), "not unlocked after a wrong passphrase");
    CHECK(bm_pq_keyring_unlock(&kr, db, address, PASS, 1700000100) == 0, "unlock with the right passphrase");
    static struct bm_pq_identity_public pub;
    CHECK(bm_pq_keyring_find_by_address(&kr, address, &pub), "find by address");
    CHECK(memcmp(pub.sig_pk, gen.sig_pk, BM_PQV5_SIG_PK_LEN) == 0 && pub.address_version == 5,
          "found public info matches");
    unsigned char tag[32];
    bm_pqv5_derive_secret_and_tag(5, 1, gen.id, NULL, tag);
    CHECK(memcmp(pub.tag, tag, 32) == 0, "tag matches derive_secret_and_tag");
    CHECK(bm_pq_keyring_find_by_tag(&kr, tag, NULL), "find by tag");
    unsigned char other_tag[32];
    memset(other_tag, 0x5a, sizeof(other_tag));
    CHECK(!bm_pq_keyring_find_by_tag(&kr, other_tag, NULL), "unknown tag is not found");

    /* 3. 2回目のunlockで増えない */
    CHECK(bm_pq_keyring_unlock(&kr, db, address, PASS, 1700000200) == 0, "second unlock succeeds");
    CHECK(count_pq_unlocked(&kr) == 1, "second unlock does not duplicate the entry");

    /* 4. 遅延展開 */
    static unsigned char sig_sk[BM_PQV5_SIG_SK_LEN];
    static unsigned char kem_sk[BM_PQV5_KEM_SK_LEN];
    CHECK(bm_pq_keyring_get_secret_keys(&kr, address, sig_sk, kem_sk) == 0, "expand secret keys");
    CHECK(memcmp(sig_sk, gen.sig_sk, sizeof(sig_sk)) == 0 && memcmp(kem_sk, gen.kem_sk, sizeof(kem_sk)) == 0,
          "expanded secret keys match the generated identity");
    memset(sig_sk, 0, sizeof(sig_sk));
    CHECK(bm_pq_keyring_get_secret_keys(&kr, address, sig_sk, NULL) == 0
              && memcmp(sig_sk, gen.sig_sk, sizeof(sig_sk)) == 0,
          "cached secret keys are returned on the second call");

    /* 5. lock */
    CHECK(bm_keyring_lock(&kr, address) == 0, "bm_keyring_lock also locks a v5 identity");
    CHECK(!bm_pq_keyring_find_by_address(&kr, address, NULL), "not found after lock");
    CHECK(bm_pq_keyring_get_secret_keys(&kr, address, sig_sk, kem_sk) != 0, "no secret keys after lock");
    CHECK(bm_pq_keyring_unlock(&kr, db, address, PASS, 1700000300) == 0, "unlock again");
    bm_keyring_lock_all(&kr);
    CHECK(count_pq_unlocked(&kr) == 0, "bm_keyring_lock_all also clears v5 identities");

    /* 6. 改竄の検出 */
    static struct bm_pqv5_identity gen2;
    CHECK(bm_pqv5_identity_generate_deterministic("pq keyring test 2", 1, 0, BM_PQV5_DEFAULT_NULL_BYTES, &gen2) == 0,
          "generate second identity");
    char address2[BM_KEYRING_MAX_ADDRESS_LEN];
    CHECK(bm_pq_keyring_create_identity(db, &gen2, "t", PASS, 1000, 1000, 1700000000, address2) == 0,
          "create second identity");
    flip_middle_bit(db, address2, "sig_pk");
    CHECK(bm_pq_keyring_unlock(&kr, db, address2, PASS, 1700000400) != 0,
          "a tampered plaintext public key is rejected at unlock");

    static struct bm_pqv5_identity gen3;
    CHECK(bm_pqv5_identity_generate_deterministic("pq keyring test 3", 1, 0, BM_PQV5_DEFAULT_NULL_BYTES, &gen3) == 0,
          "generate third identity");
    char address3[BM_KEYRING_MAX_ADDRESS_LEN];
    CHECK(bm_pq_keyring_create_identity(db, &gen3, "t", PASS, 1000, 1000, 1700000000, address3) == 0,
          "create third identity");
    flip_middle_bit(db, address3, "wrapped_seeds");
    CHECK(bm_pq_keyring_unlock(&kr, db, address3, PASS, 1700000400) != 0, "tampered wrapped seeds are rejected");

    /* seedはgen4、公開鍵とidはgen5という行(行の中身は整合し、GCMも通る) */
    static struct bm_pqv5_identity gen4, gen5, mixed;
    CHECK(bm_pqv5_identity_generate_deterministic("pq keyring test 4", 1, 0, BM_PQV5_DEFAULT_NULL_BYTES, &gen4) == 0
              && bm_pqv5_identity_generate_deterministic("pq keyring test 5", 1, 0, BM_PQV5_DEFAULT_NULL_BYTES,
                                                         &gen5)
                     == 0,
          "generate identities for the mixed row");
    mixed = gen5;
    mixed.seeds = gen4.seeds;
    char address_mixed[BM_KEYRING_MAX_ADDRESS_LEN];
    CHECK(bm_pq_keyring_create_identity(db, &mixed, "mixed", PASS, 1000, 1000, 1700000000, address_mixed) == 0,
          "create the mixed row");
    CHECK(bm_pq_keyring_unlock(&kr, db, address_mixed, PASS, 1700000500) == 0,
          "the mixed row unlocks (its own contents are consistent)");
    CHECK(bm_pq_keyring_get_secret_keys(&kr, address_mixed, sig_sk, kem_sk) != 0,
          "keys expanded from mismatching seeds are rejected");

    bm_keyring_destroy(&kr);
    sqlite3_close(db);
    unlink(TEST_IDENTITY_DB);

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_pq_keyring: all checks passed\n");
    return EXIT_SUCCESS;
}
