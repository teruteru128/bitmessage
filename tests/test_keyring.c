/*
 * core/keyring.c + core/identity_store.c の統合テスト。
 * §7: create_identity(KEKラップして保存) -> unlock(復号してkeyringへ) -> lock -> delete の一連を検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"

#define TEST_DB_PATH "test_keyring_identity.db"

static sqlite3 *open_fresh_db(void)
{
    unlink(TEST_DB_PATH);
    sqlite3 *db = NULL;
    if (sqlite3_open(TEST_DB_PATH, &db) != SQLITE_OK)
    {
        fprintf(stderr, "FAIL: sqlite3_open\n");
        exit(EXIT_FAILURE);
    }
    if (bm_identity_store_init_schema(db) != 0)
    {
        fprintf(stderr, "FAIL: init_schema\n");
        exit(EXIT_FAILURE);
    }
    return db;
}

int main(void)
{
    sqlite3 *db = open_fresh_db();

    struct bm_generated_address gen;
    if (bm_address_generate_deterministic("keyring test passphrase", 1, &gen) != 0)
    {
        fprintf(stderr, "FAIL: generate_deterministic\n");
        return EXIT_FAILURE;
    }
    char *address = bm_address_encode(4, 1, gen.ripe, BM_RIPE_LEN);
    if (address == NULL)
    {
        fprintf(stderr, "FAIL: address_encode\n");
        return EXIT_FAILURE;
    }
    printf("生成したアドレス: %s\n", address);

    const char *store_passphrase = "super secret storage passphrase";

    if (bm_keyring_create_identity(db, address, "test identity", 4, 1,
                                    gen.pub_signing, gen.pub_encryption,
                                    gen.priv_signing, gen.priv_encryption,
                                    store_passphrase, 1000, 1000) != 0)
    {
        fprintf(stderr, "FAIL: create_identity\n");
        return EXIT_FAILURE;
    }
    printf("OK: identity.dbへKEKラップして保存\n");

    /* 誤ったpassphraseではunlockできないこと */
    bm_keyring_t kr;
    bm_keyring_init(&kr);
    if (bm_keyring_unlock(&kr, db, address, "wrong passphrase") == 0)
    {
        fprintf(stderr, "FAIL: unlock succeeded with wrong passphrase!\n");
        return EXIT_FAILURE;
    }
    printf("OK: 誤ったpassphraseでのunlockを拒否\n");

    /* 正しいpassphraseでunlockでき、平文鍵が生成時と一致すること */
    if (bm_keyring_unlock(&kr, db, address, store_passphrase) != 0)
    {
        fprintf(stderr, "FAIL: unlock with correct passphrase\n");
        return EXIT_FAILURE;
    }

    struct bm_unlocked_identity found;
    if (!bm_keyring_find_by_ripe(&kr, gen.ripe, &found))
    {
        fprintf(stderr, "FAIL: find_by_ripe after unlock\n");
        return EXIT_FAILURE;
    }
    if (memcmp(found.priv_signing, gen.priv_signing, BM_PRIVATE_KEY_LEN) != 0
        || memcmp(found.priv_encryption, gen.priv_encryption, BM_PRIVATE_KEY_LEN) != 0)
    {
        fprintf(stderr, "FAIL: unwrapped private keys do not match originals\n");
        return EXIT_FAILURE;
    }
    printf("OK: unlock後の秘密鍵が生成時のものと一致\n");

    /* lockするとkeyringから消えること */
    if (bm_keyring_lock(&kr, address) != 0)
    {
        fprintf(stderr, "FAIL: lock\n");
        return EXIT_FAILURE;
    }
    if (bm_keyring_find_by_ripe(&kr, gen.ripe, &found))
    {
        fprintf(stderr, "FAIL: identity still found after lock!\n");
        return EXIT_FAILURE;
    }
    printf("OK: lock後はkeyringから見つからない\n");

    /* lock後もidentity.db上のデータは残っており、再unlockできること */
    if (bm_keyring_unlock(&kr, db, address, store_passphrase) != 0)
    {
        fprintf(stderr, "FAIL: re-unlock after lock\n");
        return EXIT_FAILURE;
    }
    printf("OK: lock後も再unlock可能(ディスク上のデータは保持される)\n");

    /* deleteすると完全に消え、再unlockできなくなること */
    if (bm_keyring_delete_identity(&kr, db, address) != 0)
    {
        fprintf(stderr, "FAIL: delete_identity\n");
        return EXIT_FAILURE;
    }
    if (bm_keyring_find_by_ripe(&kr, gen.ripe, &found))
    {
        fprintf(stderr, "FAIL: identity still in keyring after delete!\n");
        return EXIT_FAILURE;
    }
    if (bm_keyring_unlock(&kr, db, address, store_passphrase) == 0)
    {
        fprintf(stderr, "FAIL: unlock succeeded after delete!\n");
        return EXIT_FAILURE;
    }
    printf("OK: delete後は完全に消え、再unlockもできない\n");

    bm_keyring_destroy(&kr);
    free(address);

    /* §11 2026-08-29 一括unlock(bm_keyring_unlock_all)の検証。DESIGN.md §11-19。
     * 3件のidentityのうち2件を共通passphrase、1件を別passphraseで保存し、
     * 「一致しない行は黙ってスキップ、他は中断しない」ことと「既にunlock済みの行は
     * 再試行せず維持される」ことを確認する。 */
    {
        const char *common_passphrase = "bulk unlock common passphrase";
        const char *other_passphrase = "different passphrase for one address";
        const char *seeds[3] = {"bulk seed 1", "bulk seed 2", "bulk seed 3"};
        char *addrs[3];
        struct bm_generated_address gens[3];

        for (int i = 0; i < 3; i++)
        {
            if (bm_address_generate_deterministic(seeds[i], 1, &gens[i]) != 0)
            {
                fprintf(stderr, "FAIL: bulk generate_deterministic[%d]\n", i);
                return EXIT_FAILURE;
            }
            addrs[i] = bm_address_encode(4, 1, gens[i].ripe, BM_RIPE_LEN);
            if (addrs[i] == NULL)
            {
                fprintf(stderr, "FAIL: bulk address_encode[%d]\n", i);
                return EXIT_FAILURE;
            }
            const char *pass = (i == 2) ? other_passphrase : common_passphrase;
            if (bm_keyring_create_identity(db, addrs[i], "bulk test", 4, 1,
                                            gens[i].pub_signing, gens[i].pub_encryption,
                                            gens[i].priv_signing, gens[i].priv_encryption,
                                            pass, 1000, 1000) != 0)
            {
                fprintf(stderr, "FAIL: bulk create_identity[%d]\n", i);
                return EXIT_FAILURE;
            }
        }

        bm_keyring_t kr2;
        bm_keyring_init(&kr2);

        struct bm_unlock_all_entry *results = NULL;
        size_t count = 0;
        if (bm_keyring_unlock_all(&kr2, db, common_passphrase, &results, &count) != 0 || count != 3)
        {
            fprintf(stderr, "FAIL: unlock_all (first pass), count=%zu\n", count);
            return EXIT_FAILURE;
        }
        int matched_common = 0;
        int matched_other = 0;
        for (size_t i = 0; i < count; i++)
        {
            int expect_unlocked = (strcmp(results[i].address, addrs[2]) != 0) ? 1 : 0;
            if (results[i].unlocked != expect_unlocked)
            {
                fprintf(stderr, "FAIL: unlock_all result mismatch for %s (got %d, want %d)\n",
                        results[i].address, results[i].unlocked, expect_unlocked);
                return EXIT_FAILURE;
            }
            if (expect_unlocked)
            {
                matched_common++;
            }
            else
            {
                matched_other++;
            }
        }
        if (matched_common != 2 || matched_other != 1)
        {
            fprintf(stderr, "FAIL: unexpected unlock counts (common=%d other=%d)\n", matched_common, matched_other);
            return EXIT_FAILURE;
        }
        free(results);
        printf("OK: unlockAllで不一致のpassphraseの行だけ黙ってスキップされる\n");

        /* §7.4 lazy migrationの検証: common_passphraseで復号成功したaddrs[0]/addrs[1]は
         * その場でvault-hkdf方式へre-wrapされているはず。addrs[2]はまだ復号されていない
         * ので旧方式(scrypt)のまま */
        struct bm_identity_row row_check;
        if (bm_identity_store_load(db, addrs[0], &row_check) != 0
            || strcmp(row_check.kdf_algo, "vault-hkdf") != 0)
        {
            fprintf(stderr, "FAIL: addrs[0] not re-wrapped to vault-hkdf after first unlock_all\n");
            return EXIT_FAILURE;
        }
        if (bm_identity_store_load(db, addrs[2], &row_check) != 0
            || strcmp(row_check.kdf_algo, "scrypt") != 0)
        {
            fprintf(stderr, "FAIL: addrs[2] unexpectedly changed kdf_algo before being unlocked\n");
            return EXIT_FAILURE;
        }
        printf("OK: 復号成功した行はその場でvault-hkdf方式へre-wrapされる\n");

        /*
         * §7.4 2026-08-29のcanary保護の検証(最重要): この時点でvaultはcommon_passphrase由来で
         * 既に作成済み。other_passphraseはvaultのpassphraseとは異なるため、canary検証により
         * master KEKは「導出できない」として扱われるべき。もしcanary保護が無ければ、scryptは
         * 誤ったpassphraseでも必ず何らかの32byte値を返すため、addrs[2](other_passphraseで
         * 復号成功する)が誤ったmaster KEKでre-wrapされ、vault全体が壊れてしまう
         * (以後正しいcommon_passphraseでもaddrs[2]が復号不能になる)。
         * 正しく保護されていれば、addrs[2]はunlock自体は成功するがre-wrapはされず、
         * kdf_algoは'scrypt'のまま残るはず。
         */
        struct bm_unlock_all_entry *results2 = NULL;
        size_t count2 = 0;
        if (bm_keyring_unlock_all(&kr2, db, other_passphrase, &results2, &count2) != 0)
        {
            fprintf(stderr, "FAIL: unlock_all (second pass)\n");
            return EXIT_FAILURE;
        }
        for (size_t i = 0; i < count2; i++)
        {
            if (!results2[i].unlocked)
            {
                fprintf(stderr, "FAIL: %s not unlocked after second pass\n", results2[i].address);
                return EXIT_FAILURE;
            }
        }
        free(results2);
        printf("OK: 既存unlock済みの行を維持したまま異なるpassphraseの行を追加unlock可能\n");

        if (bm_identity_store_load(db, addrs[2], &row_check) != 0
            || strcmp(row_check.kdf_algo, "scrypt") != 0)
        {
            fprintf(stderr, "FAIL: addrs[2] was re-wrapped using the wrong master KEK "
                            "(vault canary protection did not work!)\n");
            return EXIT_FAILURE;
        }
        printf("OK: vault canary保護により、異なるpassphraseでの誤ったre-wrapは発生しない\n");

        /* keyringをリセットし、正しいcommon_passphraseで3回目のunlockAllを行う。
         * addrs[0]/addrs[1]は既にvault-hkdf化されているので、今度はHKDF経由(高速パス)で
         * 復号されるはず。平文鍵が生成時のものと一致することも確認する */
        bm_keyring_destroy(&kr2);
        bm_keyring_init(&kr2);

        struct bm_unlock_all_entry *results3 = NULL;
        size_t count3 = 0;
        if (bm_keyring_unlock_all(&kr2, db, common_passphrase, &results3, &count3) != 0)
        {
            fprintf(stderr, "FAIL: unlock_all (third pass, via vault-hkdf)\n");
            return EXIT_FAILURE;
        }
        /* addrs[2]はother_passphrase保存のままなので、common_passphraseでは復号されない
         * のが正しい(§7.4のcanary保護によりaddrs[2]はvault化されずscryptのまま残っている)。
         * ここではaddrs[0]/addrs[1](vault-hkdf化済み)がunlockedであることだけ確認する */
        for (size_t i = 0; i < count3; i++)
        {
            int is_addrs2 = (strcmp(results3[i].address, addrs[2]) == 0);
            if (!is_addrs2 && !results3[i].unlocked)
            {
                fprintf(stderr, "FAIL: %s not unlocked on third pass (vault-hkdf)\n", results3[i].address);
                free(results3);
                return EXIT_FAILURE;
            }
        }
        free(results3);
        for (int i = 0; i < 2; i++)
        {
            struct bm_unlocked_identity found_bulk;
            if (!bm_keyring_find_by_ripe(&kr2, gens[i].ripe, &found_bulk))
            {
                fprintf(stderr, "FAIL: addrs[%d] not found in keyring after vault-hkdf unlock\n", i);
                return EXIT_FAILURE;
            }
            if (memcmp(found_bulk.priv_signing, gens[i].priv_signing, BM_PRIVATE_KEY_LEN) != 0
                || memcmp(found_bulk.priv_encryption, gens[i].priv_encryption, BM_PRIVATE_KEY_LEN) != 0)
            {
                fprintf(stderr, "FAIL: vault-hkdf-unwrapped private keys do not match originals for addrs[%d]\n", i);
                return EXIT_FAILURE;
            }
        }
        printf("OK: vault-hkdf経由で復号した秘密鍵も生成時のものと一致する\n");

        bm_keyring_destroy(&kr2);
        for (int i = 0; i < 3; i++)
        {
            free(addrs[i]);
        }
    }

    sqlite3_close(db);
    unlink(TEST_DB_PATH);

    printf("ALL OK\n");
    return EXIT_SUCCESS;
}
