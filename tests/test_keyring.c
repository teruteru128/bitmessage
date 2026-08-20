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
    sqlite3_close(db);
    unlink(TEST_DB_PATH);

    printf("ALL OK\n");
    return EXIT_SUCCESS;
}
