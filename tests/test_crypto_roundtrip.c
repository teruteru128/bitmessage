/*
 * core/crypto.c の往復テスト(ECIES暗号化/復号、ECDSA署名/検証)。
 * PyBitmessageとのバイト互換テストベクタが手元にないため、ここでは自己往復と
 * 明確な失敗系(改竄検出)のみを検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/address.h"
#include "../src/core/crypto.h"

static int test_ecies_roundtrip(void)
{
    unsigned char priv[BM_PRIVATE_KEY_LEN];
    unsigned char pub[BM_PUBLIC_KEY_LEN];
    bm_address_derive_private_key("test passphrase for ecies", 0, priv);
    if (bm_address_get_public_key(priv, pub) != 0)
    {
        fprintf(stderr, "FAIL: get_public_key\n");
        return 1;
    }

    const char *plaintext = "Hello, Bitmessage! This is a test message for ECIES round-trip.";
    size_t plaintext_len = strlen(plaintext);

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    if (bm_crypto_ecies_encrypt((const unsigned char *)plaintext, plaintext_len, pub,
                                 &ciphertext, &ciphertext_len) != 0)
    {
        fprintf(stderr, "FAIL: ecies_encrypt\n");
        return 1;
    }

    /* IV(16) + pubkeyTLV(70) + ciphertext(16の倍数, PKCS7) + MAC(32) の構造チェック */
    size_t expected_min = 16 + 70 + 16 + 32;
    if (ciphertext_len < expected_min)
    {
        fprintf(stderr, "FAIL: ciphertext too short: %zu\n", ciphertext_len);
        free(ciphertext);
        return 1;
    }

    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    if (bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, priv, &decrypted, &decrypted_len) != 0)
    {
        fprintf(stderr, "FAIL: ecies_decrypt\n");
        free(ciphertext);
        return 1;
    }

    if (decrypted_len != plaintext_len || memcmp(decrypted, plaintext, plaintext_len) != 0)
    {
        fprintf(stderr, "FAIL: decrypted plaintext mismatch\n");
        free(ciphertext);
        free(decrypted);
        return 1;
    }
    free(decrypted);

    /* 改竄検出: MACの最後の1byteを反転させたら復号は失敗しなければならない */
    ciphertext[ciphertext_len - 1] ^= 0xff;
    unsigned char *tampered_out = NULL;
    size_t tampered_len = 0;
    int rc = bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, priv, &tampered_out, &tampered_len);
    free(ciphertext);
    if (rc == 0)
    {
        fprintf(stderr, "FAIL: tampered ciphertext was accepted!\n");
        free(tampered_out);
        return 1;
    }

    /* 他人の秘密鍵では復号できないこと */
    unsigned char wrong_priv[BM_PRIVATE_KEY_LEN];
    bm_address_derive_private_key("a completely different passphrase", 0, wrong_priv);

    unsigned char *ciphertext2 = NULL;
    size_t ciphertext2_len = 0;
    bm_crypto_ecies_encrypt((const unsigned char *)plaintext, plaintext_len, pub, &ciphertext2, &ciphertext2_len);
    unsigned char *wrong_out = NULL;
    size_t wrong_len = 0;
    rc = bm_crypto_ecies_decrypt(ciphertext2, ciphertext2_len, wrong_priv, &wrong_out, &wrong_len);
    free(ciphertext2);
    if (rc == 0)
    {
        fprintf(stderr, "FAIL: decrypted with wrong private key!\n");
        free(wrong_out);
        return 1;
    }

    printf("OK: ECIES round-trip, tamper detection, wrong-key rejection\n");
    return 0;
}

static int test_ecdsa_roundtrip(void)
{
    unsigned char priv[BM_PRIVATE_KEY_LEN];
    unsigned char pub[BM_PUBLIC_KEY_LEN];
    bm_address_derive_private_key("test passphrase for ecdsa", 0, priv);
    if (bm_address_get_public_key(priv, pub) != 0)
    {
        fprintf(stderr, "FAIL: get_public_key\n");
        return 1;
    }

    const char *data = "sign this data please";
    size_t data_len = strlen(data);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (bm_crypto_sign((const unsigned char *)data, data_len, priv, &sig, &sig_len) != 0)
    {
        fprintf(stderr, "FAIL: sign\n");
        return 1;
    }

    if (bm_crypto_verify((const unsigned char *)data, data_len, sig, sig_len, pub) != 1)
    {
        fprintf(stderr, "FAIL: verify legitimate signature\n");
        free(sig);
        return 1;
    }

    /* 改竄されたデータでは検証が失敗すること */
    char tampered[64];
    strncpy(tampered, data, sizeof(tampered) - 1);
    tampered[0] ^= 0x01;
    if (bm_crypto_verify((const unsigned char *)tampered, data_len, sig, sig_len, pub) != 0)
    {
        fprintf(stderr, "FAIL: verify accepted tampered data!\n");
        free(sig);
        return 1;
    }

    /* 他人の公開鍵では検証が失敗すること */
    unsigned char other_priv[BM_PRIVATE_KEY_LEN];
    unsigned char other_pub[BM_PUBLIC_KEY_LEN];
    bm_address_derive_private_key("another identity", 0, other_priv);
    bm_address_get_public_key(other_priv, other_pub);
    if (bm_crypto_verify((const unsigned char *)data, data_len, sig, sig_len, other_pub) != 0)
    {
        fprintf(stderr, "FAIL: verify accepted signature with wrong pubkey!\n");
        free(sig);
        return 1;
    }

    free(sig);
    printf("OK: ECDSA sign/verify round-trip, tamper detection, wrong-key rejection\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_ecies_roundtrip();
    failures += test_ecdsa_roundtrip();
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
