#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../common/hash.h"
#include "address.h"

#define ECIES_IV_LEN 16
#define ECIES_PUBKEY_TLV_LEN 70
#define ECIES_MAC_LEN 32
/* pyelliptic(OpenSSL) の secp256k1 curve NID。§3.1: 一時公開鍵のTLVエンコードで固定値として使う */
#define SECP256K1_CURVE_ID 714

/* --- 内部ヘルパー: priv * pub のECDH共有シークレット(X座標32byte)。§3.1 --- */
static int ecdh_shared_secret(const unsigned char priv[32], const unsigned char pub[65],
                               unsigned char out_secret[32])
{
    int ret = -1;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        return -1;
    }
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *priv_bn = BN_CTX_get(ctx);
    BIGNUM *x = BN_CTX_get(ctx);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT *shared = EC_POINT_new(group);

    if (priv_bn != NULL && x != NULL && pub_point != NULL && shared != NULL
        && BN_bin2bn(priv, 32, priv_bn) != NULL
        && EC_POINT_oct2point(group, pub_point, pub, 65, ctx) == 1
        && EC_POINT_mul(group, shared, NULL, pub_point, priv_bn, ctx) == 1
        && EC_POINT_get_affine_coordinates(group, shared, x, NULL, ctx) == 1
        && BN_bn2binpad(x, out_secret, 32) == 32)
    {
        ret = 0;
    }

    if (shared != NULL)
    {
        EC_POINT_free(shared);
    }
    if (pub_point != NULL)
    {
        EC_POINT_free(pub_point);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return ret;
}

/* pub(65byte, 0x04||X||Y) -> curve_id(2BE)||len_x(2BE)=32||X(32)||len_y(2BE)=32||Y(32) */
static void encode_pubkey_tlv(const unsigned char pub[65], unsigned char out[ECIES_PUBKEY_TLV_LEN])
{
    out[0] = (SECP256K1_CURVE_ID >> 8) & 0xff;
    out[1] = SECP256K1_CURVE_ID & 0xff;
    out[2] = 0x00;
    out[3] = 0x20;
    memcpy(out + 4, pub + 1, 32);
    out[36] = 0x00;
    out[37] = 0x20;
    memcpy(out + 38, pub + 33, 32);
}

static int decode_pubkey_tlv(const unsigned char tlv[ECIES_PUBKEY_TLV_LEN], unsigned char out_pub[65])
{
    uint16_t curve_id = ((uint16_t)tlv[0] << 8) | tlv[1];
    uint16_t len_x = ((uint16_t)tlv[2] << 8) | tlv[3];
    uint16_t len_y = ((uint16_t)tlv[36] << 8) | tlv[37];
    if (curve_id != SECP256K1_CURVE_ID || len_x != 32 || len_y != 32)
    {
        return -1;
    }
    out_pub[0] = 0x04;
    memcpy(out_pub + 1, tlv + 4, 32);
    memcpy(out_pub + 33, tlv + 38, 32);
    return 0;
}

static int aes256cbc_encrypt(const unsigned char key[32], const unsigned char iv[ECIES_IV_LEN],
                              const unsigned char *plaintext, size_t plaintext_len,
                              unsigned char **out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }
    int ret = -1;
    unsigned char *buf = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0;
    int len2 = 0;
    if (buf != NULL
        && EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1
        && EVP_EncryptUpdate(ctx, buf, &len1, plaintext, (int)plaintext_len) == 1
        && EVP_EncryptFinal_ex(ctx, buf + len1, &len2) == 1)
    {
        *out = buf;
        *out_len = (size_t)(len1 + len2);
        ret = 0;
    }
    else
    {
        free(buf);
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int aes256cbc_decrypt(const unsigned char key[32], const unsigned char iv[ECIES_IV_LEN],
                              const unsigned char *ciphertext, size_t ciphertext_len,
                              unsigned char **out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }
    int ret = -1;
    unsigned char *buf = malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0;
    int len2 = 0;
    if (buf != NULL
        && EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1
        && EVP_DecryptUpdate(ctx, buf, &len1, ciphertext, (int)ciphertext_len) == 1
        && EVP_DecryptFinal_ex(ctx, buf + len1, &len2) == 1)
    {
        *out = buf;
        *out_len = (size_t)(len1 + len2);
        ret = 0;
    }
    else
    {
        free(buf);
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int bm_crypto_ecies_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                             const unsigned char recipient_pub[65],
                             unsigned char **out, size_t *out_len)
{
    unsigned char eph_priv[32];
    unsigned char eph_pub[65];
    if (RAND_bytes(eph_priv, sizeof(eph_priv)) != 1
        || bm_address_get_public_key(eph_priv, eph_pub) != 0)
    {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return -1;
    }

    unsigned char shared[32];
    if (ecdh_shared_secret(eph_priv, recipient_pub, shared) != 0)
    {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return -1;
    }

    unsigned char k[64];
    bm_sha512(shared, sizeof(shared), k);
    OPENSSL_cleanse(shared, sizeof(shared));
    const unsigned char *key_e = k;
    const unsigned char *key_m = k + 32;

    unsigned char iv[ECIES_IV_LEN];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
    {
        OPENSSL_cleanse(k, sizeof(k));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return -1;
    }

    unsigned char pub_tlv[ECIES_PUBKEY_TLV_LEN];
    encode_pubkey_tlv(eph_pub, pub_tlv);

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    if (aes256cbc_encrypt(key_e, iv, plaintext, plaintext_len, &ciphertext, &ciphertext_len) != 0)
    {
        OPENSSL_cleanse(k, sizeof(k));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return -1;
    }

    size_t prefix_len = ECIES_IV_LEN + ECIES_PUBKEY_TLV_LEN;
    size_t total = prefix_len + ciphertext_len + ECIES_MAC_LEN;
    unsigned char *output = malloc(total);
    memcpy(output, iv, ECIES_IV_LEN);
    memcpy(output + ECIES_IV_LEN, pub_tlv, ECIES_PUBKEY_TLV_LEN);
    memcpy(output + prefix_len, ciphertext, ciphertext_len);
    free(ciphertext);

    unsigned char mac[ECIES_MAC_LEN];
    bm_hmac_sha256(key_m, 32, output, prefix_len + ciphertext_len, mac);
    memcpy(output + prefix_len + ciphertext_len, mac, ECIES_MAC_LEN);

    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));

    *out = output;
    *out_len = total;
    return 0;
}

int bm_crypto_ecies_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                             const unsigned char priv[32],
                             unsigned char **out, size_t *out_len)
{
    size_t prefix_len = ECIES_IV_LEN + ECIES_PUBKEY_TLV_LEN;
    if (ciphertext_len < prefix_len + ECIES_MAC_LEN)
    {
        return -1;
    }

    const unsigned char *iv = ciphertext;
    const unsigned char *pub_tlv = ciphertext + ECIES_IV_LEN;
    const unsigned char *enc_body = ciphertext + prefix_len;
    size_t enc_body_len = ciphertext_len - prefix_len - ECIES_MAC_LEN;
    const unsigned char *mac = ciphertext + ciphertext_len - ECIES_MAC_LEN;

    unsigned char eph_pub[65];
    if (decode_pubkey_tlv(pub_tlv, eph_pub) != 0)
    {
        return -1;
    }

    unsigned char shared[32];
    if (ecdh_shared_secret(priv, eph_pub, shared) != 0)
    {
        return -1;
    }

    unsigned char k[64];
    bm_sha512(shared, sizeof(shared), k);
    OPENSSL_cleanse(shared, sizeof(shared));
    const unsigned char *key_e = k;
    const unsigned char *key_m = k + 32;

    unsigned char computed_mac[ECIES_MAC_LEN];
    bm_hmac_sha256(key_m, 32, ciphertext, ciphertext_len - ECIES_MAC_LEN, computed_mac);

    /* 定数時間比較(§3.1: MAC検証を先に行い、失敗ならAES復号しない) */
    unsigned char diff = 0;
    for (int i = 0; i < ECIES_MAC_LEN; i++)
    {
        diff |= (unsigned char)(computed_mac[i] ^ mac[i]);
    }
    if (diff != 0)
    {
        OPENSSL_cleanse(k, sizeof(k));
        return -1;
    }

    int ret = aes256cbc_decrypt(key_e, iv, enc_body, enc_body_len, out, out_len);
    OPENSSL_cleanse(k, sizeof(k));
    return ret;
}

/*
 * EC_KEY/ECDSA_sign/ECDSA_verify系はOpenSSL 3.0で非推奨(EVP_PKEY+OSSL_PARAM経由が推奨)だが、
 * 生成される署名はビット単位で同一かつAPI自体は当面removeされない見込みのため、
 * OSSL_PARAM_BLDによる書き換えコストに見合わないと判断しあえてこのまま使う。
 */
static EC_KEY *build_ec_key(const unsigned char priv[32], const unsigned char pub[65])
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (key == NULL)
    {
        return NULL;
    }

    if (priv != NULL)
    {
        BIGNUM *priv_bn = BN_bin2bn(priv, 32, NULL);
        if (priv_bn == NULL || EC_KEY_set_private_key(key, priv_bn) != 1)
        {
            BN_free(priv_bn);
            EC_KEY_free(key);
            return NULL;
        }
        BN_free(priv_bn);
    }

    if (pub != NULL)
    {
        const unsigned char *p = pub;
        if (o2i_ECPublicKey(&key, &p, 65) == NULL)
        {
            EC_KEY_free(key);
            return NULL;
        }
    }

    return key;
}

int bm_crypto_sign(const unsigned char *data, size_t data_len,
                    const unsigned char priv[32],
                    unsigned char **out_sig, size_t *out_sig_len)
{
    unsigned char pub[65];
    if (bm_address_get_public_key(priv, pub) != 0)
    {
        return -1;
    }

    EC_KEY *key = build_ec_key(priv, pub);
    if (key == NULL)
    {
        return -1;
    }

    unsigned char digest[32];
    bm_sha256(data, data_len, digest);

    unsigned char *sig = malloc(ECDSA_size(key));
    unsigned int actual_len = 0;
    int rc = ECDSA_sign(0, digest, sizeof(digest), sig, &actual_len, key);
    EC_KEY_free(key);

    if (rc != 1)
    {
        free(sig);
        return -1;
    }

    *out_sig = sig;
    *out_sig_len = actual_len;
    return 0;
}

int bm_crypto_verify(const unsigned char *data, size_t data_len,
                      const unsigned char *sig, size_t sig_len,
                      const unsigned char pub[65])
{
    EC_KEY *key = build_ec_key(NULL, pub);
    if (key == NULL)
    {
        return 0;
    }

    unsigned char digest[32];
    bm_sha256(data, data_len, digest);

    int rc = ECDSA_verify(0, digest, sizeof(digest), sig, (int)sig_len, key);
    EC_KEY_free(key);
    return (rc == 1) ? 1 : 0;
}
