#include "address.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/base58.h"
#include "../common/hash.h"
#include "../common/varint.h"

void bm_address_derive_private_key(const char *passphrase, uint64_t nonce,
                                    unsigned char out_priv[BM_PRIVATE_KEY_LEN])
{
    size_t pass_len = strlen(passphrase);
    size_t nonce_len = bm_varint_size(nonce);
    unsigned char *buf = malloc(pass_len + nonce_len);
    memcpy(buf, passphrase, pass_len);
    bm_varint_encode(buf + pass_len, nonce);

    unsigned char full[64];
    bm_sha512(buf, pass_len + nonce_len, full);
    memcpy(out_priv, full, BM_PRIVATE_KEY_LEN);
    free(buf);
}

int bm_address_get_public_key(const unsigned char priv[BM_PRIVATE_KEY_LEN],
                               unsigned char out_pub[BM_PUBLIC_KEY_LEN])
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
    EC_POINT *pub_point = EC_POINT_new(group);

    if (priv_bn != NULL && pub_point != NULL
        && BN_bin2bn(priv, BM_PRIVATE_KEY_LEN, priv_bn) != NULL
        && EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx) == 1)
    {
        size_t written = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                             out_pub, BM_PUBLIC_KEY_LEN, ctx);
        ret = (written == BM_PUBLIC_KEY_LEN) ? 0 : -1;
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

void bm_address_calc_ripe(const unsigned char sign_pub[BM_PUBLIC_KEY_LEN],
                           const unsigned char enc_pub[BM_PUBLIC_KEY_LEN],
                           unsigned char out_ripe[BM_RIPE_LEN])
{
    unsigned char combined[BM_PUBLIC_KEY_LEN * 2];
    memcpy(combined, sign_pub, BM_PUBLIC_KEY_LEN);
    memcpy(combined + BM_PUBLIC_KEY_LEN, enc_pub, BM_PUBLIC_KEY_LEN);

    unsigned char sha512_out[64];
    bm_sha512(combined, sizeof(combined), sha512_out);
    bm_ripemd160(sha512_out, 64, out_ripe);
}

char *bm_address_encode(uint64_t version, uint64_t stream, const unsigned char *ripe, size_t ripe_len)
{
    if (ripe_len != BM_RIPE_LEN)
    {
        return NULL;
    }

    unsigned char work[BM_RIPE_LEN];
    memcpy(work, ripe, BM_RIPE_LEN);
    unsigned char *trimmed = work;
    size_t trimmed_len = BM_RIPE_LEN;

    /* §3.3: v2/v3は先頭最大2byte、v4は先頭0x00を全て除去 */
    if (version >= 2 && version < 4)
    {
        if (work[0] == 0x00 && work[1] == 0x00)
        {
            trimmed = work + 2;
            trimmed_len -= 2;
        }
        else if (work[0] == 0x00)
        {
            trimmed = work + 1;
            trimmed_len -= 1;
        }
    }
    else if (version == 4)
    {
        size_t i = 0;
        while (i < BM_RIPE_LEN && work[i] == 0x00)
        {
            i++;
        }
        trimmed = work + i;
        trimmed_len -= i;
    }

    size_t ver_len = bm_varint_size(version);
    size_t stream_len = bm_varint_size(stream);
    size_t data_len = ver_len + stream_len + trimmed_len;
    unsigned char *data = malloc(data_len + 4);
    bm_varint_encode(data, version);
    bm_varint_encode(data + ver_len, stream);
    memcpy(data + ver_len + stream_len, trimmed, trimmed_len);

    unsigned char checksum[64];
    bm_double_sha512(data, data_len, checksum);
    memcpy(data + data_len, checksum, 4);

    char *b58 = bm_base58_encode(data, data_len + 4);
    free(data);
    if (b58 == NULL)
    {
        return NULL;
    }

    size_t out_len = strlen(b58) + 3 + 1;
    char *out = malloc(out_len);
    snprintf(out, out_len, "BM-%s", b58);
    free(b58);
    return out;
}

char *bm_address_encode_wif(const unsigned char priv[BM_PRIVATE_KEY_LEN])
{
    unsigned char raw[1 + BM_PRIVATE_KEY_LEN + 4];
    raw[0] = 0x80;
    memcpy(raw + 1, priv, BM_PRIVATE_KEY_LEN);

    unsigned char checksum[32];
    bm_double_sha256(raw, 1 + BM_PRIVATE_KEY_LEN, checksum);
    memcpy(raw + 1 + BM_PRIVATE_KEY_LEN, checksum, 4);

    return bm_base58_encode(raw, sizeof(raw));
}

int bm_address_generate_deterministic(const char *passphrase, int null_bytes,
                                       struct bm_generated_address *out)
{
    uint64_t signing_nonce = 0;
    uint64_t encryption_nonce = 1;

    for (;;)
    {
        unsigned char priv_sign[BM_PRIVATE_KEY_LEN];
        unsigned char priv_enc[BM_PRIVATE_KEY_LEN];
        bm_address_derive_private_key(passphrase, signing_nonce, priv_sign);
        bm_address_derive_private_key(passphrase, encryption_nonce, priv_enc);

        unsigned char pub_sign[BM_PUBLIC_KEY_LEN];
        unsigned char pub_enc[BM_PUBLIC_KEY_LEN];
        if (bm_address_get_public_key(priv_sign, pub_sign) != 0
            || bm_address_get_public_key(priv_enc, pub_enc) != 0)
        {
            return -1;
        }

        unsigned char ripe[BM_RIPE_LEN];
        bm_address_calc_ripe(pub_sign, pub_enc, ripe);

        int ok = 1;
        for (int i = 0; i < null_bytes; i++)
        {
            if (ripe[i] != 0x00)
            {
                ok = 0;
                break;
            }
        }

        /* 決定性アドレス生成は毎試行nonceを2ずつ進める(class_addressGenerator.py:262-263) */
        signing_nonce += 2;
        encryption_nonce += 2;

        if (ok)
        {
            memcpy(out->priv_signing, priv_sign, BM_PRIVATE_KEY_LEN);
            memcpy(out->priv_encryption, priv_enc, BM_PRIVATE_KEY_LEN);
            memcpy(out->pub_signing, pub_sign, BM_PUBLIC_KEY_LEN);
            memcpy(out->pub_encryption, pub_enc, BM_PUBLIC_KEY_LEN);
            memcpy(out->ripe, ripe, BM_RIPE_LEN);
            /* 見つかった鍵に対応するnonce値(直前にインクリメントされているので2引く) */
            out->signing_nonce = signing_nonce - 2;
            out->encryption_nonce = encryption_nonce - 2;
            return 0;
        }
    }
}
