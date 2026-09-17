/* address_v5.h の説明を参照。DESIGN-PQ.md §4。 */

#include "address_v5.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "base58.h"
#include "hash.h"
#include "varint.h"
#include "pq_hybrid.h"

/*
 * bm_varint_encodeは「書き込んだ後も引数のoutをそのまま返す」(varint.h参照)。
 * 連結して書き進める用途ではポインタを自分で進める必要があるため、取り違えを
 * 防ぐ小さなラッパを置く(取り違えると varint が後続データに上書きされ、
 * version/streamがハッシュ入力から丸ごと抜け落ちる形で壊れる)。
 */
static unsigned char *put_varint(unsigned char *p, uint64_t v)
{
    bm_varint_encode(p, v);
    return p + bm_varint_size(v);
}

void bm_pqv5_calc_id(uint64_t version, uint64_t stream,
                      const unsigned char sig_pk[BM_PQV5_SIG_PK_LEN],
                      const unsigned char kem_pk[BM_PQV5_KEM_PK_LEN],
                      unsigned char out_id[BM_PQV5_ID_LEN])
{
    size_t label_len = strlen(BM_PQV5_LABEL_ID);
    size_t total = label_len + bm_varint_size(version) + bm_varint_size(stream) +
                   BM_PQV5_SIG_PK_LEN + BM_PQV5_KEM_PK_LEN;
    unsigned char *buf = malloc(total);
    unsigned char *p;

    if (buf == NULL)
    {
        /* 呼び出し側にエラーを返す経路が無い(v4のbm_address_calc_ripeと同じくvoid)。
         * 全0のidを返すと「たまたま衝突するアドレス」を作ってしまうので、
         * ここは確保できない=続行不能として扱う */
        abort();
    }
    p = buf;
    memcpy(p, BM_PQV5_LABEL_ID, label_len);
    p += label_len;
    p = put_varint(p, version);
    p = put_varint(p, stream);
    memcpy(p, sig_pk, BM_PQV5_SIG_PK_LEN);
    p += BM_PQV5_SIG_PK_LEN;
    memcpy(p, kem_pk, BM_PQV5_KEM_PK_LEN);

    bm_pq_sha3_256(buf, total, out_id);
    free(buf);
}

void bm_pqv5_derive_secret_and_tag(uint64_t version, uint64_t stream,
                                    const unsigned char id[BM_PQV5_ID_LEN],
                                    unsigned char out_seed[BM_PQV5_SEED_LEN],
                                    unsigned char out_tag[32])
{
    unsigned char buf[64 + BM_PQV5_ID_LEN];
    unsigned char digest[64];
    size_t label_len = strlen(BM_PQV5_LABEL_TAG);
    unsigned char *p = buf;

    memcpy(p, BM_PQV5_LABEL_TAG, label_len);
    p += label_len;
    p = put_varint(p, version);
    p = put_varint(p, stream);
    memcpy(p, id, BM_PQV5_ID_LEN);
    p += BM_PQV5_ID_LEN;

    bm_pq_sha3_512(buf, (size_t)(p - buf), digest);
    if (out_seed != NULL)
    {
        memcpy(out_seed, digest, BM_PQV5_SEED_LEN);
    }
    if (out_tag != NULL)
    {
        memcpy(out_tag, digest + 32, 32);
    }
    OPENSSL_cleanse(digest, sizeof(digest));
}

int bm_pqv5_address_kem_keypair(uint64_t version, uint64_t stream,
                                 const unsigned char id[BM_PQV5_ID_LEN],
                                 unsigned char out_pk[BM_PQV5_KEM_PK_LEN],
                                 unsigned char out_sk[BM_PQV5_KEM_SK_LEN])
{
    unsigned char seed[BM_PQV5_SEED_LEN];
    int rc;

    bm_pqv5_derive_secret_and_tag(version, stream, id, seed, NULL);
    rc = bm_pqv5_kem_keypair_from_seed(seed, out_pk, out_sk);
    OPENSSL_cleanse(seed, sizeof(seed));
    return rc;
}

char *bm_pqv5_address_encode(uint64_t version, uint64_t stream, const unsigned char id[BM_PQV5_ID_LEN])
{
    unsigned char buf[16 + BM_PQV5_ID_LEN + 4];
    unsigned char checksum[64];
    unsigned char *p = buf;
    size_t strip = 0;
    size_t data_len;
    char *b58;
    char *out;

    /* v4と同じ規則で先頭の0x00を全て落とす(非正規エンコーディングはdecode側で拒否する) */
    while (strip < BM_PQV5_ID_LEN && id[strip] == 0x00)
    {
        strip++;
    }

    p = put_varint(p, version);
    p = put_varint(p, stream);
    memcpy(p, id + strip, BM_PQV5_ID_LEN - strip);
    p += BM_PQV5_ID_LEN - strip;
    data_len = (size_t)(p - buf);

    bm_double_sha512(buf, data_len, checksum);
    memcpy(p, checksum, 4);
    data_len += 4;

    b58 = bm_base58_encode(buf, data_len);
    if (b58 == NULL)
    {
        return NULL;
    }
    out = malloc(strlen(b58) + 4);
    if (out == NULL)
    {
        free(b58);
        return NULL;
    }
    memcpy(out, "BM-", 3);
    memcpy(out + 3, b58, strlen(b58) + 1);
    free(b58);
    return out;
}

int bm_pqv5_address_decode(const char *address, uint64_t *out_version, uint64_t *out_stream,
                            unsigned char out_id[BM_PQV5_ID_LEN])
{
    const char *body = address;
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    size_t offset = 0;
    size_t consumed;
    uint64_t version = 0;
    uint64_t stream = 0;
    size_t id_data_len;
    unsigned char checksum[64];
    int rc = -1;

    if (address == NULL)
    {
        return -1;
    }
    if (strncmp(body, "BM-", 3) == 0)
    {
        body += 3;
    }
    if (bm_base58_decode(body, &raw, &raw_len) != 0)
    {
        return -1;
    }
    if (raw_len < 4 + 2)
    {
        goto out;
    }

    /* checksumはdouble_sha512の先頭4byte(v2〜v4と共通) */
    bm_double_sha512(raw, raw_len - 4, checksum);
    if (memcmp(checksum, raw + raw_len - 4, 4) != 0)
    {
        goto out;
    }

    consumed = bm_varint_decode(raw, raw_len - 4, &version);
    if (consumed == 0 || version != BM_PQV5_ADDRESS_VERSION)
    {
        goto out;
    }
    offset += consumed;
    consumed = bm_varint_decode(raw + offset, raw_len - 4 - offset, &stream);
    if (consumed == 0)
    {
        goto out;
    }
    offset += consumed;

    id_data_len = raw_len - 4 - offset;
    if (id_data_len > BM_PQV5_ID_LEN)
    {
        goto out;
    }
    /* 非マレアビリティ: 先頭0x00が残っているエンコーディングは拒否する(v4と同じ) */
    if (id_data_len > 0 && raw[offset] == 0x00)
    {
        goto out;
    }
    memset(out_id, 0x00, BM_PQV5_ID_LEN - id_data_len);
    memcpy(out_id + (BM_PQV5_ID_LEN - id_data_len), raw + offset, id_data_len);

    if (out_version != NULL)
    {
        *out_version = version;
    }
    if (out_stream != NULL)
    {
        *out_stream = stream;
    }
    rc = 0;

out:
    free(raw);
    return rc;
}

int bm_pqv5_identity_from_seeds(uint64_t stream,
                                 const unsigned char sig_seed[BM_PQV5_SEED_LEN],
                                 const unsigned char kem_seed[BM_PQV5_SEED_LEN],
                                 struct bm_pqv5_identity *out)
{
    memset(out, 0, sizeof(*out));
    out->version = BM_PQV5_ADDRESS_VERSION;
    out->stream = stream;
    if (bm_pqv5_sig_keypair_from_seed(sig_seed, out->sig_pk, out->sig_sk) != 0)
    {
        return -1;
    }
    if (bm_pqv5_kem_keypair_from_seed(kem_seed, out->kem_pk, out->kem_sk) != 0)
    {
        return -1;
    }
    bm_pqv5_calc_id(out->version, out->stream, out->sig_pk, out->kem_pk, out->id);
    return 0;
}

int bm_pqv5_identity_generate_random(uint64_t stream, struct bm_pqv5_identity *out)
{
    unsigned char sig_seed[BM_PQV5_SEED_LEN];
    unsigned char kem_seed[BM_PQV5_SEED_LEN];
    int rc;

    if (RAND_bytes(sig_seed, sizeof(sig_seed)) != 1 || RAND_bytes(kem_seed, sizeof(kem_seed)) != 1)
    {
        return -1;
    }
    rc = bm_pqv5_identity_from_seeds(stream, sig_seed, kem_seed, out);
    OPENSSL_cleanse(sig_seed, sizeof(sig_seed));
    OPENSSL_cleanse(kem_seed, sizeof(kem_seed));
    return rc;
}

/* seed = SHA3-512(label || 0x00 || passphrase || varint(nonce))[0:32] */
static int derive_seed(const char *passphrase, uint64_t nonce, unsigned char out_seed[BM_PQV5_SEED_LEN])
{
    size_t label_len = strlen(BM_PQV5_LABEL_DETERMINISTIC);
    size_t pass_len = strlen(passphrase);
    size_t total = label_len + 1 + pass_len + bm_varint_size(nonce);
    unsigned char *buf = malloc(total);
    unsigned char digest[64];
    unsigned char *p;

    if (buf == NULL)
    {
        return -1;
    }
    p = buf;
    memcpy(p, BM_PQV5_LABEL_DETERMINISTIC, label_len);
    p += label_len;
    *p++ = 0x00;
    memcpy(p, passphrase, pass_len);
    p += pass_len;
    p = put_varint(p, nonce);

    bm_pq_sha3_512(buf, (size_t)(p - buf), digest);
    memcpy(out_seed, digest, BM_PQV5_SEED_LEN);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(buf, total);
    free(buf);
    return 0;
}

int bm_pqv5_identity_generate_deterministic(const char *passphrase, uint64_t stream,
                                             uint64_t start_nonce, int null_bytes,
                                             struct bm_pqv5_identity *out)
{
    uint64_t nonce = start_nonce;
    unsigned char sig_seed[BM_PQV5_SEED_LEN];
    unsigned char kem_seed[BM_PQV5_SEED_LEN];

    if (null_bytes < 0 || null_bytes > BM_PQV5_ID_LEN)
    {
        return -1;
    }
    for (;;)
    {
        int i;
        int ok = 1;

        if (derive_seed(passphrase, nonce, sig_seed) != 0 ||
            derive_seed(passphrase, nonce + 1, kem_seed) != 0)
        {
            return -1;
        }
        if (bm_pqv5_identity_from_seeds(stream, sig_seed, kem_seed, out) != 0)
        {
            OPENSSL_cleanse(sig_seed, sizeof(sig_seed));
            OPENSSL_cleanse(kem_seed, sizeof(kem_seed));
            return -1;
        }
        for (i = 0; i < null_bytes; i++)
        {
            if (out->id[i] != 0x00)
            {
                ok = 0;
                break;
            }
        }
        if (ok)
        {
            out->sig_nonce = nonce;
            out->kem_nonce = nonce + 1;
            break;
        }
        /* v4(class_addressGenerator.py)と同じく署名鍵nonceと暗号化鍵nonceを
         * ペアで2ずつ進める */
        nonce += 2;
    }
    OPENSSL_cleanse(sig_seed, sizeof(sig_seed));
    OPENSSL_cleanse(kem_seed, sizeof(kem_seed));
    return 0;
}
