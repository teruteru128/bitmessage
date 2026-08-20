#include "message_builder.h"

#include <endian.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "../common/hash.h"
#include "../common/varint.h"
#include "../infra/object.h" /* BM_OBJECT_* 定数 */
#include "address.h"
#include "crypto.h"

/* --- 内部ヘルパー: 可変長バッファ --- */

struct bytebuf
{
    unsigned char *data;
    size_t len;
    size_t cap;
};

static void bb_init(struct bytebuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void bb_reserve(struct bytebuf *b, size_t additional)
{
    if (b->len + additional <= b->cap)
    {
        return;
    }
    size_t new_cap = b->cap == 0 ? 64 : b->cap;
    while (new_cap < b->len + additional)
    {
        new_cap *= 2;
    }
    b->data = realloc(b->data, new_cap);
    b->cap = new_cap;
}

static void bb_append(struct bytebuf *b, const unsigned char *data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    bb_reserve(b, len);
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void bb_append_be64(struct bytebuf *b, uint64_t v)
{
    uint64_t n = htobe64(v);
    bb_append(b, (const unsigned char *)&n, 8);
}

static void bb_append_be32(struct bytebuf *b, uint32_t v)
{
    uint32_t n = htobe32(v);
    bb_append(b, (const unsigned char *)&n, 4);
}

static void bb_append_varint(struct bytebuf *b, uint64_t v)
{
    unsigned char tmp[9];
    bm_varint_encode(tmp, v);
    bb_append(b, tmp, bm_varint_size(v));
}

/* varint(len) || dataの形で追加する(§5の"varint(sigLen)||sig"等のパターン) */
static void bb_append_varbytes(struct bytebuf *b, const unsigned char *data, size_t len)
{
    bb_append_varint(b, len);
    bb_append(b, data, len);
}

/* 所有権をもらい受ける(呼び出し側でbb_freeする必要はなくなる) */
static unsigned char *bb_take(struct bytebuf *b, size_t *out_len)
{
    if (out_len != NULL)
    {
        *out_len = b->len;
    }
    unsigned char *data = b->data;
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    return data;
}

static void bb_free(struct bytebuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* --- 内部ヘルパー: オブジェクト共通ヘッダ(§5.0、nonce抜き) --- */

static void append_common_header(struct bytebuf *b, uint64_t expires_time, uint32_t object_type,
                                  uint64_t version, uint64_t stream)
{
    bb_append_be64(b, expires_time);
    bb_append_be32(b, object_type);
    bb_append_varint(b, version);
    bb_append_varint(b, stream);
}

static void append_bitfield(struct bytebuf *b, int does_ack)
{
    bb_append_be32(b, does_ack ? 1U : 0U); /* BITFIELD_DOESACK = 1 (§5.2) */
}

/* pub(65byte, 0x04||X||Y)の先頭0x04を落として64byteをワイヤに乗せる */
static void append_pubkey64(struct bytebuf *b, const unsigned char pub65[65])
{
    bb_append(b, pub65 + 1, 64);
}

/* §5.1/§5.2/§5.4で使う: SHA512(varint(version)||varint(stream)||ripe)。
 * 前半32byteがv4暗号化用の秘密鍵、後半32byteがtag。 */
static void derive_addr_secret_and_tag(uint64_t version, uint64_t stream, const unsigned char ripe[20],
                                        unsigned char out_secret[32], unsigned char out_tag[32])
{
    struct bytebuf b;
    bb_init(&b);
    bb_append_varint(&b, version);
    bb_append_varint(&b, stream);
    bb_append(&b, ripe, 20);

    unsigned char full[64];
    bm_sha512(b.data, b.len, full);
    bb_free(&b);

    if (out_secret != NULL)
    {
        memcpy(out_secret, full, 32);
    }
    if (out_tag != NULL)
    {
        memcpy(out_tag, full + 32, 32);
    }
}

/* "Subject:%s\nBody:%s"(BITMESSAGE_ENCODING_SIMPLE、§8) */
static void append_simple_encoded_message(struct bytebuf *b, const char *subject, const char *body)
{
    struct bytebuf msg;
    bb_init(&msg);
    bb_append(&msg, (const unsigned char *)"Subject:", 8);
    bb_append(&msg, (const unsigned char *)subject, strlen(subject));
    bb_append(&msg, (const unsigned char *)"\nBody:", 6);
    bb_append(&msg, (const unsigned char *)body, strlen(body));

    bb_append_varint(b, 2); /* encoding = BITMESSAGE_ENCODING_SIMPLE */
    bb_append_varbytes(b, msg.data, msg.len);
    bb_free(&msg);
}

/* --- §5.1: getpubkey --- */

unsigned char *bm_build_getpubkey(uint64_t address_version, uint64_t stream,
                                   const unsigned char ripe[20], uint64_t expires_time,
                                   size_t *out_len)
{
    struct bytebuf b;
    bb_init(&b);
    append_common_header(&b, expires_time, BM_OBJECT_GETPUBKEY, address_version, stream);

    if (address_version <= 3)
    {
        bb_append(&b, ripe, 20);
    }
    else
    {
        unsigned char tag[32];
        derive_addr_secret_and_tag(address_version, stream, ripe, NULL, tag);
        bb_append(&b, tag, 32);
    }

    return bb_take(&b, out_len);
}

/* --- §5.2: pubkey v2/v3/v4 --- */

unsigned char *bm_build_pubkey_v2(const struct bm_identity_info *id, uint64_t expires_time, size_t *out_len)
{
    struct bytebuf b;
    bb_init(&b);
    append_common_header(&b, expires_time, BM_OBJECT_PUBKEY, 2, id->stream);
    append_bitfield(&b, id->does_ack);
    append_pubkey64(&b, id->pub_signing);
    append_pubkey64(&b, id->pub_encryption);
    return bb_take(&b, out_len);
}

unsigned char *bm_build_pubkey_v3(const struct bm_identity_info *id, uint64_t expires_time, size_t *out_len)
{
    struct bytebuf b;
    bb_init(&b);
    append_common_header(&b, expires_time, BM_OBJECT_PUBKEY, 3, id->stream);
    append_bitfield(&b, id->does_ack);
    append_pubkey64(&b, id->pub_signing);
    append_pubkey64(&b, id->pub_encryption);
    bb_append_varint(&b, id->nonce_trials_per_byte);
    bb_append_varint(&b, id->payload_length_extra_bytes);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (bm_crypto_sign(b.data, b.len, id->priv_signing, &sig, &sig_len) != 0)
    {
        bb_free(&b);
        return NULL;
    }
    bb_append_varbytes(&b, sig, sig_len);
    free(sig);

    return bb_take(&b, out_len);
}

unsigned char *bm_build_pubkey_v4(const struct bm_identity_info *id, const unsigned char ripe[20],
                                   uint64_t expires_time, size_t *out_len)
{
    struct bytebuf plain;
    bb_init(&plain);
    append_common_header(&plain, expires_time, BM_OBJECT_PUBKEY, 4, id->stream);

    unsigned char priv_enc[32];
    unsigned char tag[32];
    derive_addr_secret_and_tag(4, id->stream, ripe, priv_enc, tag);
    bb_append(&plain, tag, 32);

    struct bytebuf to_encrypt;
    bb_init(&to_encrypt);
    append_bitfield(&to_encrypt, id->does_ack);
    append_pubkey64(&to_encrypt, id->pub_signing);
    append_pubkey64(&to_encrypt, id->pub_encryption);
    bb_append_varint(&to_encrypt, id->nonce_trials_per_byte);
    bb_append_varint(&to_encrypt, id->payload_length_extra_bytes);

    /* 署名対象 = 平文部(tag込み) || dataToEncrypt(署名を除く) */
    struct bytebuf to_sign;
    bb_init(&to_sign);
    bb_append(&to_sign, plain.data, plain.len);
    bb_append(&to_sign, to_encrypt.data, to_encrypt.len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int rc = bm_crypto_sign(to_sign.data, to_sign.len, id->priv_signing, &sig, &sig_len);
    bb_free(&to_sign);
    if (rc != 0)
    {
        bb_free(&plain);
        bb_free(&to_encrypt);
        return NULL;
    }
    bb_append_varbytes(&to_encrypt, sig, sig_len);
    free(sig);

    unsigned char pub_enc[65];
    if (bm_address_get_public_key(priv_enc, pub_enc) != 0)
    {
        bb_free(&plain);
        bb_free(&to_encrypt);
        return NULL;
    }

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    rc = bm_crypto_ecies_encrypt(to_encrypt.data, to_encrypt.len, pub_enc, &ciphertext, &ciphertext_len);
    bb_free(&to_encrypt);
    if (rc != 0)
    {
        bb_free(&plain);
        return NULL;
    }

    bb_append(&plain, ciphertext, ciphertext_len);
    free(ciphertext);

    return bb_take(&plain, out_len);
}

/* --- §5.3: msg --- */

unsigned char *bm_build_msg(const struct bm_identity_info *from, uint64_t to_stream,
                             const unsigned char to_ripe[20],
                             const unsigned char to_pub_encryption[65],
                             const char *subject, const char *body,
                             const unsigned char *ack_payload, size_t ack_payload_len,
                             uint64_t expires_time, size_t *out_len)
{
    struct bytebuf header;
    bb_init(&header);
    append_common_header(&header, expires_time, BM_OBJECT_MSG, 1, to_stream);

    struct bytebuf payload;
    bb_init(&payload);
    bb_append_varint(&payload, from->address_version);
    bb_append_varint(&payload, from->stream);
    append_bitfield(&payload, from->does_ack);
    append_pubkey64(&payload, from->pub_signing);
    append_pubkey64(&payload, from->pub_encryption);
    if (from->address_version >= 3)
    {
        bb_append_varint(&payload, from->nonce_trials_per_byte);
        bb_append_varint(&payload, from->payload_length_extra_bytes);
    }
    bb_append(&payload, to_ripe, 20);
    append_simple_encoded_message(&payload, subject, body);
    bb_append_varbytes(&payload, ack_payload != NULL ? ack_payload : (const unsigned char *)"",
                        ack_payload_len);

    /* 署名対象 = ヘッダ(平文、objectVersion=1固定) || payload(署名を除く) */
    struct bytebuf to_sign;
    bb_init(&to_sign);
    bb_append(&to_sign, header.data, header.len);
    bb_append(&to_sign, payload.data, payload.len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int rc = bm_crypto_sign(to_sign.data, to_sign.len, from->priv_signing, &sig, &sig_len);
    bb_free(&to_sign);
    if (rc != 0)
    {
        bb_free(&header);
        bb_free(&payload);
        return NULL;
    }
    bb_append_varbytes(&payload, sig, sig_len);
    free(sig);

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    rc = bm_crypto_ecies_encrypt(payload.data, payload.len, to_pub_encryption, &ciphertext, &ciphertext_len);
    bb_free(&payload);
    if (rc != 0)
    {
        bb_free(&header);
        return NULL;
    }

    bb_append(&header, ciphertext, ciphertext_len);
    free(ciphertext);

    return bb_take(&header, out_len);
}

/* --- §5.4: broadcast --- */

unsigned char *bm_build_broadcast(const struct bm_identity_info *from, const unsigned char from_ripe[20],
                                   const char *subject, const char *body,
                                   uint64_t expires_time, size_t *out_len)
{
    int is_v5 = (from->address_version >= 4);
    uint64_t object_version = is_v5 ? 5 : 4;

    struct bytebuf plain;
    bb_init(&plain);
    append_common_header(&plain, expires_time, BM_OBJECT_BROADCAST, object_version, from->stream);

    unsigned char priv_enc[32];
    unsigned char tag[32];
    derive_addr_secret_and_tag(from->address_version, from->stream, from_ripe, priv_enc, tag);
    if (is_v5)
    {
        bb_append(&plain, tag, 32);
    }

    struct bytebuf to_encrypt;
    bb_init(&to_encrypt);
    bb_append_varint(&to_encrypt, from->address_version);
    bb_append_varint(&to_encrypt, from->stream);
    append_bitfield(&to_encrypt, from->does_ack);
    append_pubkey64(&to_encrypt, from->pub_signing);
    append_pubkey64(&to_encrypt, from->pub_encryption);
    if (from->address_version >= 3)
    {
        bb_append_varint(&to_encrypt, from->nonce_trials_per_byte);
        bb_append_varint(&to_encrypt, from->payload_length_extra_bytes);
    }
    append_simple_encoded_message(&to_encrypt, subject, body);

    struct bytebuf to_sign;
    bb_init(&to_sign);
    bb_append(&to_sign, plain.data, plain.len);
    bb_append(&to_sign, to_encrypt.data, to_encrypt.len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int rc = bm_crypto_sign(to_sign.data, to_sign.len, from->priv_signing, &sig, &sig_len);
    bb_free(&to_sign);
    if (rc != 0)
    {
        bb_free(&plain);
        bb_free(&to_encrypt);
        return NULL;
    }
    bb_append_varbytes(&to_encrypt, sig, sig_len);
    free(sig);

    unsigned char pub_enc[65];
    if (bm_address_get_public_key(priv_enc, pub_enc) != 0)
    {
        bb_free(&plain);
        bb_free(&to_encrypt);
        return NULL;
    }

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    rc = bm_crypto_ecies_encrypt(to_encrypt.data, to_encrypt.len, pub_enc, &ciphertext, &ciphertext_len);
    bb_free(&to_encrypt);
    if (rc != 0)
    {
        bb_free(&plain);
        return NULL;
    }

    bb_append(&plain, ciphertext, ciphertext_len);
    free(ciphertext);

    return bb_take(&plain, out_len);
}

/* --- §5.5: ack object --- */

/* stealth level 0/デフォルト: type=msg(2)||version=1||stream||random(32byte)
 * (中身を復号できる者はいない。単なる「msgオブジェクトのふり」をした32byteの乱数) */
static unsigned char *build_ack_level0(uint64_t stream, size_t *out_len)
{
    struct bytebuf b;
    bb_init(&b);
    bb_append_be32(&b, BM_OBJECT_MSG);
    bb_append_varint(&b, 1);
    bb_append_varint(&b, stream);

    unsigned char random32[32];
    if (RAND_bytes(random32, sizeof(random32)) != 1)
    {
        bb_free(&b);
        return NULL;
    }
    bb_append(&b, random32, sizeof(random32));

    return bb_take(&b, out_len);
}

/* stealth level 1(既定、§8-6): type=getpubkey(0)||version=4||stream||random(32byte)。
 * 本物のgetpubkeyのtagと同じ形なので、観測者からは区別できない。 */
static unsigned char *build_ack_level1(uint64_t stream, size_t *out_len)
{
    struct bytebuf b;
    bb_init(&b);
    bb_append_be32(&b, BM_OBJECT_GETPUBKEY);
    bb_append_varint(&b, 4);
    bb_append_varint(&b, stream);

    unsigned char random32[32];
    if (RAND_bytes(random32, sizeof(random32)) != 1)
    {
        bb_free(&b);
        return NULL;
    }
    bb_append(&b, random32, sizeof(random32));

    return bb_take(&b, out_len);
}

/* stealth level 2(最大の秘匿性): 使い捨て鍵ペアへ234〜800byteのランダム長ダミーメッセージを
 * 本物のECIESで暗号化する。本物のmsgオブジェクトと構造上完全に区別がつかない。 */
static unsigned char *build_ack_level2(uint64_t stream, size_t *out_len)
{
    unsigned char dummy_priv[32];
    if (RAND_bytes(dummy_priv, sizeof(dummy_priv)) != 1)
    {
        return NULL;
    }
    unsigned char dummy_pub[65];
    if (bm_address_get_public_key(dummy_priv, dummy_pub) != 0)
    {
        return NULL;
    }

    uint32_t rand_len_seed = 0;
    if (RAND_bytes((unsigned char *)&rand_len_seed, sizeof(rand_len_seed)) != 1)
    {
        return NULL;
    }
    size_t dummy_len = 234 + (rand_len_seed % (800 - 234 + 1));

    unsigned char *dummy_message = malloc(dummy_len);
    if (dummy_message == NULL || RAND_bytes(dummy_message, (int)dummy_len) != 1)
    {
        free(dummy_message);
        return NULL;
    }

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    int rc = bm_crypto_ecies_encrypt(dummy_message, dummy_len, dummy_pub, &ciphertext, &ciphertext_len);
    free(dummy_message);
    if (rc != 0)
    {
        return NULL;
    }

    struct bytebuf b;
    bb_init(&b);
    bb_append_be32(&b, BM_OBJECT_MSG);
    bb_append_varint(&b, 1);
    bb_append_varint(&b, stream);
    bb_append(&b, ciphertext, ciphertext_len);
    free(ciphertext);

    return bb_take(&b, out_len);
}

unsigned char *bm_build_ack_object(int stealth_level, uint64_t stream, size_t *out_len)
{
    switch (stealth_level)
    {
    case 1:
        return build_ack_level1(stream, out_len);
    case 2:
        return build_ack_level2(stream, out_len);
    default:
        return build_ack_level0(stream, out_len);
    }
}
