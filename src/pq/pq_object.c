/* pq_object.h の説明を参照。DESIGN-PQ.md §7。 */

#include "pq_object.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "varint.h"

/* object種別番号は既存のinfra/object.hと同じ値。infra層へ依存させたくないのでここで再定義する */
#define PQ_OBJECT_GETPUBKEY 0
#define PQ_OBJECT_PUBKEY 1
#define PQ_OBJECT_MSG 2
#define PQ_OBJECT_BROADCAST 3

/* --- 境界チェック付きの書き込み/読み出しヘルパ --- */

struct wbuf
{
    unsigned char *p;
    unsigned char *end;
    int overflow;
};

static void w_bytes(struct wbuf *w, const void *data, size_t len)
{
    if (w->overflow || (size_t)(w->end - w->p) < len)
    {
        w->overflow = 1;
        return;
    }
    memcpy(w->p, data, len);
    w->p += len;
}

static void w_u32(struct wbuf *w, uint32_t v)
{
    unsigned char b[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16),
                           (unsigned char)(v >> 8), (unsigned char)v };
    w_bytes(w, b, sizeof(b));
}

static void w_u64(struct wbuf *w, uint64_t v)
{
    unsigned char b[8];
    int i;
    for (i = 0; i < 8; i++)
    {
        b[i] = (unsigned char)(v >> (56 - 8 * i));
    }
    w_bytes(w, b, sizeof(b));
}

static void w_varint(struct wbuf *w, uint64_t v)
{
    unsigned char b[9];
    size_t n = bm_varint_size(v);
    bm_varint_encode(b, v);
    w_bytes(w, b, n);
}

struct rbuf
{
    const unsigned char *p;
    const unsigned char *end;
    int error;
};

static void r_bytes(struct rbuf *r, void *out, size_t len)
{
    if (r->error || (size_t)(r->end - r->p) < len)
    {
        r->error = 1;
        return;
    }
    memcpy(out, r->p, len);
    r->p += len;
}

static uint32_t r_u32(struct rbuf *r)
{
    unsigned char b[4];
    r_bytes(r, b, sizeof(b));
    if (r->error)
    {
        return 0;
    }
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static uint64_t r_varint(struct rbuf *r)
{
    uint64_t v = 0;
    size_t consumed;
    if (r->error)
    {
        return 0;
    }
    consumed = bm_varint_decode(r->p, (size_t)(r->end - r->p), &v);
    if (consumed == 0)
    {
        r->error = 1;
        return 0;
    }
    r->p += consumed;
    return v;
}

/* 共通ヘッダ(nonce抜き)を書く。DESIGN.md §5.0と同じ並び */
static void w_object_header(struct wbuf *w, uint64_t expires_time, uint32_t object_type,
                             uint64_t object_version, uint64_t stream)
{
    w_u64(w, expires_time);
    w_u32(w, object_type);
    w_varint(w, object_version);
    w_varint(w, stream);
}

static size_t object_header_size(uint64_t object_version, uint64_t stream)
{
    return 8 + 4 + bm_varint_size(object_version) + bm_varint_size(stream);
}

/*
 * 署名対象を組み立てる: 平文部(nonce抜きヘッダ + あればtag) || 封緘される中身の
 * signatureフィールドより手前まで。mallocして返す(呼び出し側でfree)。
 */
static unsigned char *build_signing_message(const unsigned char *plain, size_t plain_len,
                                             const unsigned char *inner, size_t inner_len,
                                             size_t *out_len)
{
    unsigned char *buf = malloc(plain_len + inner_len);
    if (buf == NULL)
    {
        return NULL;
    }
    memcpy(buf, plain, plain_len);
    memcpy(buf + plain_len, inner, inner_len);
    *out_len = plain_len + inner_len;
    return buf;
}

/* --- getpubkey --- */

unsigned char *bm_pq_build_getpubkey(uint64_t address_version, uint64_t stream,
                                      const unsigned char id[BM_PQV5_ID_LEN],
                                      uint64_t expires_time, size_t *out_len)
{
    size_t total = object_header_size(BM_PQ_GETPUBKEY_OBJECT_VERSION, stream) + 32;
    unsigned char *buf = malloc(total);
    unsigned char tag[32];
    struct wbuf w;

    if (buf == NULL)
    {
        return NULL;
    }
    bm_pqv5_derive_secret_and_tag(address_version, stream, id, NULL, tag);

    w.p = buf;
    w.end = buf + total;
    w.overflow = 0;
    w_object_header(&w, expires_time, PQ_OBJECT_GETPUBKEY, BM_PQ_GETPUBKEY_OBJECT_VERSION, stream);
    w_bytes(&w, tag, sizeof(tag));
    if (w.overflow)
    {
        free(buf);
        return NULL;
    }
    *out_len = total;
    return buf;
}

/* --- pubkey --- */

unsigned char *bm_pq_build_pubkey(const struct bm_pq_sender_info *from, uint64_t expires_time,
                                   size_t *out_len)
{
    const struct bm_pqv5_identity *id = from->identity;
    size_t plain_len = object_header_size(BM_PQ_PUBKEY_OBJECT_VERSION, id->stream) + 32;
    size_t inner_presig_len = 4 + BM_PQV5_SIG_PK_LEN + BM_PQV5_KEM_PK_LEN +
                              bm_varint_size(from->nonce_trials_per_byte) +
                              bm_varint_size(from->payload_length_extra_bytes);
    size_t inner_len = inner_presig_len + bm_varint_size(BM_PQV5_SIG_LEN) + BM_PQV5_SIG_LEN;
    size_t total = plain_len + BM_PQV5_SEAL_OVERHEAD + inner_len;
    unsigned char *buf = malloc(total);
    unsigned char *inner = malloc(inner_len);
    unsigned char *signing_msg = NULL;
    unsigned char sig[BM_PQV5_SIG_LEN];
    unsigned char addr_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char addr_kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char tag[32];
    struct wbuf w;
    struct wbuf iw;
    size_t signing_len = 0;
    size_t sealed_len = 0;

    if (buf == NULL || inner == NULL)
    {
        goto fail;
    }
    bm_pqv5_derive_secret_and_tag(id->version, id->stream, id->id, NULL, tag);
    if (bm_pqv5_address_kem_keypair(id->version, id->stream, id->id, addr_kem_pk, addr_kem_sk) != 0)
    {
        goto fail;
    }

    /* 平文部 */
    w.p = buf;
    w.end = buf + total;
    w.overflow = 0;
    w_object_header(&w, expires_time, PQ_OBJECT_PUBKEY, BM_PQ_PUBKEY_OBJECT_VERSION, id->stream);
    w_bytes(&w, tag, sizeof(tag));

    /* 封緘される中身(署名の手前まで) */
    iw.p = inner;
    iw.end = inner + inner_len;
    iw.overflow = 0;
    w_u32(&iw, from->bitfield);
    w_bytes(&iw, id->sig_pk, BM_PQV5_SIG_PK_LEN);
    w_bytes(&iw, id->kem_pk, BM_PQV5_KEM_PK_LEN);
    w_varint(&iw, from->nonce_trials_per_byte);
    w_varint(&iw, from->payload_length_extra_bytes);
    if (w.overflow || iw.overflow)
    {
        goto fail;
    }

    signing_msg = build_signing_message(buf, plain_len, inner, inner_presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_sign(signing_msg, signing_len, id->sig_sk, sig) != 0)
    {
        goto fail;
    }
    w_varint(&iw, BM_PQV5_SIG_LEN);
    w_bytes(&iw, sig, sizeof(sig));
    if (iw.overflow)
    {
        goto fail;
    }

    if (bm_pqv5_seal(addr_kem_pk, buf, plain_len, inner, inner_len, buf + plain_len, &sealed_len) != 0 ||
        plain_len + sealed_len != total)
    {
        goto fail;
    }

    free(signing_msg);
    free(inner);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    *out_len = total;
    return buf;

fail:
    free(signing_msg);
    free(inner);
    free(buf);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    return NULL;
}

int bm_pq_parse_pubkey(const unsigned char *object, size_t object_len,
                        uint64_t address_version, uint64_t stream,
                        const unsigned char id[BM_PQV5_ID_LEN],
                        struct bm_pq_pubkey_parsed *out)
{
    const unsigned char *plain;
    size_t plain_len;
    unsigned char expected_tag[32];
    unsigned char addr_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char addr_kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char *inner = NULL;
    unsigned char *signing_msg = NULL;
    size_t inner_len = 0;
    size_t signing_len = 0;
    size_t sealed_len;
    unsigned char sig[BM_PQV5_SIG_LEN];
    unsigned char recomputed_id[BM_PQV5_ID_LEN];
    struct rbuf r;
    uint64_t sig_len_field;
    size_t presig_len;
    int rc = -1;

    if (object_len < 8)
    {
        return -1;
    }
    /* 先頭8byteのPoW nonceはAAD・署名対象のどちらにも含めない(PoW後に前置されるため) */
    plain = object + 8;
    plain_len = object_header_size(BM_PQ_PUBKEY_OBJECT_VERSION, stream) + 32;
    if (object_len < 8 + plain_len + BM_PQV5_SEAL_OVERHEAD)
    {
        return -1;
    }

    bm_pqv5_derive_secret_and_tag(address_version, stream, id, NULL, expected_tag);
    if (memcmp(plain + plain_len - 32, expected_tag, 32) != 0)
    {
        /* この候補宛てではない。開封を試みるまでもない(v4 pubkeyのtag照合と同じ) */
        return -1;
    }
    if (bm_pqv5_address_kem_keypair(address_version, stream, id, addr_kem_pk, addr_kem_sk) != 0)
    {
        return -1;
    }

    sealed_len = object_len - 8 - plain_len;
    inner_len = sealed_len - BM_PQV5_SEAL_OVERHEAD;
    inner = malloc(inner_len);
    if (inner == NULL)
    {
        goto out;
    }
    if (bm_pqv5_open(addr_kem_sk, plain, plain_len, plain + plain_len, sealed_len, inner, &inner_len) != 0)
    {
        goto out;
    }

    memset(out, 0, sizeof(*out));
    out->address_version = address_version;
    out->stream = stream;

    r.p = inner;
    r.end = inner + inner_len;
    r.error = 0;
    out->bitfield = r_u32(&r);
    r_bytes(&r, out->sig_pk, BM_PQV5_SIG_PK_LEN);
    r_bytes(&r, out->kem_pk, BM_PQV5_KEM_PK_LEN);
    out->nonce_trials_per_byte = r_varint(&r);
    out->payload_length_extra_bytes = r_varint(&r);
    presig_len = (size_t)(r.p - inner);
    sig_len_field = r_varint(&r);
    if (r.error || sig_len_field != BM_PQV5_SIG_LEN)
    {
        goto out;
    }
    r_bytes(&r, sig, sizeof(sig));
    if (r.error)
    {
        goto out;
    }

    signing_msg = build_signing_message(plain, plain_len, inner, presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_verify(signing_msg, signing_len, sig, out->sig_pk) != 1)
    {
        goto out;
    }

    /* 中の公開鍵から再計算したidが、要求していたアドレスと一致することを確認する
     * (別人の公開鍵を詰めたpubkeyを掴まされないための整合性チェック) */
    bm_pqv5_calc_id(out->sig_pk, out->kem_pk, recomputed_id);
    if (memcmp(recomputed_id, id, BM_PQV5_ID_LEN) != 0)
    {
        goto out;
    }
    rc = 0;

out:
    free(signing_msg);
    free(inner);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    return rc;
}

/* --- msg --- */

unsigned char *bm_pq_build_msg(const struct bm_pq_sender_info *from, uint64_t to_stream,
                                const unsigned char to_id[BM_PQV5_ID_LEN],
                                const unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN],
                                uint64_t encoding, const unsigned char *message, size_t message_len,
                                const unsigned char *ack, size_t ack_len,
                                uint64_t expires_time, size_t *out_len)
{
    const struct bm_pqv5_identity *id = from->identity;
    size_t plain_len = object_header_size(BM_PQ_MSG_OBJECT_VERSION, to_stream);
    size_t inner_presig_len = bm_varint_size(id->version) + bm_varint_size(id->stream) + 4 +
                              BM_PQV5_SIG_PK_LEN + BM_PQV5_KEM_PK_LEN +
                              bm_varint_size(from->nonce_trials_per_byte) +
                              bm_varint_size(from->payload_length_extra_bytes) +
                              BM_PQV5_ID_LEN +
                              bm_varint_size(encoding) +
                              bm_varint_size(message_len) + message_len +
                              bm_varint_size(ack_len) + ack_len;
    size_t inner_len = inner_presig_len + bm_varint_size(BM_PQV5_SIG_LEN) + BM_PQV5_SIG_LEN;
    size_t total = plain_len + BM_PQV5_SEAL_OVERHEAD + inner_len;
    unsigned char *buf = malloc(total);
    unsigned char *inner = malloc(inner_len);
    unsigned char *signing_msg = NULL;
    unsigned char sig[BM_PQV5_SIG_LEN];
    struct wbuf w;
    struct wbuf iw;
    size_t signing_len = 0;
    size_t sealed_len = 0;

    if (buf == NULL || inner == NULL)
    {
        goto fail;
    }

    w.p = buf;
    w.end = buf + total;
    w.overflow = 0;
    w_object_header(&w, expires_time, PQ_OBJECT_MSG, BM_PQ_MSG_OBJECT_VERSION, to_stream);

    iw.p = inner;
    iw.end = inner + inner_len;
    iw.overflow = 0;
    w_varint(&iw, id->version);
    w_varint(&iw, id->stream);
    w_u32(&iw, from->bitfield);
    w_bytes(&iw, id->sig_pk, BM_PQV5_SIG_PK_LEN);
    w_bytes(&iw, id->kem_pk, BM_PQV5_KEM_PK_LEN);
    w_varint(&iw, from->nonce_trials_per_byte);
    w_varint(&iw, from->payload_length_extra_bytes);
    w_bytes(&iw, to_id, BM_PQV5_ID_LEN);
    w_varint(&iw, encoding);
    w_varint(&iw, message_len);
    w_bytes(&iw, message, message_len);
    w_varint(&iw, ack_len);
    if (ack_len > 0)
    {
        w_bytes(&iw, ack, ack_len);
    }
    if (w.overflow || iw.overflow || (size_t)(iw.p - inner) != inner_presig_len)
    {
        goto fail;
    }

    signing_msg = build_signing_message(buf, plain_len, inner, inner_presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_sign(signing_msg, signing_len, id->sig_sk, sig) != 0)
    {
        goto fail;
    }
    w_varint(&iw, BM_PQV5_SIG_LEN);
    w_bytes(&iw, sig, sizeof(sig));
    if (iw.overflow)
    {
        goto fail;
    }

    if (bm_pqv5_seal(to_kem_pk, buf, plain_len, inner, inner_len, buf + plain_len, &sealed_len) != 0 ||
        plain_len + sealed_len != total)
    {
        goto fail;
    }

    free(signing_msg);
    free(inner);
    *out_len = total;
    return buf;

fail:
    free(signing_msg);
    free(inner);
    free(buf);
    return NULL;
}

int bm_pq_parse_msg(const unsigned char *object, size_t object_len,
                     const unsigned char kem_sk[BM_PQV5_KEM_SK_LEN],
                     struct bm_pq_msg_parsed *out)
{
    const unsigned char *plain;
    size_t plain_len;
    unsigned char *inner = NULL;
    unsigned char *signing_msg = NULL;
    size_t inner_len;
    size_t signing_len = 0;
    size_t sealed_len;
    size_t presig_len;
    unsigned char sig[BM_PQV5_SIG_LEN];
    struct rbuf r;
    uint64_t version;
    uint64_t stream;
    uint64_t sig_len_field;
    uint64_t len_field;
    size_t header_consumed;
    int rc = -1;

    memset(out, 0, sizeof(*out));
    if (object_len < 8 + 12)
    {
        return -1;
    }
    plain = object + 8;

    /* ヘッダのstreamは可変長varintなので、objectVersionとstreamを読んで平文部の長さを決める */
    r.p = plain + 8 + 4;
    r.end = object + object_len;
    r.error = 0;
    if (r_varint(&r) != BM_PQ_MSG_OBJECT_VERSION || r.error)
    {
        return -1;
    }
    (void)r_varint(&r);
    if (r.error)
    {
        return -1;
    }
    header_consumed = (size_t)(r.p - plain);
    plain_len = header_consumed;
    if (object_len < 8 + plain_len + BM_PQV5_SEAL_OVERHEAD)
    {
        return -1;
    }

    sealed_len = object_len - 8 - plain_len;
    inner_len = sealed_len - BM_PQV5_SEAL_OVERHEAD;
    inner = malloc(inner_len);
    if (inner == NULL)
    {
        goto out;
    }
    if (bm_pqv5_open(kem_sk, plain, plain_len, plain + plain_len, sealed_len, inner, &inner_len) != 0)
    {
        /* 自分宛てではない(あるいは改竄されている)。ここが「総当たり復号」の棄却点 */
        goto out;
    }

    r.p = inner;
    r.end = inner + inner_len;
    r.error = 0;
    version = r_varint(&r);
    stream = r_varint(&r);
    out->from_address_version = version;
    out->from_stream = stream;
    out->bitfield = r_u32(&r);
    r_bytes(&r, out->from_sig_pk, BM_PQV5_SIG_PK_LEN);
    r_bytes(&r, out->from_kem_pk, BM_PQV5_KEM_PK_LEN);
    out->nonce_trials_per_byte = r_varint(&r);
    out->payload_length_extra_bytes = r_varint(&r);
    r_bytes(&r, out->to_id, BM_PQV5_ID_LEN);
    out->encoding = r_varint(&r);

    len_field = r_varint(&r);
    if (r.error || len_field > (uint64_t)(r.end - r.p))
    {
        goto out;
    }
    out->message_len = (size_t)len_field;
    out->message = malloc(out->message_len + 1);
    if (out->message == NULL)
    {
        goto out;
    }
    r_bytes(&r, out->message, out->message_len);
    out->message[out->message_len] = '\0';

    len_field = r_varint(&r);
    if (r.error || len_field > (uint64_t)(r.end - r.p))
    {
        goto out;
    }
    out->ack_len = (size_t)len_field;
    if (out->ack_len > 0)
    {
        out->ack = malloc(out->ack_len);
        if (out->ack == NULL)
        {
            goto out;
        }
        r_bytes(&r, out->ack, out->ack_len);
    }

    presig_len = (size_t)(r.p - inner);
    sig_len_field = r_varint(&r);
    if (r.error || sig_len_field != BM_PQV5_SIG_LEN)
    {
        goto out;
    }
    r_bytes(&r, sig, sizeof(sig));
    if (r.error)
    {
        goto out;
    }

    signing_msg = build_signing_message(plain, plain_len, inner, presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_verify(signing_msg, signing_len, sig, out->from_sig_pk) != 1)
    {
        goto out;
    }

    bm_pqv5_calc_id(out->from_sig_pk, out->from_kem_pk, out->from_id);
    rc = 0;

out:
    free(signing_msg);
    free(inner);
    if (rc != 0)
    {
        bm_pq_msg_parsed_free(out);
    }
    return rc;
}

void bm_pq_msg_parsed_free(struct bm_pq_msg_parsed *parsed)
{
    free(parsed->message);
    free(parsed->ack);
    parsed->message = NULL;
    parsed->ack = NULL;
    parsed->message_len = 0;
    parsed->ack_len = 0;
}

/* --- broadcast --- */

unsigned char *bm_pq_build_broadcast(const struct bm_pq_sender_info *from,
                                      uint64_t encoding, const unsigned char *message, size_t message_len,
                                      uint64_t expires_time, size_t *out_len)
{
    const struct bm_pqv5_identity *id = from->identity;
    size_t plain_len = object_header_size(BM_PQ_BROADCAST_OBJECT_VERSION, id->stream) + 32;
    size_t inner_presig_len = bm_varint_size(id->version) + bm_varint_size(id->stream) + 4 +
                              BM_PQV5_SIG_PK_LEN + BM_PQV5_KEM_PK_LEN +
                              bm_varint_size(from->nonce_trials_per_byte) +
                              bm_varint_size(from->payload_length_extra_bytes) +
                              bm_varint_size(encoding) +
                              bm_varint_size(message_len) + message_len;
    size_t inner_len = inner_presig_len + bm_varint_size(BM_PQV5_SIG_LEN) + BM_PQV5_SIG_LEN;
    size_t total = plain_len + BM_PQV5_SEAL_OVERHEAD + inner_len;
    unsigned char *buf = malloc(total);
    unsigned char *inner = malloc(inner_len);
    unsigned char *signing_msg = NULL;
    unsigned char sig[BM_PQV5_SIG_LEN];
    unsigned char addr_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char addr_kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char tag[32];
    struct wbuf w;
    struct wbuf iw;
    size_t signing_len = 0;
    size_t sealed_len = 0;

    if (buf == NULL || inner == NULL)
    {
        goto fail;
    }
    bm_pqv5_derive_secret_and_tag(id->version, id->stream, id->id, NULL, tag);
    if (bm_pqv5_address_kem_keypair(id->version, id->stream, id->id, addr_kem_pk, addr_kem_sk) != 0)
    {
        goto fail;
    }

    w.p = buf;
    w.end = buf + total;
    w.overflow = 0;
    w_object_header(&w, expires_time, PQ_OBJECT_BROADCAST, BM_PQ_BROADCAST_OBJECT_VERSION, id->stream);
    w_bytes(&w, tag, sizeof(tag));

    iw.p = inner;
    iw.end = inner + inner_len;
    iw.overflow = 0;
    w_varint(&iw, id->version);
    w_varint(&iw, id->stream);
    w_u32(&iw, from->bitfield);
    w_bytes(&iw, id->sig_pk, BM_PQV5_SIG_PK_LEN);
    w_bytes(&iw, id->kem_pk, BM_PQV5_KEM_PK_LEN);
    w_varint(&iw, from->nonce_trials_per_byte);
    w_varint(&iw, from->payload_length_extra_bytes);
    w_varint(&iw, encoding);
    w_varint(&iw, message_len);
    w_bytes(&iw, message, message_len);
    if (w.overflow || iw.overflow)
    {
        goto fail;
    }

    signing_msg = build_signing_message(buf, plain_len, inner, inner_presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_sign(signing_msg, signing_len, id->sig_sk, sig) != 0)
    {
        goto fail;
    }
    w_varint(&iw, BM_PQV5_SIG_LEN);
    w_bytes(&iw, sig, sizeof(sig));
    if (iw.overflow)
    {
        goto fail;
    }

    if (bm_pqv5_seal(addr_kem_pk, buf, plain_len, inner, inner_len, buf + plain_len, &sealed_len) != 0 ||
        plain_len + sealed_len != total)
    {
        goto fail;
    }

    free(signing_msg);
    free(inner);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    *out_len = total;
    return buf;

fail:
    free(signing_msg);
    free(inner);
    free(buf);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    return NULL;
}

int bm_pq_parse_broadcast(const unsigned char *object, size_t object_len,
                           uint64_t address_version, uint64_t stream,
                           const unsigned char id[BM_PQV5_ID_LEN],
                           struct bm_pq_broadcast_parsed *out)
{
    const unsigned char *plain;
    size_t plain_len;
    unsigned char expected_tag[32];
    unsigned char addr_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char addr_kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char *inner = NULL;
    unsigned char *signing_msg = NULL;
    size_t inner_len;
    size_t signing_len = 0;
    size_t sealed_len;
    size_t presig_len;
    unsigned char sig[BM_PQV5_SIG_LEN];
    unsigned char recomputed_id[BM_PQV5_ID_LEN];
    struct rbuf r;
    uint64_t sig_len_field;
    uint64_t len_field;
    int rc = -1;

    memset(out, 0, sizeof(*out));
    if (object_len < 8)
    {
        return -1;
    }
    plain = object + 8;
    plain_len = object_header_size(BM_PQ_BROADCAST_OBJECT_VERSION, stream) + 32;
    if (object_len < 8 + plain_len + BM_PQV5_SEAL_OVERHEAD)
    {
        return -1;
    }

    bm_pqv5_derive_secret_and_tag(address_version, stream, id, NULL, expected_tag);
    if (memcmp(plain + plain_len - 32, expected_tag, 32) != 0)
    {
        return -1;
    }
    if (bm_pqv5_address_kem_keypair(address_version, stream, id, addr_kem_pk, addr_kem_sk) != 0)
    {
        return -1;
    }

    sealed_len = object_len - 8 - plain_len;
    inner_len = sealed_len - BM_PQV5_SEAL_OVERHEAD;
    inner = malloc(inner_len);
    if (inner == NULL)
    {
        goto out;
    }
    if (bm_pqv5_open(addr_kem_sk, plain, plain_len, plain + plain_len, sealed_len, inner, &inner_len) != 0)
    {
        goto out;
    }

    r.p = inner;
    r.end = inner + inner_len;
    r.error = 0;
    out->from_address_version = r_varint(&r);
    out->from_stream = r_varint(&r);
    out->bitfield = r_u32(&r);
    r_bytes(&r, out->from_sig_pk, BM_PQV5_SIG_PK_LEN);
    r_bytes(&r, out->from_kem_pk, BM_PQV5_KEM_PK_LEN);
    out->nonce_trials_per_byte = r_varint(&r);
    out->payload_length_extra_bytes = r_varint(&r);
    out->encoding = r_varint(&r);

    len_field = r_varint(&r);
    if (r.error || len_field > (uint64_t)(r.end - r.p))
    {
        goto out;
    }
    out->message_len = (size_t)len_field;
    out->message = malloc(out->message_len + 1);
    if (out->message == NULL)
    {
        goto out;
    }
    r_bytes(&r, out->message, out->message_len);
    out->message[out->message_len] = '\0';

    presig_len = (size_t)(r.p - inner);
    sig_len_field = r_varint(&r);
    if (r.error || sig_len_field != BM_PQV5_SIG_LEN)
    {
        goto out;
    }
    r_bytes(&r, sig, sizeof(sig));
    if (r.error)
    {
        goto out;
    }

    signing_msg = build_signing_message(plain, plain_len, inner, presig_len, &signing_len);
    if (signing_msg == NULL ||
        bm_pqv5_verify(signing_msg, signing_len, sig, out->from_sig_pk) != 1)
    {
        goto out;
    }

    /* 送信元アドレス由来の鍵で開封できた以上、中の公開鍵もそのアドレスのものであるはず。
     * v4のbroadcast復号(core/broadcast_decrypt.c)と同じ整合性チェックを行う */
    bm_pqv5_calc_id(out->from_sig_pk, out->from_kem_pk, recomputed_id);
    if (memcmp(recomputed_id, id, BM_PQV5_ID_LEN) != 0)
    {
        goto out;
    }
    memcpy(out->from_id, recomputed_id, BM_PQV5_ID_LEN);
    rc = 0;

out:
    free(signing_msg);
    free(inner);
    OPENSSL_cleanse(addr_kem_sk, sizeof(addr_kem_sk));
    if (rc != 0)
    {
        bm_pq_broadcast_parsed_free(out);
    }
    return rc;
}

void bm_pq_broadcast_parsed_free(struct bm_pq_broadcast_parsed *parsed)
{
    free(parsed->message);
    parsed->message = NULL;
    parsed->message_len = 0;
}
