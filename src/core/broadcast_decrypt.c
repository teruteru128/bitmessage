#include "broadcast_decrypt.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/hash.h"
#include "../common/varint.h"
#include "../infra/object.h"
#include "address.h"
#include "crypto.h"
#include "messages_store.h"

static char *dup_bytes_as_cstr(const unsigned char *data, size_t len)
{
    char *out = malloc(len + 1);
    if (out == NULL)
    {
        return NULL;
    }
    if (len > 0)
    {
        memcpy(out, data, len);
    }
    out[len] = '\0';
    return out;
}

/* trial_decrypt.cのdecode_simpleと同一規則(§8 BITMESSAGE_ENCODING_SIMPLE) */
static void decode_simple(const unsigned char *data, size_t len, char **out_subject, char **out_body)
{
    static const char needle[] = "\nBody:";
    const size_t needle_len = 6;
    size_t body_idx = (size_t)-1;

    if (len >= needle_len)
    {
        for (size_t i = 0; i + needle_len <= len; i++)
        {
            if (memcmp(data + i, needle, needle_len) == 0)
            {
                body_idx = i;
                break;
            }
        }
    }

    if (body_idx != (size_t)-1 && body_idx > 1)
    {
        const size_t subject_prefix_len = 8; /* "Subject:" */
        size_t subject_len = (subject_prefix_len <= body_idx) ? (body_idx - subject_prefix_len) : 0;
        if (subject_len > 500)
        {
            subject_len = 500;
        }
        size_t first_line_len = subject_len;
        for (size_t i = 0; i < subject_len; i++)
        {
            if (data[subject_prefix_len + i] == '\n')
            {
                first_line_len = i;
                break;
            }
        }
        *out_subject = dup_bytes_as_cstr(data + subject_prefix_len, first_line_len);

        size_t body_start = body_idx + needle_len;
        *out_body = dup_bytes_as_cstr(data + body_start, len - body_start);
    }
    else
    {
        *out_subject = dup_bytes_as_cstr(NULL, 0);
        *out_body = dup_bytes_as_cstr(data, len);
    }
}

int bm_trial_decrypt_broadcast(const unsigned char *object, size_t object_len,
                                uint64_t candidate_version, uint64_t candidate_stream,
                                const unsigned char candidate_ripe[20],
                                struct bm_decoded_broadcast *out)
{
    struct bm_object_header hdr;
    if (bm_object_parse_header(object, object_len, &hdr) != 0)
    {
        return -1;
    }
    if (hdr.object_type != BM_OBJECT_BROADCAST || (hdr.version != 4 && hdr.version != 5))
    {
        return -1;
    }

    unsigned char secret[32];
    unsigned char expected_tag[32];
    bm_address_derive_secret_and_tag(candidate_version, candidate_stream, candidate_ripe, secret, expected_tag);

    size_t offset = hdr.header_len;
    if (hdr.version == 5)
    {
        if (offset + 32 > object_len)
        {
            OPENSSL_cleanse(secret, sizeof(secret));
            return -1;
        }
        if (memcmp(object + offset, expected_tag, 32) != 0)
        {
            OPENSSL_cleanse(secret, sizeof(secret));
            return -1; /* candidate宛てではない(tag不一致、復号を試みるまでもない) */
        }
        offset += 32;
    }

    const unsigned char *ciphertext = object + offset;
    size_t ciphertext_len = object_len - offset;

    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    int rc = bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, secret, &decrypted, &decrypted_len);
    OPENSSL_cleanse(secret, sizeof(secret));
    if (rc != 0)
    {
        return -1;
    }

    size_t p = 0;
    size_t consumed;
    uint64_t from_ver = 0;
    uint64_t from_stream = 0;

    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &from_ver);
    if (consumed == 0)
    {
        goto fail;
    }
    p += consumed;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &from_stream);
    if (consumed == 0)
    {
        goto fail;
    }
    p += consumed;

    if (p + 4 + 64 + 64 > decrypted_len)
    {
        goto fail;
    }
    p += 4; /* bitfield: v1では内容を検証しない(trial_decrypt.cと同じ簡略化) */

    unsigned char from_pub_signing[65];
    unsigned char from_pub_encryption[65];
    from_pub_signing[0] = 0x04;
    memcpy(from_pub_signing + 1, decrypted + p, 64);
    p += 64;
    from_pub_encryption[0] = 0x04;
    memcpy(from_pub_encryption + 1, decrypted + p, 64);
    p += 64;

    if (from_ver >= 3)
    {
        uint64_t nonce_trials = 0;
        uint64_t extra_bytes = 0;
        consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &nonce_trials);
        if (consumed == 0)
        {
            goto fail;
        }
        p += consumed;
        consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &extra_bytes);
        if (consumed == 0)
        {
            goto fail;
        }
        p += consumed;
    }

    uint64_t encoding = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &encoding);
    if (consumed == 0)
    {
        goto fail;
    }
    p += consumed;

    uint64_t msg_len = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &msg_len);
    if (consumed == 0 || p + consumed + msg_len > decrypted_len)
    {
        goto fail;
    }
    p += consumed;
    const unsigned char *msg_data = decrypted + p;
    p += msg_len;

    size_t presig_offset = p;
    uint64_t sig_len = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &sig_len);
    if (consumed == 0 || p + consumed + sig_len > decrypted_len)
    {
        goto fail;
    }
    p += consumed;
    const unsigned char *sig = decrypted + p;

    /* 署名対象 = 平文部(ヘッダ+tag、nonce抜き) || decrypted(署名を除く)。§5.4 */
    size_t header_no_nonce_len = hdr.header_len - 8;
    size_t tag_len = (hdr.version == 5) ? 32 : 0;
    unsigned char *to_sign = malloc(header_no_nonce_len + tag_len + presig_offset);
    memcpy(to_sign, object + 8, header_no_nonce_len);
    if (tag_len > 0)
    {
        memcpy(to_sign + header_no_nonce_len, object + hdr.header_len, 32);
    }
    memcpy(to_sign + header_no_nonce_len + tag_len, decrypted, presig_offset);
    int verify_ok =
        bm_crypto_verify(to_sign, header_no_nonce_len + tag_len + presig_offset, sig, sig_len, from_pub_signing);
    free(to_sign);
    if (verify_ok != 1)
    {
        goto fail;
    }

    /* 整合性チェック: 復号できたpubkeyから計算したripeがcandidateと一致するはず(pubkey v4の
     * 検証と同じ考え方、鍵は合っていたが偽装されたpubkeyという可能性を排除する) */
    unsigned char computed_ripe[20];
    bm_address_calc_ripe(from_pub_signing, from_pub_encryption, computed_ripe);
    if (memcmp(computed_ripe, candidate_ripe, 20) != 0)
    {
        goto fail;
    }

    memset(out, 0, sizeof(*out));
    out->from_address_version = from_ver;
    out->from_stream = from_stream;
    char *from_addr_str = bm_address_encode(from_ver, from_stream, computed_ripe, 20);
    if (from_addr_str != NULL)
    {
        strncpy(out->from_address, from_addr_str, sizeof(out->from_address) - 1);
        free(from_addr_str);
    }

    if (encoding == 2)
    {
        decode_simple(msg_data, msg_len, &out->subject, &out->body);
    }
    else
    {
        out->subject = dup_bytes_as_cstr(NULL, 0);
        out->body = dup_bytes_as_cstr(msg_data, msg_len);
    }

    OPENSSL_cleanse(decrypted, decrypted_len);
    free(decrypted);
    return 0;

fail:
    if (decrypted != NULL)
    {
        OPENSSL_cleanse(decrypted, decrypted_len);
        free(decrypted);
    }
    return -1;
}

void bm_decoded_broadcast_free(struct bm_decoded_broadcast *msg)
{
    free(msg->subject);
    free(msg->body);
    memset(msg, 0, sizeof(*msg));
}

int bm_trial_decrypt_broadcast_and_store(sqlite3 *messages_db, const unsigned char *object, size_t object_len,
                                          uint64_t candidate_version, uint64_t candidate_stream,
                                          const unsigned char candidate_ripe[20])
{
    struct bm_decoded_broadcast decoded;
    if (bm_trial_decrypt_broadcast(object, object_len, candidate_version, candidate_stream, candidate_ripe,
                                    &decoded) != 0)
    {
        return -1;
    }

    unsigned char msg_id[32];
    bm_inventory_hash(object, object_len, msg_id);

    /* broadcastには単一の宛先アドレスが無いため、PyBitmessageに倣いto_address=from_addressを
     * 入れて「これはbroadcastである」ことをinbox上で見分けられるようにする(§5.4) */
    int rc = bm_messages_store_insert_inbox(messages_db, msg_id, decoded.from_address, decoded.from_address,
                                             decoded.subject, decoded.body, (int64_t)time(NULL));
    bm_decoded_broadcast_free(&decoded);
    return rc;
}
