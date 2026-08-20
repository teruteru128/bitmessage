#include "trial_decrypt.h"

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

/*
 * BITMESSAGE_ENCODING_SIMPLE("Subject:...\nBody:...")のデコード。
 * PyBitmessage helper_msgcoding.py の decodeSimple と同じ規則:
 * "\nBody:"を探し、見つかった位置が1より大きければ分割(subjectは最初の行のみ、最大500byte)。
 * 見つからなければsubject=""、body=data全体。
 */
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
        /* 最初の改行までに切り詰める(ヘッダ偽装対策、decodeSimpleのsplitlines()[0]相当) */
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

int bm_trial_decrypt_msg(bm_keyring_t *kr, const unsigned char *object, size_t object_len,
                          struct bm_decoded_msg *out)
{
    struct bm_object_header hdr;
    if (bm_object_parse_header(object, object_len, &hdr) != 0)
    {
        return -1;
    }
    if (hdr.object_type != BM_OBJECT_MSG || hdr.version != 1)
    {
        return -1;
    }

    const unsigned char *ciphertext = object + hdr.header_len;
    size_t ciphertext_len = object_len - hdr.header_len;

    /* keyring内のunlocked鍵全てでトライアル復号を試みる */
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    struct bm_unlocked_identity matched;
    int found = 0;
    while (cur != NULL)
    {
        if (bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, cur->priv_encryption, &decrypted, &decrypted_len) == 0)
        {
            matched = *cur;
            matched.next = NULL;
            found = 1;
            break;
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&kr->lock);

    if (!found)
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
    p += 4; /* bitfield: v1では内容を検証しない */

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

    if (p + 20 > decrypted_len)
    {
        goto fail;
    }
    /* なりすまし転送対策(§5.3): 復号できてもtoRipeが自分のものでなければ拒否 */
    if (memcmp(decrypted + p, matched.ripe, 20) != 0)
    {
        goto fail;
    }
    p += 20;

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

    uint64_t ack_len = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &ack_len);
    if (consumed == 0 || p + consumed + ack_len > decrypted_len)
    {
        goto fail;
    }
    p += consumed;
    const unsigned char *ack_data = decrypted + p;
    p += ack_len;

    size_t presig_offset = p;
    uint64_t sig_len = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &sig_len);
    if (consumed == 0 || p + consumed + sig_len > decrypted_len)
    {
        goto fail;
    }
    p += consumed;
    const unsigned char *sig = decrypted + p;

    /* 署名対象 = ヘッダ(平文、nonce抜き) || payload(署名を除く)。§5.3 */
    size_t header_no_nonce_len = hdr.header_len - 8;
    unsigned char *to_sign = malloc(header_no_nonce_len + presig_offset);
    memcpy(to_sign, object + 8, header_no_nonce_len);
    memcpy(to_sign + header_no_nonce_len, decrypted, presig_offset);
    int verify_ok = bm_crypto_verify(to_sign, header_no_nonce_len + presig_offset, sig, sig_len, from_pub_signing);
    free(to_sign);
    if (verify_ok != 1)
    {
        goto fail;
    }

    memset(out, 0, sizeof(*out));
    out->from_address_version = from_ver;
    out->from_stream = from_stream;

    unsigned char from_ripe[20];
    bm_address_calc_ripe(from_pub_signing, from_pub_encryption, from_ripe);
    char *from_addr_str = bm_address_encode(from_ver, from_stream, from_ripe, 20);
    if (from_addr_str != NULL)
    {
        strncpy(out->from_address, from_addr_str, sizeof(out->from_address) - 1);
        free(from_addr_str);
    }
    strncpy(out->to_address, matched.address, sizeof(out->to_address) - 1);

    if (encoding == 2)
    {
        decode_simple(msg_data, msg_len, &out->subject, &out->body);
    }
    else
    {
        /* TRIVIAL(1)またはEXTENDED(3、§8-8で未対応)は本文をそのままbodyとして保持する */
        out->subject = dup_bytes_as_cstr(NULL, 0);
        out->body = dup_bytes_as_cstr(msg_data, msg_len);
    }

    if (ack_len > 0)
    {
        out->ack_payload = malloc(ack_len);
        memcpy(out->ack_payload, ack_data, ack_len);
        out->ack_payload_len = ack_len;
    }

    OPENSSL_cleanse(decrypted, decrypted_len);
    free(decrypted);
    OPENSSL_cleanse(&matched, sizeof(matched));
    return 0;

fail:
    if (decrypted != NULL)
    {
        OPENSSL_cleanse(decrypted, decrypted_len);
        free(decrypted);
    }
    OPENSSL_cleanse(&matched, sizeof(matched));
    return -1;
}

void bm_decoded_msg_free(struct bm_decoded_msg *msg)
{
    free(msg->subject);
    free(msg->body);
    free(msg->ack_payload);
    memset(msg, 0, sizeof(*msg));
}

int bm_trial_decrypt_and_store(bm_keyring_t *kr, sqlite3 *db,
                                const unsigned char *object, size_t object_len)
{
    struct bm_decoded_msg decoded;
    if (bm_trial_decrypt_msg(kr, object, object_len, &decoded) != 0)
    {
        return -1;
    }

    unsigned char msg_id[32];
    bm_inventory_hash(object, object_len, msg_id);

    int rc = bm_messages_store_insert_inbox(db, msg_id, decoded.to_address, decoded.from_address,
                                             decoded.subject, decoded.body, (int64_t)time(NULL));
    bm_decoded_msg_free(&decoded);
    return rc;
}

void *bm_trial_decrypt_thread(void *arg)
{
    (void)arg;
    /* TODO(§1.1 decrypt_worker_thread): decrypt_request_queueをpopし、object_pool.dbから
     * payloadを引いてbm_trial_decrypt_and_storeを呼ぶループを実装する(object_store.c/
     * infra層のキュー結線が前提)。中核ロジック(bm_trial_decrypt_msg/_and_store)は
     * 実装・テスト済みなので、ここは配線するだけで良い。 */
    return NULL;
}
