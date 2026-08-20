/*
 * core/message_builder.c のテスト。組み立てたobjectを自前でパースし直し、
 * ECIES復号・署名検証・各フィールドの中身が期待通りであることを確認する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/hash.h"
#include "../src/common/varint.h"
#include "../src/core/address.h"
#include "../src/core/crypto.h"
#include "../src/core/message_builder.h"
#include "../src/infra/object.h"

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void make_identity(const char *passphrase, struct bm_identity_info *out_id,
                           unsigned char out_ripe[20])
{
    struct bm_generated_address gen;
    if (bm_address_generate_deterministic(passphrase, 1, &gen) != 0)
    {
        fprintf(stderr, "FATAL: generate_deterministic failed\n");
        exit(EXIT_FAILURE);
    }
    memset(out_id, 0, sizeof(*out_id));
    out_id->address_version = 4;
    out_id->stream = 1;
    memcpy(out_id->pub_signing, gen.pub_signing, 65);
    memcpy(out_id->pub_encryption, gen.pub_encryption, 65);
    memcpy(out_id->priv_signing, gen.priv_signing, 32);
    out_id->nonce_trials_per_byte = 1000;
    out_id->payload_length_extra_bytes = 1000;
    out_id->does_ack = 1;
    memcpy(out_ripe, gen.ripe, 20);
}

static uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_be64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
    {
        v = (v << 8) | p[i];
    }
    return v;
}

static void test_msg(void)
{
    struct bm_identity_info from;
    unsigned char from_ripe[20];
    make_identity("message_builder test sender", &from, from_ripe);

    struct bm_identity_info to;
    unsigned char to_ripe[20];
    make_identity("message_builder test receiver", &to, to_ripe);

    const char *subject = "hello";
    const char *body = "this is a test message body";

    size_t obj_len = 0;
    unsigned char *obj = bm_build_msg(&from, /*to_stream=*/1, to_ripe, to.pub_encryption,
                                       subject, body, NULL, 0, /*expires_time=*/1234567890, &obj_len);
    CHECK(obj != NULL, "bm_build_msg returned NULL");
    if (obj == NULL)
    {
        return;
    }

    /* ヘッダを検証 */
    CHECK(read_be64(obj) == 1234567890ULL, "msg expires_time mismatch");
    CHECK(read_be32(obj + 8) == BM_OBJECT_MSG, "msg objectType mismatch");
    size_t offset = 12;
    uint64_t version = 0;
    offset += bm_varint_decode(obj + offset, obj_len - offset, &version);
    CHECK(version == 1, "msg objectVersion should be 1");
    uint64_t stream = 0;
    offset += bm_varint_decode(obj + offset, obj_len - offset, &stream);
    CHECK(stream == 1, "msg header stream should be toStream(1)");

    size_t header_len = offset;
    const unsigned char *ciphertext = obj + header_len;
    size_t ciphertext_len = obj_len - header_len;

    /* bm_identity_infoは公開鍵のみを保持する設計のため、復号には秘密鍵が別途必要。
     * ここでは受信者と同じpassphraseから再導出する(make_identity内で使ったのと同じ関数)。 */
    struct bm_generated_address to_gen;
    bm_address_generate_deterministic("message_builder test receiver", 1, &to_gen);

    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    int rc = bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, to_gen.priv_encryption, &decrypted, &decrypted_len);
    CHECK(rc == 0, "msg ecies_decrypt failed");
    if (rc != 0)
    {
        free(obj);
        return;
    }

    size_t p = 0;
    uint64_t from_ver = 0, from_stream = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &from_ver);
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &from_stream);
    CHECK(from_ver == 4, "msg fromAddressVersion mismatch");
    CHECK(from_stream == 1, "msg fromStream mismatch");

    uint32_t bitfield = read_be32(decrypted + p);
    p += 4;
    CHECK(bitfield == 1, "msg bitfield (doesAck) mismatch");

    CHECK(memcmp(decrypted + p, from.pub_signing + 1, 64) == 0, "msg fromSigningPubkey mismatch");
    p += 64;
    CHECK(memcmp(decrypted + p, from.pub_encryption + 1, 64) == 0, "msg fromEncryptionPubkey mismatch");
    p += 64;

    uint64_t noncetrials = 0, extrabytes = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &noncetrials);
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &extrabytes);
    CHECK(noncetrials == 1000, "msg nonceTrialsPerByte mismatch");
    CHECK(extrabytes == 1000, "msg payloadLengthExtraBytes mismatch");

    CHECK(memcmp(decrypted + p, to_ripe, 20) == 0, "msg toRipe mismatch");
    p += 20;

    uint64_t encoding = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &encoding);
    CHECK(encoding == 2, "msg encoding should be SIMPLE(2)");

    uint64_t msg_len = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &msg_len);
    char expected_encoded[256];
    snprintf(expected_encoded, sizeof(expected_encoded), "Subject:%s\nBody:%s", subject, body);
    CHECK(msg_len == strlen(expected_encoded), "msg encoded length mismatch");
    CHECK(memcmp(decrypted + p, expected_encoded, msg_len) == 0, "msg encoded content mismatch");
    p += msg_len;

    uint64_t ack_len = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &ack_len);
    CHECK(ack_len == 0, "msg ackPayload should be empty");
    p += ack_len;

    size_t presig_offset = p;
    uint64_t sig_len = 0;
    p += bm_varint_decode(decrypted + p, decrypted_len - p, &sig_len);
    const unsigned char *sig = decrypted + p;

    /* 署名対象 = ヘッダ(平文) || payload(署名を除く) */
    unsigned char *to_sign = malloc(header_len + presig_offset);
    memcpy(to_sign, obj, header_len);
    memcpy(to_sign + header_len, decrypted, presig_offset);
    int verify_ok = bm_crypto_verify(to_sign, header_len + presig_offset, sig, sig_len, from.pub_signing);
    CHECK(verify_ok == 1, "msg signature verification failed");
    free(to_sign);

    free(decrypted);
    free(obj);

    if (failures == 0)
    {
        printf("OK: msg build -> decrypt -> field check -> signature verify\n");
    }
}

static void test_getpubkey(void)
{
    unsigned char ripe[20];
    memset(ripe, 0x42, sizeof(ripe));

    size_t len3 = 0;
    unsigned char *obj3 = bm_build_getpubkey(3, 1, ripe, 1000, &len3);
    CHECK(obj3 != NULL, "getpubkey v3 build failed");
    if (obj3 != NULL)
    {
        CHECK(read_be32(obj3 + 8) == BM_OBJECT_GETPUBKEY, "getpubkey v3 objectType");
        size_t off = 12;
        uint64_t ver = 0;
        off += bm_varint_decode(obj3 + off, len3 - off, &ver);
        CHECK(ver == 3, "getpubkey v3 version");
        uint64_t stream = 0;
        off += bm_varint_decode(obj3 + off, len3 - off, &stream);
        CHECK(len3 - off == 20, "getpubkey v3 payload should be raw ripe(20byte)");
        CHECK(memcmp(obj3 + off, ripe, 20) == 0, "getpubkey v3 ripe mismatch");
        free(obj3);
    }

    size_t len4 = 0;
    unsigned char *obj4 = bm_build_getpubkey(4, 1, ripe, 1000, &len4);
    CHECK(obj4 != NULL, "getpubkey v4 build failed");
    if (obj4 != NULL)
    {
        size_t off = 12;
        uint64_t ver = 0;
        off += bm_varint_decode(obj4 + off, len4 - off, &ver);
        uint64_t stream = 0;
        off += bm_varint_decode(obj4 + off, len4 - off, &stream);
        CHECK(len4 - off == 32, "getpubkey v4 payload should be tag(32byte)");

        /* tag = SHA512(varint(4)||varint(1)||ripe)[32:64] を独自に再計算して照合
         * (varint(4)=0x04, varint(1)=0x01は1byteエンコードなので直接埋め込む) */
        unsigned char concat[2 + 20];
        size_t clen = 0;
        concat[clen++] = 4;
        concat[clen++] = 1;
        memcpy(concat + clen, ripe, 20);
        clen += 20;
        unsigned char full[64];
        bm_sha512(concat, clen, full);
        CHECK(memcmp(obj4 + off, full + 32, 32) == 0, "getpubkey v4 tag mismatch");
        free(obj4);
    }

    if (failures == 0)
    {
        printf("OK: getpubkey v3/v4 build\n");
    }
}

static void test_pubkey_v3(void)
{
    struct bm_identity_info id;
    unsigned char ripe[20];
    make_identity("pubkey v3 test identity", &id, ripe);
    id.address_version = 3;

    size_t len = 0;
    unsigned char *obj = bm_build_pubkey_v3(&id, 2000000000, &len);
    CHECK(obj != NULL, "pubkey v3 build failed");
    if (obj == NULL)
    {
        return;
    }

    size_t presig_len; /* 署名対象の長さを後で確定させる */
    size_t off = 12;
    uint64_t ver = 0, stream = 0;
    off += bm_varint_decode(obj + off, len - off, &ver);
    off += bm_varint_decode(obj + off, len - off, &stream);
    CHECK(ver == 3, "pubkey v3 version");

    off += 4; /* bitfield */
    CHECK(memcmp(obj + off, id.pub_signing + 1, 64) == 0, "pubkey v3 signingPubkey mismatch");
    off += 64;
    CHECK(memcmp(obj + off, id.pub_encryption + 1, 64) == 0, "pubkey v3 encryptionPubkey mismatch");
    off += 64;
    uint64_t nt = 0, eb = 0;
    off += bm_varint_decode(obj + off, len - off, &nt);
    off += bm_varint_decode(obj + off, len - off, &eb);
    CHECK(nt == 1000 && eb == 1000, "pubkey v3 nonce/extra bytes mismatch");

    presig_len = off;
    uint64_t sig_len = 0;
    off += bm_varint_decode(obj + off, len - off, &sig_len);
    int ok = bm_crypto_verify(obj, presig_len, obj + off, sig_len, id.pub_signing);
    CHECK(ok == 1, "pubkey v3 signature verification failed");

    free(obj);
    if (failures == 0)
    {
        printf("OK: pubkey v3 build -> field check -> signature verify\n");
    }
}

int main(void)
{
    test_msg();
    test_getpubkey();
    test_pubkey_v3();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
