/*
 * src/pq/pq_object.c(v5のgetpubkey/pubkey/msg/broadcastオブジェクト)の検証。
 * DESIGN-PQ.md §7。
 *
 * 検証観点:
 *   - 組み立て→解析の往復で全フィールドが戻ること(v4のtests/test_message_builder.cと同じ趣旨)
 *   - 宛先違い(他人の鍵)では開けないこと=トライアル復号の空振り経路
 *   - オブジェクトヘッダ(expiresTime等)を差し替えた改竄を検出できること。
 *     v4のECIESはヘッダを認証しておらず署名検証まで進んで初めて分かるが、v5は
 *     AEADのAADにヘッダを入れているので復号の時点で落ちる。その差がここで確認できる
 *   - tagによる早期棄却が効いていること(pubkey/broadcast)
 *   - サイズがMAX_OBJECT_PAYLOAD_SIZE(2^18)に収まること
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/pq/address_v5.h"
#include "../src/pq/pq_object.h"

#define MAX_OBJECT_PAYLOAD_SIZE (1u << 18)

/* ビルダーはPoW前(nonce抜き)を返し、パーサはnonce込みを受け取るので、その変換 */
static unsigned char *with_nonce(const unsigned char *payload, size_t len, size_t *out_len)
{
    unsigned char *buf = malloc(len + 8);
    if (buf == NULL)
    {
        return NULL;
    }
    memset(buf, 0, 8);
    memcpy(buf + 8, payload, len);
    *out_len = len + 8;
    return buf;
}

static void fill_sender(struct bm_pq_sender_info *info, const struct bm_pqv5_identity *id)
{
    memset(info, 0, sizeof(*info));
    info->identity = id;
    info->bitfield = 2;
    info->nonce_trials_per_byte = 1000;
    info->payload_length_extra_bytes = 1000;
}

static int test_getpubkey(const struct bm_pqv5_identity *alice)
{
    unsigned char *payload;
    size_t len = 0;
    unsigned char tag[32];
    int rc = 1;

    payload = bm_pq_build_getpubkey(alice->version, alice->stream, alice->id, 1234567890, &len);
    if (payload == NULL)
    {
        fprintf(stderr, "FAIL: build getpubkey\n");
        return 1;
    }
    bm_pqv5_derive_secret_and_tag(alice->version, alice->stream, alice->id, NULL, tag);
    if (len < 32 || memcmp(payload + len - 32, tag, 32) != 0)
    {
        fprintf(stderr, "FAIL: getpubkey tag mismatch\n");
        goto out;
    }
    /* PyBitmessageのcheckGetpubkeyが要求する下限(42byte)を満たすこと */
    if (len + 8 < 42)
    {
        fprintf(stderr, "FAIL: getpubkey too short for legacy relays (%zu)\n", len + 8);
        goto out;
    }
    rc = 0;

out:
    free(payload);
    return rc;
}

static int test_pubkey(const struct bm_pqv5_identity *alice, const struct bm_pqv5_identity *bob)
{
    struct bm_pq_sender_info info;
    struct bm_pq_pubkey_parsed parsed;
    unsigned char *payload;
    unsigned char *object;
    size_t len = 0;
    size_t object_len = 0;
    int rc = 1;

    fill_sender(&info, alice);
    payload = bm_pq_build_pubkey(&info, 1234567890, &len);
    if (payload == NULL)
    {
        fprintf(stderr, "FAIL: build pubkey\n");
        return 1;
    }
    object = with_nonce(payload, len, &object_len);
    free(payload);
    if (object == NULL)
    {
        return 1;
    }
    if (object_len > MAX_OBJECT_PAYLOAD_SIZE)
    {
        fprintf(stderr, "FAIL: pubkey object exceeds 2^18 (%zu)\n", object_len);
        goto out;
    }

    if (bm_pq_parse_pubkey(object, object_len, alice->version, alice->stream, alice->id, &parsed) != 0)
    {
        fprintf(stderr, "FAIL: parse pubkey\n");
        goto out;
    }
    if (memcmp(parsed.sig_pk, alice->sig_pk, BM_PQV5_SIG_PK_LEN) != 0 ||
        memcmp(parsed.kem_pk, alice->kem_pk, BM_PQV5_KEM_PK_LEN) != 0 ||
        parsed.bitfield != info.bitfield ||
        parsed.nonce_trials_per_byte != info.nonce_trials_per_byte ||
        parsed.payload_length_extra_bytes != info.payload_length_extra_bytes)
    {
        fprintf(stderr, "FAIL: parsed pubkey fields differ\n");
        goto out;
    }

    /* 別人のアドレスを候補にした場合はtagで即棄却されること */
    if (bm_pq_parse_pubkey(object, object_len, bob->version, bob->stream, bob->id, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: pubkey parsed with the wrong candidate address\n");
        goto out;
    }

    /* ヘッダ(expiresTime)の改竄はAAD不一致で落ちること */
    object[8] ^= 0x01;
    if (bm_pq_parse_pubkey(object, object_len, alice->version, alice->stream, alice->id, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: pubkey with a tampered header was accepted\n");
        goto out;
    }
    object[8] ^= 0x01;

    /* 封緘本体の改竄 */
    object[object_len - 1] ^= 0x01;
    if (bm_pq_parse_pubkey(object, object_len, alice->version, alice->stream, alice->id, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: pubkey with a tampered body was accepted\n");
        goto out;
    }
    rc = 0;

out:
    free(object);
    return rc;
}

static int test_msg(const struct bm_pqv5_identity *alice, const struct bm_pqv5_identity *bob)
{
    struct bm_pq_sender_info info;
    struct bm_pq_msg_parsed parsed;
    unsigned char *payload;
    unsigned char *object;
    size_t len = 0;
    size_t object_len = 0;
    const unsigned char body[] = "Subject:pq test\nBody:hello post-quantum world";
    const unsigned char ack[] = { 0x00, 0x01, 0x02, 0x03 };
    int rc = 1;

    fill_sender(&info, alice);
    payload = bm_pq_build_msg(&info, bob->stream, bob->id, bob->kem_pk, 2, body, sizeof(body) - 1,
                              ack, sizeof(ack), 1234567890, &len);
    if (payload == NULL)
    {
        fprintf(stderr, "FAIL: build msg\n");
        return 1;
    }
    object = with_nonce(payload, len, &object_len);
    free(payload);
    if (object == NULL)
    {
        return 1;
    }
    if (object_len > MAX_OBJECT_PAYLOAD_SIZE)
    {
        fprintf(stderr, "FAIL: msg object exceeds 2^18 (%zu)\n", object_len);
        goto out;
    }

    if (bm_pq_parse_msg(object, object_len, bob->kem_sk, &parsed) != 0)
    {
        fprintf(stderr, "FAIL: parse msg\n");
        goto out;
    }
    if (parsed.from_address_version != alice->version || parsed.from_stream != alice->stream ||
        memcmp(parsed.from_id, alice->id, BM_PQV5_ID_LEN) != 0 ||
        memcmp(parsed.to_id, bob->id, BM_PQV5_ID_LEN) != 0 ||
        parsed.encoding != 2 || parsed.message_len != sizeof(body) - 1 ||
        memcmp(parsed.message, body, sizeof(body) - 1) != 0 ||
        parsed.ack_len != sizeof(ack) || memcmp(parsed.ack, ack, sizeof(ack)) != 0)
    {
        fprintf(stderr, "FAIL: parsed msg fields differ\n");
        bm_pq_msg_parsed_free(&parsed);
        goto out;
    }
    bm_pq_msg_parsed_free(&parsed);

    /* 自分宛てでないmsgは開封できない(受信側の総当たりが空振りする経路) */
    if (bm_pq_parse_msg(object, object_len, alice->kem_sk, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: msg opened with the wrong key\n");
        bm_pq_msg_parsed_free(&parsed);
        goto out;
    }

    /* ヘッダ改竄 */
    object[8] ^= 0x01;
    if (bm_pq_parse_msg(object, object_len, bob->kem_sk, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: msg with a tampered header was accepted\n");
        bm_pq_msg_parsed_free(&parsed);
        goto out;
    }
    object[8] ^= 0x01;

    /* PoW nonceは署名にもAADにも含まれないので、書き換えても復号・検証は通る
     * (PoW後にnonceが前置される以上、ここが通らないと成立しない) */
    object[0] = 0xff;
    if (bm_pq_parse_msg(object, object_len, bob->kem_sk, &parsed) != 0)
    {
        fprintf(stderr, "FAIL: msg rejected after changing the PoW nonce\n");
        goto out;
    }
    bm_pq_msg_parsed_free(&parsed);
    rc = 0;

out:
    free(object);
    return rc;
}

static int test_broadcast(const struct bm_pqv5_identity *alice, const struct bm_pqv5_identity *bob)
{
    struct bm_pq_sender_info info;
    struct bm_pq_broadcast_parsed parsed;
    unsigned char *payload;
    unsigned char *object;
    size_t len = 0;
    size_t object_len = 0;
    const unsigned char body[] = "Subject:bc\nBody:broadcast body";
    int rc = 1;

    fill_sender(&info, alice);
    payload = bm_pq_build_broadcast(&info, 2, body, sizeof(body) - 1, 1234567890, &len);
    if (payload == NULL)
    {
        fprintf(stderr, "FAIL: build broadcast\n");
        return 1;
    }
    object = with_nonce(payload, len, &object_len);
    free(payload);
    if (object == NULL)
    {
        return 1;
    }

    if (bm_pq_parse_broadcast(object, object_len, alice->version, alice->stream, alice->id, &parsed) != 0)
    {
        fprintf(stderr, "FAIL: parse broadcast\n");
        goto out;
    }
    if (parsed.message_len != sizeof(body) - 1 || memcmp(parsed.message, body, sizeof(body) - 1) != 0 ||
        memcmp(parsed.from_id, alice->id, BM_PQV5_ID_LEN) != 0)
    {
        fprintf(stderr, "FAIL: parsed broadcast fields differ\n");
        bm_pq_broadcast_parsed_free(&parsed);
        goto out;
    }
    bm_pq_broadcast_parsed_free(&parsed);

    /* 購読していない(=別アドレスを候補にした)場合はtagで即棄却 */
    if (bm_pq_parse_broadcast(object, object_len, bob->version, bob->stream, bob->id, &parsed) == 0)
    {
        fprintf(stderr, "FAIL: broadcast parsed with the wrong subscription\n");
        bm_pq_broadcast_parsed_free(&parsed);
        goto out;
    }
    rc = 0;

out:
    free(object);
    return rc;
}

int main(void)
{
    struct bm_pqv5_identity alice;
    struct bm_pqv5_identity bob;

    if (bm_pqv5_identity_generate_deterministic("alice v5", 1, 0, 0, BM_PQV5_SEARCH_X25519, &alice) != 0 ||
        bm_pqv5_identity_generate_deterministic("bob v5", 1, 0, 0, BM_PQV5_SEARCH_X25519, &bob) != 0)
    {
        fprintf(stderr, "FAIL: identity generation\n");
        return 1;
    }
    if (test_getpubkey(&alice) != 0)
    {
        return 1;
    }
    if (test_pubkey(&alice, &bob) != 0)
    {
        return 1;
    }
    if (test_msg(&alice, &bob) != 0)
    {
        return 1;
    }
    if (test_broadcast(&alice, &bob) != 0)
    {
        return 1;
    }
    printf("test_pq_object: OK\n");
    return 0;
}
