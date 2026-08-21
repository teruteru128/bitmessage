#include "send_pipeline.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../infra/protocol.h"
#include "../pow/pow_engine.h"
#include "address.h"
#include "message_builder.h"
#include "messages_store.h"
#include "pubkey_cache.h"

/* ackobject自体のPoW難易度。誰宛でもない匿名objectとして偽装するため、宛先固有の難易度
 * ではなくネットワーク既定値(PyBitmessage networkDefaultProofOfWorkNonceTrialsPerByte等)を使う */
#define BM_ACK_NONCE_TRIALS_PER_BYTE 1000
#define BM_ACK_PAYLOAD_LENGTH_EXTRA_BYTES 1000

static void pack_be64(unsigned char out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        out[i] = (unsigned char)((v >> (56 - 8 * i)) & 0xff);
    }
}

/*
 * §5.5 generateFullAckMessage相当。bm_build_ack_objectが作るackobject本体(type/version/
 * stream/data)にexpiresTimeを付けてPoWし、nonce付きの完成object(*out_object、§5.0形式)と、
 * それをさらにP2P "object"パケットとして包んだもの(*out_packet、msgのackPayloadへ平文埋め込み
 * 用。受信側が復号後そのままソケットへ書き込める形)の両方を作る。
 */
static int generate_full_ack(int stealth_level, uint64_t stream, uint64_t expires_time, uint64_t ttl_seconds,
                              unsigned char **out_object, size_t *out_object_len,
                              unsigned char **out_packet, size_t *out_packet_len)
{
    size_t ack_body_len = 0;
    unsigned char *ack_body = bm_build_ack_object(stealth_level, stream, &ack_body_len);
    if (ack_body == NULL)
    {
        return -1;
    }

    size_t payload_len = 8 + ack_body_len;
    unsigned char *payload = malloc(payload_len);
    if (payload == NULL)
    {
        free(ack_body);
        return -1;
    }
    pack_be64(payload, expires_time);
    memcpy(payload + 8, ack_body, ack_body_len);
    free(ack_body);

    uint64_t target = bm_pow_get_target(payload_len, ttl_seconds,
                                         BM_ACK_NONCE_TRIALS_PER_BYTE, BM_ACK_PAYLOAD_LENGTH_EXTRA_BYTES);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    if (object == NULL)
    {
        free(payload);
        return -1;
    }
    pack_be64(object, nonce);
    memcpy(object + 8, payload, payload_len);
    free(payload);

    size_t packet_len = 0;
    unsigned char *packet = bm_create_packet("object", object, object_len, &packet_len);
    if (packet == NULL)
    {
        free(object);
        return -1;
    }

    *out_object = object;
    *out_object_len = object_len;
    *out_packet = packet;
    *out_packet_len = packet_len;
    return 0;
}

int bm_send_pipeline_send_message(bm_keyring_t *kr, sqlite3 *identity_db, sqlite3 *messages_db,
                                   const char *from_address, const char *to_address,
                                   const unsigned char to_pub_encryption[65],
                                   const char *subject, const char *body,
                                   uint64_t ttl_seconds, int ack_stealth_level,
                                   unsigned char **out_object, size_t *out_object_len)
{
    struct bm_unlocked_identity from_id;
    if (!bm_keyring_find_by_address(kr, from_address, &from_id))
    {
        return -1; /* fromアドレスがunlockされていない */
    }

    uint64_t to_version = 0;
    uint64_t to_stream = 0;
    unsigned char to_ripe[BM_RIPE_LEN];
    if (bm_address_decode(to_address, &to_version, &to_stream, to_ripe) != 0)
    {
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }
    (void)to_version; /* msgの共通ヘッダstreamにはtoStreamだけが必要(§5.3) */

    /* to_pub_encryptionが指定されなければpubkey_cacheから引く */
    unsigned char cached_pub_encryption[65];
    if (to_pub_encryption == NULL)
    {
        struct bm_cached_pubkey cached;
        if (bm_pubkey_cache_lookup_by_ripe(identity_db, to_ripe, &cached) != 0)
        {
            OPENSSL_cleanse(&from_id, sizeof(from_id));
            return -1; /* 宛先のpubkeyが分からない(getpubkey要求の自動化は未実装、TODO) */
        }
        memcpy(cached_pub_encryption, cached.encryption_pubkey, 65);
        to_pub_encryption = cached_pub_encryption;
        bm_pubkey_cache_mark_used_personally(identity_db, to_ripe);
    }

    struct bm_identity_info from_info;
    memset(&from_info, 0, sizeof(from_info));
    from_info.address_version = from_id.address_version;
    from_info.stream = from_id.stream;
    memcpy(from_info.pub_signing, from_id.pub_signing, 65);
    memcpy(from_info.pub_encryption, from_id.pub_encryption, 65);
    memcpy(from_info.priv_signing, from_id.priv_signing, 32);
    from_info.nonce_trials_per_byte = from_id.nonce_trials_per_byte;
    from_info.payload_length_extra_bytes = from_id.payload_length_extra_bytes;
    /* TODO: PyBitmessageのdontsendack相当の設定はidentity.dbに未実装。既定でack要求する */
    from_info.does_ack = 1;

    uint64_t expires_time = (uint64_t)time(NULL) + ttl_seconds;

    unsigned char *ack_data = NULL;    /* nonce付き完成object(§5.0形式)、sent.ack_dataとして保存 */
    size_t ack_data_len = 0;
    unsigned char *ack_packet = NULL;  /* P2P "object"パケット(24byteヘッダ込み)、msgへ平文埋め込み */
    size_t ack_packet_len = 0;
    if (generate_full_ack(ack_stealth_level, to_stream, expires_time, ttl_seconds,
                           &ack_data, &ack_data_len, &ack_packet, &ack_packet_len) != 0)
    {
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }

    size_t payload_len = 0;
    unsigned char *payload = bm_build_msg(&from_info, to_stream, to_ripe, to_pub_encryption,
                                           subject, body, ack_packet, ack_packet_len, expires_time, &payload_len);
    if (payload == NULL)
    {
        free(ack_data);
        free(ack_packet);
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }

    /* §4.1: 宛先pubkeyが要求する難易度とネットワーク既定値(=from_idの既定設定と同値)の
     * 大きい方を使う。pubkey_cacheに宛先の情報があれば(address_version>=3のみ意味を持つ、
     * §5.2)そちらを優先し、無ければ送信元の設定値のみを使う。 */
    uint64_t required_nonce_trials = from_id.nonce_trials_per_byte;
    uint64_t required_extra_bytes = from_id.payload_length_extra_bytes;
    {
        struct bm_cached_pubkey recipient_info;
        if (bm_pubkey_cache_lookup_by_ripe(identity_db, to_ripe, &recipient_info) == 0
            && recipient_info.address_version >= 3)
        {
            if (recipient_info.nonce_trials_per_byte > required_nonce_trials)
            {
                required_nonce_trials = recipient_info.nonce_trials_per_byte;
            }
            if (recipient_info.payload_length_extra_bytes > required_extra_bytes)
            {
                required_extra_bytes = recipient_info.payload_length_extra_bytes;
            }
        }
    }
    uint64_t target = bm_pow_get_target(payload_len, ttl_seconds, required_nonce_trials, required_extra_bytes);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    if (object == NULL)
    {
        free(payload);
        free(ack_data);
        free(ack_packet);
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);
    free(ack_packet);

    int rc = bm_messages_store_insert_sent(messages_db, ack_data, ack_data_len, to_address, from_address,
                                            subject, body, "sent", (int64_t)time(NULL),
                                            (int64_t)ttl_seconds);
    free(ack_data);
    OPENSSL_cleanse(&from_id, sizeof(from_id));

    if (rc != 0)
    {
        free(object);
        return -1;
    }

    *out_object = object;
    *out_object_len = object_len;
    return 0;
}

void *bm_send_pipeline_thread(void *arg)
{
    (void)arg;
    /* TODO(§1.1 send_pipeline_thread): send_request_queueをpopしbm_send_pipeline_send_messageを
     * 呼ぶループを実装する(api_server.c実装後、キュー結線が前提)。中核ロジックは
     * 実装・テスト済みなので、ここは配線するだけで良い。 */
    return NULL;
}
