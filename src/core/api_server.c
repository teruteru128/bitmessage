#include "api_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../common/broadcast_item.h"
#include "../common/hash.h"
#include "../common/json.h"
#include "../common/logging.h"
#include "../infra/network.h"
#include "../infra/object_sync.h"
#include "../infra/peer_registry.h"
#include "../pow/pow_engine.h"
#include "address.h"
#include "config_store.h"
#include "identity_store.h"
#include "message_builder.h"
#include "messages_store.h"
#include "peer_manager.h"
#include "pubkey_cache.h"
#include "send_pipeline.h"

/* getpubkey要求自体のPoW難易度。誰が受け取るか分からない匿名objectのため、宛先固有の
 * 難易度ではなくネットワーク既定値(send_pipeline.cのack生成と同じ考え方)を使う */
#define BM_GETPUBKEY_NONCE_TRIALS_PER_BYTE 1000
#define BM_GETPUBKEY_PAYLOAD_LENGTH_EXTRA_BYTES 1000
#define BM_GETPUBKEY_REQUEST_TTL_SECONDS (2 * 24 * 60 * 60)
/* 同じ宛先への再要求は最低でもこの間隔を空ける(短時間の連続sendMessage呼び出しでネットワークに
 * getpubkeyをbroadcastし続けないため) */
#define BM_GETPUBKEY_REQUEST_COOLDOWN_SECONDS (10 * 60)

#define MAX_REQUEST_SIZE (1 * 1024 * 1024) /* 1MiB上限、DoS対策 */

static char *dup_cstr(const char *s)
{
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    memcpy(out, s, len + 1);
    return out;
}

/* --- HTTP Basic認証 --- */

static int base64_decode(const char *b64, unsigned char *out, size_t out_cap, size_t *out_len)
{
    size_t in_len = strlen(b64);
    if (in_len == 0 || in_len % 4 != 0)
    {
        return -1;
    }
    size_t max_out = (in_len / 4) * 3;
    if (max_out > out_cap)
    {
        return -1;
    }
    int n = EVP_DecodeBlock(out, (const unsigned char *)b64, (int)in_len);
    if (n < 0)
    {
        return -1;
    }
    size_t actual = (size_t)n;
    if (in_len >= 1 && b64[in_len - 1] == '=' && actual > 0)
    {
        actual--;
    }
    if (in_len >= 2 && b64[in_len - 2] == '=' && actual > 0)
    {
        actual--;
    }
    *out_len = actual;
    return 0;
}

/* 定数時間比較(タイミング攻撃対策) */
static int constant_time_equal(const char *a, size_t a_len, const char *b, size_t b_len)
{
    if (a_len != b_len)
    {
        return 0;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a_len; i++)
    {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int check_basic_auth(const struct bm_api_server_config *config, const char *auth_header)
{
    if (config->username == NULL)
    {
        return 1; /* 認証設定なし(テスト用) */
    }
    if (auth_header == NULL || strncmp(auth_header, "Basic ", 6) != 0)
    {
        return 0;
    }
    unsigned char decoded[256];
    size_t decoded_len = 0;
    if (base64_decode(auth_header + 6, decoded, sizeof(decoded) - 1, &decoded_len) != 0)
    {
        return 0;
    }
    decoded[decoded_len] = '\0';

    char expected[256];
    snprintf(expected, sizeof(expected), "%s:%s", config->username, config->password);
    return constant_time_equal((const char *)decoded, decoded_len, expected, strlen(expected));
}

/* --- ハンドラ辞書(§6.0-6.1) --- */

typedef bm_json_value_t *(*bm_api_handler_fn)(const struct bm_api_server_config *config,
                                               const bm_json_value_t *params, char **out_error);

struct bm_api_method
{
    const char *name;
    bm_api_handler_fn handler;
};

static const char *param_str(const bm_json_value_t *params, size_t i)
{
    return bm_json_as_string(bm_json_array_get(params, i));
}

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/* out_lenバイトちょうど(=strlen(hex)/2)であることを要求する固定長hexデコード */
static int hex_decode_fixed(const char *hex, unsigned char *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++)
    {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
        {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static bm_json_value_t *h_unlockAddress(const struct bm_api_server_config *config,
                                         const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *passphrase = param_str(params, 1);
    if (address == NULL || passphrase == NULL)
    {
        *out_error = dup_cstr("unlockAddress requires [address, passphrase]");
        return NULL;
    }
    int rc = bm_keyring_unlock(config->keyring, config->identity_db, address, passphrase);
    if (rc == 0 && config->object_pool_db != NULL)
    {
        /* §11 2026-08-25 join-chan後にchan宛の過去メッセージが読めない問題の対応
         * (bm_object_sync_backfill_trial_decryptのコメント参照)。unlock成功直後、
         * その鍵がkeyringに載った状態でobject_pool.db中の未復号MSGオブジェクトを
         * 再走査する。joinChan自体はDBへidentityを保存するだけでkeyringには載せない
         * ため、trial_decryptが意味を持つのはこのunlockAddressのタイミングになる。 */
        bm_object_sync_backfill_trial_decrypt(config->object_pool_db, config->messages_db, config->keyring);
    }
    return bm_json_new_bool(rc == 0);
}

/*
 * §11 2026-08-29 数千件規模の一括インポート運用向け(DESIGN.md §11-19)。単一passphraseで
 * 全identityの一括unlockを試みる。各行のkdf_saltは個別のままなので、行ごとに独立して
 * passphraseの一致/不一致が判定される(bm_keyring_unlock_all参照)。戻り値はlistAddresses同様
 * [{address, unlocked}]の配列にし、呼び出し側が「どのアドレスが別passphraseだったか」を
 * 判別できるようにしてある。
 */
static bm_json_value_t *h_unlockAllAddresses(const struct bm_api_server_config *config,
                                              const bm_json_value_t *params, char **out_error)
{
    const char *passphrase = param_str(params, 0);
    if (passphrase == NULL)
    {
        *out_error = dup_cstr("unlockAllAddresses requires [passphrase]");
        return NULL;
    }

    struct bm_unlock_all_entry *results = NULL;
    size_t count = 0;
    if (bm_keyring_unlock_all(config->keyring, config->identity_db, passphrase, &results, &count) != 0)
    {
        *out_error = dup_cstr("failed to list identities");
        return NULL;
    }

    int any_unlocked = 0;
    bm_json_value_t *arr = bm_json_new_array();
    for (size_t i = 0; i < count; i++)
    {
        if (results[i].unlocked)
        {
            any_unlocked = 1;
        }
        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "address", bm_json_new_string(results[i].address));
        bm_json_object_set(entry, "unlocked", bm_json_new_bool(results[i].unlocked));
        bm_json_array_append(arr, entry);
    }
    free(results);

    if (any_unlocked && config->object_pool_db != NULL)
    {
        /* h_unlockAddressと同じ理由(上記コメント参照)。個別に何度も呼ばず1回だけ再走査する */
        bm_object_sync_backfill_trial_decrypt(config->object_pool_db, config->messages_db, config->keyring);
    }
    return arr;
}

static bm_json_value_t *h_lockAddress(const struct bm_api_server_config *config,
                                       const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("lockAddress requires [address]");
        return NULL;
    }
    int rc = bm_keyring_lock(config->keyring, address);
    return bm_json_new_bool(rc == 0);
}

static bm_json_value_t *h_lockAllAddresses(const struct bm_api_server_config *config,
                                            const bm_json_value_t *params, char **out_error)
{
    (void)params;
    (void)out_error;
    bm_keyring_lock_all(config->keyring);
    return bm_json_new_bool(1);
}

static bm_json_value_t *h_deleteAddress(const struct bm_api_server_config *config,
                                         const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("deleteAddress requires [address]");
        return NULL;
    }
    int rc = bm_keyring_delete_identity(config->keyring, config->identity_db, address);
    return bm_json_new_bool(rc == 0);
}

static bm_json_value_t *h_listAddresses(const struct bm_api_server_config *config,
                                         const bm_json_value_t *params, char **out_error)
{
    (void)params;
    struct bm_identity_summary *list = NULL;
    size_t count = 0;
    if (bm_identity_store_list(config->identity_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list identities");
        return NULL;
    }

    bm_json_value_t *arr = bm_json_new_array();
    for (size_t i = 0; i < count; i++)
    {
        struct bm_unlocked_identity dummy;
        int unlocked = bm_keyring_find_by_address(config->keyring, list[i].address, &dummy) ? 1 : 0;

        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "address", bm_json_new_string(list[i].address));
        bm_json_object_set(entry, "label", bm_json_new_string(list[i].label));
        bm_json_object_set(entry, "enabled", bm_json_new_bool(list[i].enabled));
        bm_json_object_set(entry, "unlocked", bm_json_new_bool(unlocked));
        bm_json_object_set(entry, "isChan", bm_json_new_bool(list[i].is_chan));
        bm_json_array_append(arr, entry);
    }
    free(list);
    return arr;
}

static bm_json_value_t *h_createDeterministicAddress(const struct bm_api_server_config *config,
                                                       const bm_json_value_t *params, char **out_error)
{
    const char *passphrase = param_str(params, 0);
    const bm_json_value_t *version_v = bm_json_array_get(params, 1);
    const bm_json_value_t *stream_v = bm_json_array_get(params, 2);
    const bm_json_value_t *null_bytes_v = bm_json_array_get(params, 3);
    const char *label = param_str(params, 4);
    const char *store_passphrase = param_str(params, 5);

    if (passphrase == NULL || version_v == NULL || stream_v == NULL || null_bytes_v == NULL
        || store_passphrase == NULL)
    {
        *out_error = dup_cstr("createDeterministicAddress requires "
                               "[passphrase, addressVersion, stream, ripeNullBytes, label, storePassphrase]");
        return NULL;
    }

    uint64_t version = (uint64_t)bm_json_as_number(version_v);
    uint64_t stream = (uint64_t)bm_json_as_number(stream_v);
    int null_bytes = (int)bm_json_as_number(null_bytes_v);
    if (version < 3 || version > 4)
    {
        *out_error = dup_cstr("addressVersion must be 3 or 4");
        return NULL;
    }

    struct bm_generated_address gen;
    if (bm_address_generate_deterministic(passphrase, null_bytes, &gen) != 0)
    {
        *out_error = dup_cstr("address generation failed");
        return NULL;
    }
    char *address = bm_address_encode(version, stream, gen.ripe, BM_RIPE_LEN);
    if (address == NULL)
    {
        *out_error = dup_cstr("address encoding failed");
        return NULL;
    }

    int rc = bm_keyring_create_identity(config->identity_db, address, label != NULL ? label : "",
                                         (int)version, (int)stream, gen.pub_signing, gen.pub_encryption,
                                         gen.priv_signing, gen.priv_encryption, store_passphrase,
                                         config->default_nonce_trials_per_byte,
                                         config->default_payload_length_extra_bytes);
    if (rc != 0)
    {
        free(address);
        *out_error = dup_cstr("failed to store identity (duplicate address?)");
        return NULL;
    }

    bm_json_value_t *result = bm_json_new_string(address);
    free(address);
    return result;
}

/*
 * §11 chan仕様: joinChan: [passphrase, label, storePassphrase]
 *
 * chanは暗号的には通常のdeterministic addressと全く同じもの(§5.1相当のaddress
 * generation)で、共有passphraseから同じ鍵を導出したpeer全員が同じアドレス/鍵を持つことで
 * 疑似グループチャットとして機能する(PyBitmessageのchan相当)。createDeterministicAddress
 * を固定パラメータ(addressVersion=4, stream=1, ripeNullBytes=1)で呼んだ上でis_chan=1を
 * 立てる薄いラッパー。同じpassphraseで複数のクライアントが呼べば全員が同じアドレスへ
 * 「join」したことになる。chanへの投稿はsendMessage(fromAddress=chanAddress,
 * toAddress=chanAddress, ...)で行う(自分自身宛の送信、§11のsend_pipeline.c参照。
 * toPubEncryptionHexを省略してもfrom_id自身のpub_encryptionが自動的に使われる)。
 * 受信側はtrial_decrypt(core/trial_decrypt.c)が既にkeyring中の全identityを試すため、
 * chan用の鍵をunlockしてさえいれば新規の受信処理は不要で、他メンバーの投稿も自動的に
 * inboxへ復号される。
 */
static bm_json_value_t *h_joinChan(const struct bm_api_server_config *config,
                                    const bm_json_value_t *params, char **out_error)
{
    const char *passphrase = param_str(params, 0);
    const char *label = param_str(params, 1);
    const char *store_passphrase = param_str(params, 2);

    if (passphrase == NULL || store_passphrase == NULL)
    {
        *out_error = dup_cstr("joinChan requires [passphrase, label, storePassphrase]");
        return NULL;
    }

    struct bm_generated_address gen;
    if (bm_address_generate_deterministic(passphrase, 1, &gen) != 0)
    {
        *out_error = dup_cstr("address generation failed");
        return NULL;
    }
    char *address = bm_address_encode(4, 1, gen.ripe, BM_RIPE_LEN);
    if (address == NULL)
    {
        *out_error = dup_cstr("address encoding failed");
        return NULL;
    }

    int rc = bm_keyring_create_identity(config->identity_db, address, label != NULL ? label : "",
                                         4, 1, gen.pub_signing, gen.pub_encryption,
                                         gen.priv_signing, gen.priv_encryption, store_passphrase,
                                         config->default_nonce_trials_per_byte,
                                         config->default_payload_length_extra_bytes);
    if (rc != 0)
    {
        free(address);
        *out_error = dup_cstr("failed to store chan identity (already joined this chan?)");
        return NULL;
    }
    bm_keyring_mark_as_chan(config->identity_db, address);

    bm_json_value_t *result = bm_json_new_string(address);
    free(address);
    return result;
}

/*
 * sendMessage: [fromAddress, toAddress, toPubEncryptionHex(130桁hex, 65byte)|null,
 *               subject, body, ttlSeconds?, ackStealthLevel?]
 *
 * toPubEncryptionHexはnull(またはJSON上省略)可。その場合pubkey_cache(§2.3、cachePubkeyメソッド
 * 参照)をto_addressのripeで検索する。見つからなければ、能動的にgetpubkey要求を自動broadcastした
 * うえで送信失敗を返す(§5.0「getpubkey要求の自動化」参照)。応答が届き自動キャッシュされ次第、
 * 改めてsendMessageを呼び直せば送信できる。
 */

/*
 * cachePubkey: [address, signingPubkeyHex(130桁hex), encryptionPubkeyHex(130桁hex)]
 *
 * 手動でpubkey_cacheへ相手の公開鍵を登録する。object_sync_thread(実ネットワークから受信した
 * pubkeyオブジェクトを自動的にcacheへ投入する処理)は未実装(TODO)のため、v1では既に知っている
 * 相手の公開鍵をこのメソッドで明示的に登録してからsendMessageのtoPubEncryptionHexを省略する、
 * という使い方を想定する。
 */
static bm_json_value_t *h_cachePubkey(const struct bm_api_server_config *config,
                                       const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *signing_hex = param_str(params, 1);
    const char *encryption_hex = param_str(params, 2);

    if (address == NULL || signing_hex == NULL || encryption_hex == NULL)
    {
        *out_error = dup_cstr("cachePubkey requires [address, signingPubkeyHex, encryptionPubkeyHex] "
                              "(each 130 hex characters, 65 bytes, 0x04||X||Y)");
        return NULL;
    }

    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char ripe[BM_RIPE_LEN];
    if (bm_address_decode(address, &version, &stream, ripe) != 0)
    {
        *out_error = dup_cstr("invalid address");
        return NULL;
    }

    struct bm_cached_pubkey entry;
    memset(&entry, 0, sizeof(entry));
    memcpy(entry.ripe, ripe, BM_RIPE_LEN);
    entry.address_version = version;
    entry.stream = stream;
    if (hex_decode_fixed(signing_hex, entry.signing_pubkey, sizeof(entry.signing_pubkey)) != 0
        || hex_decode_fixed(encryption_hex, entry.encryption_pubkey, sizeof(entry.encryption_pubkey)) != 0)
    {
        *out_error = dup_cstr("pubkeys must be exactly 130 hex characters (65 bytes) each");
        return NULL;
    }

    if (bm_pubkey_cache_upsert(config->identity_db, &entry, (int64_t)time(NULL)) != 0)
    {
        *out_error = dup_cstr("failed to store pubkey cache entry");
        return NULL;
    }
    return bm_json_new_bool(1);
}

static bm_json_value_t *h_sendMessage(const struct bm_api_server_config *config,
                                       const bm_json_value_t *params, char **out_error)
{
    const char *from_address = param_str(params, 0);
    const char *to_address = param_str(params, 1);
    const char *to_pubenc_hex = param_str(params, 2); /* NULL可(pubkey_cacheへフォールバック) */
    const char *subject = param_str(params, 3);
    const char *body = param_str(params, 4);
    const bm_json_value_t *ttl_v = bm_json_array_get(params, 5);
    const bm_json_value_t *stealth_v = bm_json_array_get(params, 6);

    if (from_address == NULL || to_address == NULL || subject == NULL || body == NULL)
    {
        *out_error = dup_cstr("sendMessage requires [fromAddress, toAddress, toPubEncryptionHex|null, "
                              "subject, body, ttlSeconds?, ackStealthLevel?]. toPubEncryptionHex may be "
                              "null to look up the recipient's key from pubkey_cache instead.");
        return NULL;
    }

    unsigned char to_pub_encryption[65];
    const unsigned char *to_pub_encryption_ptr = NULL;
    if (to_pubenc_hex != NULL && to_pubenc_hex[0] != '\0')
    {
        if (hex_decode_fixed(to_pubenc_hex, to_pub_encryption, sizeof(to_pub_encryption)) != 0)
        {
            *out_error = dup_cstr("toPubEncryptionHex must be exactly 130 hex characters (65 bytes)");
            return NULL;
        }
        to_pub_encryption_ptr = to_pub_encryption;
    }
    else
    {
        /* §11 getpubkey要求の自動化: pubkey_cacheに無ければ能動的にgetpubkeyオブジェクトを
         * 発行してネットワークへ流す(この呼び出し自体はまだ送れないので、以下のsend_pipeline
         * 呼び出しは従来通り失敗する。pubkeyが手に入り次第、改めてsendMessageを呼び直す運用を
         * 想定。短時間の連続呼び出しでbroadcastし続けないようcooldownを設ける)。 */
        uint64_t to_version = 0;
        uint64_t to_stream = 0;
        unsigned char to_ripe[BM_RIPE_LEN];
        struct bm_cached_pubkey cached;
        if (bm_address_decode(to_address, &to_version, &to_stream, to_ripe) == 0
            && bm_pubkey_cache_lookup_by_ripe(config->identity_db, to_ripe, &cached) != 0)
        {
            int64_t now = (int64_t)time(NULL);
            if (!bm_pubkey_cache_has_recent_request(config->identity_db, to_ripe, now,
                                                      BM_GETPUBKEY_REQUEST_COOLDOWN_SECONDS))
            {
                size_t getpubkey_len = 0;
                unsigned char *getpubkey_payload = bm_build_getpubkey(
                    to_version, to_stream, to_ripe, (uint64_t)now + BM_GETPUBKEY_REQUEST_TTL_SECONDS,
                    &getpubkey_len);
                if (getpubkey_payload != NULL)
                {
                    uint64_t gp_target = bm_pow_get_target(getpubkey_len, BM_GETPUBKEY_REQUEST_TTL_SECONDS,
                                                            BM_GETPUBKEY_NONCE_TRIALS_PER_BYTE,
                                                            BM_GETPUBKEY_PAYLOAD_LENGTH_EXTRA_BYTES);
                    uint64_t gp_nonce = bm_pow_run(getpubkey_payload, getpubkey_len, gp_target);

                    size_t gp_object_len = 8 + getpubkey_len;
                    unsigned char *gp_object = malloc(gp_object_len);
                    for (int i = 0; i < 8; i++)
                    {
                        gp_object[i] = (unsigned char)((gp_nonce >> (56 - 8 * i)) & 0xff);
                    }
                    memcpy(gp_object + 8, getpubkey_payload, getpubkey_len);
                    free(getpubkey_payload);

                    if (config->broadcast_queue != NULL)
                    {
                        struct bm_broadcast_item *gp_item = malloc(sizeof(*gp_item));
                        gp_item->object = gp_object;
                        gp_item->object_len = gp_object_len;
                        bm_queue_push(config->broadcast_queue, gp_item);
                    }
                    else
                    {
                        free(gp_object);
                    }
                    bm_pubkey_cache_record_request(config->identity_db, to_ripe, to_version, to_stream, now);
                }
            }
        }
    }

    uint64_t ttl_seconds = ttl_v != NULL ? (uint64_t)bm_json_as_number(ttl_v) : (uint64_t)(2 * 24 * 60 * 60);
    int ack_stealth_level = stealth_v != NULL ? (int)bm_json_as_number(stealth_v) : 1;

    unsigned char *object = NULL;
    size_t object_len = 0;
    int64_t next_resend_time = (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS;
    int rc = bm_send_pipeline_send_message(config->keyring, config->identity_db, config->messages_db,
                                            from_address, to_address, to_pub_encryption_ptr,
                                            subject, body, ttl_seconds, ack_stealth_level,
                                            NULL, next_resend_time,
                                            &object, &object_len);
    if (rc != 0)
    {
        *out_error = dup_cstr("send failed (is fromAddress unlocked? is toAddress valid? if "
                              "toPubEncryptionHex was omitted and the recipient's key was not yet "
                              "cached, a getpubkey request was broadcast automatically; retry "
                              "sendMessage once it has been received, or supply toPubEncryptionHex "
                              "directly / via cachePubkey)");
        return NULL;
    }

    unsigned char inv_hash[32];
    bm_inventory_hash(object, object_len, inv_hash);

    /* §1.2 broadcast_queueへ投入(infra/object_sync.cのbm_object_sync_broadcast_threadが
     * object_pool.dbへの挿入とpeer_registry経由のネットワークへのinv broadcastを行う)。
     * 所有権(object)はここでqueueへ渡す(popした側がfreeする)。queueが未設定(NULL)なら
     * ネットワークへは流さずここでfreeする(test/CLI単体動作用)。 */
    if (config->broadcast_queue != NULL)
    {
        struct bm_broadcast_item *item = malloc(sizeof(*item));
        item->object = object;
        item->object_len = object_len;
        bm_queue_push(config->broadcast_queue, item);
    }
    else
    {
        free(object);
    }

    char inv_hex[65];
    hex_encode(inv_hash, sizeof(inv_hash), inv_hex);

    bm_json_value_t *result = bm_json_new_object();
    bm_json_object_set(result, "objectLength", bm_json_new_number((double)object_len));
    bm_json_object_set(result, "inventoryHash", bm_json_new_string(inv_hex));
    return result;
}

/* sendBroadcast: [fromAddress, subject, body, ttlSeconds?]。§5.4/§11 */
static bm_json_value_t *h_sendBroadcast(const struct bm_api_server_config *config,
                                         const bm_json_value_t *params, char **out_error)
{
    const char *from_address = param_str(params, 0);
    const char *subject = param_str(params, 1);
    const char *body = param_str(params, 2);
    const bm_json_value_t *ttl_v = bm_json_array_get(params, 3);

    if (from_address == NULL || subject == NULL || body == NULL)
    {
        *out_error = dup_cstr("sendBroadcast requires [fromAddress, subject, body, ttlSeconds?]");
        return NULL;
    }
    uint64_t ttl_seconds = ttl_v != NULL ? (uint64_t)bm_json_as_number(ttl_v) : (uint64_t)(2 * 24 * 60 * 60);

    unsigned char *object = NULL;
    size_t object_len = 0;
    int rc = bm_send_pipeline_send_broadcast(config->keyring, from_address, subject, body, ttl_seconds,
                                              &object, &object_len);
    if (rc != 0)
    {
        *out_error = dup_cstr("broadcast failed (is fromAddress unlocked?)");
        return NULL;
    }

    unsigned char inv_hash[32];
    bm_inventory_hash(object, object_len, inv_hash);

    if (config->broadcast_queue != NULL)
    {
        struct bm_broadcast_item *item = malloc(sizeof(*item));
        item->object = object;
        item->object_len = object_len;
        bm_queue_push(config->broadcast_queue, item);
    }
    else
    {
        free(object);
    }

    char inv_hex[65];
    hex_encode(inv_hash, sizeof(inv_hash), inv_hex);

    bm_json_value_t *result = bm_json_new_object();
    bm_json_object_set(result, "objectLength", bm_json_new_number((double)object_len));
    bm_json_object_set(result, "inventoryHash", bm_json_new_string(inv_hex));
    return result;
}

/* getInboxMessages: [folder?](省略時は全件、'inbox'/'trash'等で絞り込み可) */
static bm_json_value_t *h_addSubscription(const struct bm_api_server_config *config,
                                           const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *label = param_str(params, 1);
    if (address == NULL)
    {
        *out_error = dup_cstr("addSubscription requires [address, label?]");
        return NULL;
    }

    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char ripe[BM_RIPE_LEN];
    if (bm_address_decode(address, &version, &stream, ripe) != 0)
    {
        *out_error = dup_cstr("invalid address");
        return NULL;
    }

    int rc = bm_messages_store_add_subscription(config->messages_db, address, label != NULL ? label : "");
    return bm_json_new_bool(rc == 0);
}

static bm_json_value_t *h_removeSubscription(const struct bm_api_server_config *config,
                                              const bm_json_value_t *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("removeSubscription requires [address]");
        return NULL;
    }
    int rc = bm_messages_store_remove_subscription(config->messages_db, address);
    return bm_json_new_bool(rc == 0);
}

static bm_json_value_t *h_listSubscriptions(const struct bm_api_server_config *config,
                                             const bm_json_value_t *params, char **out_error)
{
    (void)params;

    struct bm_subscription *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_subscriptions(config->messages_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list subscriptions");
        return NULL;
    }

    bm_json_value_t *arr = bm_json_new_array();
    for (size_t i = 0; i < count; i++)
    {
        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "address", bm_json_new_string(list[i].address));
        bm_json_object_set(entry, "label", bm_json_new_string(list[i].label));
        bm_json_array_append(arr, entry);
    }
    bm_subscription_list_free(list);
    return arr;
}

/*
 * §11 2026-08-26: onionピア向け/クリアネットIP向けでSOCKS5設定を分離した
 * (config_store.hのdoc参照。以前は単一設定を全outbound接続に適用しており、これが
 * クリアネットIPまでTor出口ノード経由にしてしまい外部ノードへの接続性を悪化させて
 * いた)。get/setどちらもgetter/setter関数を引数に取るだけの共通ロジックにまとめ、
 * Onion/Clearnetの2つのAPIハンドラから呼ぶ。
 */
typedef int (*socks_proxy_getter_t)(sqlite3 *, struct bm_socks_proxy_config *);
typedef int (*socks_proxy_setter_t)(sqlite3 *, const struct bm_socks_proxy_config *);

static bm_json_value_t *get_socks_proxy_common(const struct bm_api_server_config *config,
                                                socks_proxy_getter_t getter, char **out_error)
{
    if (config->config_db == NULL)
    {
        *out_error = dup_cstr("config store is not available");
        return NULL;
    }

    struct bm_socks_proxy_config proxy;
    if (getter(config->config_db, &proxy) != 0)
    {
        *out_error = dup_cstr("failed to read socks proxy config");
        return NULL;
    }

    bm_json_value_t *result = bm_json_new_object();
    bm_json_object_set(result, "enabled", bm_json_new_bool(proxy.enabled));
    bm_json_object_set(result, "host", bm_json_new_string(proxy.host));
    bm_json_object_set(result, "port", bm_json_new_number((double)proxy.port));
    return result;
}

static bm_json_value_t *set_socks_proxy_common(const struct bm_api_server_config *config,
                                                const bm_json_value_t *params, socks_proxy_setter_t setter,
                                                const char *usage_error, char **out_error)
{
    if (config->config_db == NULL)
    {
        *out_error = dup_cstr("config store is not available");
        return NULL;
    }

    const bm_json_value_t *enabled_v = bm_json_array_get(params, 0);
    const char *host = param_str(params, 1);
    const bm_json_value_t *port_v = bm_json_array_get(params, 2);
    if (enabled_v == NULL || host == NULL || port_v == NULL)
    {
        *out_error = dup_cstr(usage_error);
        return NULL;
    }

    struct bm_socks_proxy_config proxy;
    memset(&proxy, 0, sizeof(proxy));
    proxy.enabled = (bm_json_as_number(enabled_v) != 0.0) ? 1 : 0;
    if (strlen(host) == 0 || strlen(host) >= sizeof(proxy.host))
    {
        *out_error = dup_cstr("host must be non-empty and shorter than 256 bytes");
        return NULL;
    }
    strncpy(proxy.host, host, sizeof(proxy.host) - 1);
    proxy.port = (int)bm_json_as_number(port_v);
    if (proxy.port <= 0 || proxy.port > 65535)
    {
        *out_error = dup_cstr("port must be between 1 and 65535");
        return NULL;
    }

    if (setter(config->config_db, &proxy) != 0)
    {
        *out_error = dup_cstr("failed to store socks proxy config");
        return NULL;
    }
    return bm_json_new_bool(1);
}

/* getSocksProxyOnion: [] -> {enabled, host, port}(onion peer(.onion宛)専用) */
static bm_json_value_t *h_getSocksProxyOnion(const struct bm_api_server_config *config,
                                              const bm_json_value_t *params, char **out_error)
{
    (void)params;
    return get_socks_proxy_common(config, bm_config_store_get_socks_proxy_onion, out_error);
}

/*
 * setSocksProxyOnion: [enabled, host, port](onion peer(.onion宛)専用)
 * 変更はconfig.dbへ即座に永続化される。稼働中のpeer_connector_threadは再接続サイクルの
 * たびconfig.dbを読み直すため(§11設定変更の動的リロード)、daemon再起動なしで次の
 * 再接続サイクル(既定30秒以内)から反映される。
 */
static bm_json_value_t *h_setSocksProxyOnion(const struct bm_api_server_config *config,
                                              const bm_json_value_t *params, char **out_error)
{
    return set_socks_proxy_common(config, params, bm_config_store_set_socks_proxy_onion,
                                   "setSocksProxyOnion requires [enabled, host, port]", out_error);
}

/* getSocksProxyClearnet: [] -> {enabled, host, port}(クリアネットIP宛専用、既定disabled=直結) */
static bm_json_value_t *h_getSocksProxyClearnet(const struct bm_api_server_config *config,
                                                 const bm_json_value_t *params, char **out_error)
{
    (void)params;
    return get_socks_proxy_common(config, bm_config_store_get_socks_proxy_clearnet, out_error);
}

/* setSocksProxyClearnet: [enabled, host, port](クリアネットIP宛専用) */
static bm_json_value_t *h_setSocksProxyClearnet(const struct bm_api_server_config *config,
                                                 const bm_json_value_t *params, char **out_error)
{
    return set_socks_proxy_common(config, params, bm_config_store_set_socks_proxy_clearnet,
                                   "setSocksProxyClearnet requires [enabled, host, port]", out_error);
}

/*
 * §11 手動peer追加(`addPeer`): [ipAddress, port, stream?]
 *
 * mainnetシード全滅時、addr伝播やOBJECT_ONIONPEER発見は既に1本繋がっていることが前提の
 * 仕組みのため、そもそも1件も接続できない状況では機能しない。その最後の手段として、
 * ユーザーが個人的に(掲示板等の匿名リストではなく、実際に運用者と面識のある経路で)
 * 存在を確認したノードを手動でpeers.dbへ追加する。PyBitmessageのGitHub issue #2310で
 * 「身元不明の匿名申告アドレスリスト」の採用が拒否された事例を踏まえ、この実装でも
 * 匿名の公開リストを自動採用する設計は避けている(DESIGN.md §11参照。同じ理由で
 * seeds/observed_nodes.txtも「開発者が直接確認しただけ」という限定的な位置づけで
 * peer_manager.c側に分離してある)。
 *
 * bm_peer_manager_upsert_learnedを使うため、rating=0.0(既存行があれば変更しない)から
 * スタートする。手動追加だからといって無条件に信用するわけではなく、他の候補と同じく
 * 実際の接続実績でratingを積み上げていく。
 */
static bm_json_value_t *h_addPeer(const struct bm_api_server_config *config,
                                   const bm_json_value_t *params, char **out_error)
{
    if (config->peers_db == NULL)
    {
        *out_error = dup_cstr("peer store is not available");
        return NULL;
    }

    const char *ip_address = param_str(params, 0);
    const bm_json_value_t *port_v = bm_json_array_get(params, 1);
    const bm_json_value_t *stream_v = bm_json_array_get(params, 2);
    if (ip_address == NULL || port_v == NULL)
    {
        *out_error = dup_cstr("addPeer requires [ipAddress, port, stream?]");
        return NULL;
    }
    if (strlen(ip_address) == 0 || strlen(ip_address) >= 64)
    {
        *out_error = dup_cstr("ipAddress must be non-empty and shorter than 64 bytes");
        return NULL;
    }

    int port = (int)bm_json_as_number(port_v);
    if (port <= 0 || port > 65535)
    {
        *out_error = dup_cstr("port must be between 1 and 65535");
        return NULL;
    }
    int stream = stream_v != NULL ? (int)bm_json_as_number(stream_v) : 1;

    if (bm_peer_manager_upsert_learned(config->peers_db, ip_address, port, stream, 1,
                                        (int64_t)time(NULL), "manual") != 0)
    {
        *out_error = dup_cstr("failed to store peer");
        return NULL;
    }
    return bm_json_new_bool(1);
}

/*
 * listConnections: [] -> {inbound: [{host,port,fullyEstablished,userAgent}], outbound: [...]}
 * §11 2026-08-23 backlog項目5。PyBitmessage(api.pyのHandleListConnections)と同じ形。
 * ヘッドレスdaemonのGUI Network Statusタブ相当として、現在接続中のpeer一覧を返す。
 */
struct list_connections_ctx
{
    bm_json_value_t *inbound;
    bm_json_value_t *outbound;
};

static void list_connections_one(struct bm_fd_data *conn, void *user_data)
{
    struct list_connections_ctx *ctx = user_data;
    if (conn->type == BM_FD_LISTEN_SOCKET)
    {
        return; /* listenソケット自体は接続ではない */
    }

    char ip[BM_PEER_IP_STRLEN];
    int port = 0;
    bm_network_resolve_peer_ip_port(conn, ip, sizeof(ip), &port);

    bm_json_value_t *entry = bm_json_new_object();
    bm_json_object_set(entry, "host", bm_json_new_string(ip));
    bm_json_object_set(entry, "port", bm_json_new_number((double)port));
    bm_json_object_set(entry, "fullyEstablished", bm_json_new_bool(conn->handshake_complete));
    bm_json_object_set(entry, "userAgent", bm_json_new_string(conn->user_agent != NULL ? conn->user_agent : ""));
    /* §11 2026-08-23 backlog項目5(送受信バイト数、後半分)。PyBitmessage自体には
     * 無い機能(本家のadvanceddispatcher.pyのsentBytes/receivedBytesはどこからも
     * 参照・表示されない実質デッドなフィールドだった、DESIGN.md参照)。受信バイト数は
     * 全経路を正確に集計できるが、送信バイト数はbroadcast_inv経由(dup()したfdへの
     * 書き込み、connを持たない)の分だけこの接続の集計に含められない(ユーザー了承済み、
     * 全体累積のgetNetworkStatsには含まれる)。 */
    bm_json_object_set(entry, "sentBytes", bm_json_new_number((double)conn->bytes_sent));
    bm_json_object_set(entry, "receivedBytes", bm_json_new_number((double)conn->bytes_received));

    bm_json_array_append(conn->type == BM_FD_SERVER_SOCKET ? ctx->inbound : ctx->outbound, entry);
}

static bm_json_value_t *h_listConnections(const struct bm_api_server_config *config,
                                           const bm_json_value_t *params, char **out_error)
{
    (void)params;
    if (config->registry == NULL)
    {
        *out_error = dup_cstr("connection registry is not available");
        return NULL;
    }

    struct list_connections_ctx ctx;
    ctx.inbound = bm_json_new_array();
    ctx.outbound = bm_json_new_array();
    /* §11 2026-08-23: for_each_locked(APIサーバスレッドからの呼び出し専用の変種)を使う。
     * 通常のfor_eachはロックを早期解放するため、network_epoll_thread側で該当connが
     * close_connection経由でfree()されるuse-after-freeを起こしうる(peer_registry.h参照)。 */
    bm_peer_registry_for_each_locked(config->registry, list_connections_one, &ctx);

    bm_json_value_t *result = bm_json_new_object();
    bm_json_object_set(result, "inbound", ctx.inbound);
    bm_json_object_set(result, "outbound", ctx.outbound);
    return result;
}

/*
 * getNetworkStats: [] -> {sentBytes, receivedBytes}
 * §11 2026-08-23 backlog項目5(送受信バイト数、後半分)。プロセス起動時からの送受信
 * バイト数の全体累積(切断済みの接続ぶんも含む)。listConnectionsとは別メソッドにした
 * (ユーザーの指摘: "listConnections"という名前でtotalsまで返すのは名前と実態が
 * 合わない)。PyBitmessage自体には無いAPI(本家はGUIのNetwork Statusタブの
 * スループット表示にのみ内部的に使っている、DESIGN.md参照)。
 */
static bm_json_value_t *h_getNetworkStats(const struct bm_api_server_config *config,
                                           const bm_json_value_t *params, char **out_error)
{
    (void)config;
    (void)params;
    (void)out_error;

    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    bm_network_get_stats(&bytes_sent, &bytes_received);

    bm_json_value_t *result = bm_json_new_object();
    bm_json_object_set(result, "sentBytes", bm_json_new_number((double)bytes_sent));
    bm_json_object_set(result, "receivedBytes", bm_json_new_number((double)bytes_received));
    return result;
}

static bm_json_value_t *h_getInboxMessages(const struct bm_api_server_config *config,
                                            const bm_json_value_t *params, char **out_error)
{
    const char *folder = param_str(params, 0);

    struct bm_inbox_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_inbox(config->messages_db, folder, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list inbox");
        return NULL;
    }

    bm_json_value_t *arr = bm_json_new_array();
    for (size_t i = 0; i < count; i++)
    {
        char msg_id_hex[65];
        hex_encode(list[i].msg_id, sizeof(list[i].msg_id), msg_id_hex);

        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "msgId", bm_json_new_string(msg_id_hex));
        bm_json_object_set(entry, "toAddress", bm_json_new_string(list[i].to_address));
        bm_json_object_set(entry, "fromAddress", bm_json_new_string(list[i].from_address));
        bm_json_object_set(entry, "subject", bm_json_new_string(list[i].subject));
        bm_json_object_set(entry, "body", bm_json_new_string(list[i].body));
        bm_json_object_set(entry, "receivedTime", bm_json_new_number((double)list[i].received_time));
        bm_json_object_set(entry, "read", bm_json_new_bool(list[i].read));
        bm_json_object_set(entry, "folder", bm_json_new_string(list[i].folder));
        bm_json_array_append(arr, entry);
    }
    bm_inbox_message_list_free(list, count);
    return arr;
}

/* §11 2026-08-25: getSentMessages: [] -> [{msgId,toAddress,fromAddress,subject,body,status,
 * sentTime,ttl,resendCount}, ...]。sentテーブルはこれまでack追跡専用でユーザー向けの一覧
 * 手段が無かった(getInboxMessagesに相当するものが未実装だった)ため追加。 */
static bm_json_value_t *h_getSentMessages(const struct bm_api_server_config *config,
                                           const bm_json_value_t *params, char **out_error)
{
    (void)params;

    struct bm_sent_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_sent(config->messages_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list sent");
        return NULL;
    }

    bm_json_value_t *arr = bm_json_new_array();
    for (size_t i = 0; i < count; i++)
    {
        char msg_id_hex[65];
        hex_encode(list[i].msg_id, sizeof(list[i].msg_id), msg_id_hex);

        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "msgId", bm_json_new_string(msg_id_hex));
        bm_json_object_set(entry, "toAddress", bm_json_new_string(list[i].to_address));
        bm_json_object_set(entry, "fromAddress", bm_json_new_string(list[i].from_address));
        bm_json_object_set(entry, "subject", bm_json_new_string(list[i].subject));
        bm_json_object_set(entry, "body", bm_json_new_string(list[i].body));
        bm_json_object_set(entry, "status", bm_json_new_string(list[i].status));
        bm_json_object_set(entry, "sentTime", bm_json_new_number((double)list[i].sent_time));
        bm_json_object_set(entry, "ttl", bm_json_new_number((double)list[i].ttl));
        bm_json_object_set(entry, "resendCount", bm_json_new_number((double)list[i].resend_count));
        bm_json_array_append(arr, entry);
    }
    bm_sent_message_list_free(list, count);
    return arr;
}

static const struct bm_api_method METHODS[] = {
    {"unlockAddress", h_unlockAddress},
    {"unlockAllAddresses", h_unlockAllAddresses},
    {"lockAddress", h_lockAddress},
    {"lockAllAddresses", h_lockAllAddresses},
    {"deleteAddress", h_deleteAddress},
    {"listAddresses", h_listAddresses},
    {"createDeterministicAddress", h_createDeterministicAddress},
    {"joinChan", h_joinChan},
    {"cachePubkey", h_cachePubkey},
    {"sendMessage", h_sendMessage},
    {"sendBroadcast", h_sendBroadcast},
    {"getInboxMessages", h_getInboxMessages},
    {"getSentMessages", h_getSentMessages},
    {"addSubscription", h_addSubscription},
    {"removeSubscription", h_removeSubscription},
    {"listSubscriptions", h_listSubscriptions},
    {"getSocksProxyOnion", h_getSocksProxyOnion},
    {"setSocksProxyOnion", h_setSocksProxyOnion},
    {"getSocksProxyClearnet", h_getSocksProxyClearnet},
    {"setSocksProxyClearnet", h_setSocksProxyClearnet},
    {"addPeer", h_addPeer},
    {"listConnections", h_listConnections},
    {"getNetworkStats", h_getNetworkStats},
};
#define METHOD_COUNT (sizeof(METHODS) / sizeof(METHODS[0]))

/* --- JSON-RPC 2.0処理 --- */

static char *build_response(const bm_json_value_t *id, bm_json_value_t *result, const char *error_msg)
{
    bm_json_value_t *resp = bm_json_new_object();
    bm_json_object_set(resp, "jsonrpc", bm_json_new_string("2.0"));
    if (error_msg != NULL)
    {
        bm_json_value_t *err = bm_json_new_object();
        bm_json_object_set(err, "code", bm_json_new_number(-32000));
        bm_json_object_set(err, "message", bm_json_new_string(error_msg));
        bm_json_object_set(resp, "error", err);
        bm_json_free(result);
    }
    else
    {
        bm_json_object_set(resp, "result", result != NULL ? result : bm_json_new_null());
    }
    if (id != NULL)
    {
        /* idはリクエストの値をそのまま複製して返す(number/string/nullいずれか) */
        if (id->type == BM_JSON_STRING)
        {
            bm_json_object_set(resp, "id", bm_json_new_string(id->string));
        }
        else if (id->type == BM_JSON_NUMBER)
        {
            bm_json_object_set(resp, "id", bm_json_new_number(id->number));
        }
        else
        {
            bm_json_object_set(resp, "id", bm_json_new_null());
        }
    }
    else
    {
        bm_json_object_set(resp, "id", bm_json_new_null());
    }

    char *text = bm_json_serialize(resp);
    bm_json_free(resp);
    return text;
}

static char *process_jsonrpc_request(const struct bm_api_server_config *config,
                                      const char *body, size_t body_len)
{
    bm_json_value_t *req = bm_json_parse(body, body_len);
    if (req == NULL || req->type != BM_JSON_OBJECT)
    {
        bm_json_free(req);
        return build_response(NULL, NULL, "Parse error: invalid JSON");
    }

    const bm_json_value_t *id = bm_json_object_get(req, "id");
    const char *method = bm_json_as_string(bm_json_object_get(req, "method"));
    const bm_json_value_t *params = bm_json_object_get(req, "params");

    if (method == NULL)
    {
        char *resp = build_response(id, NULL, "Invalid request: missing method");
        bm_json_free(req);
        return resp;
    }

    for (size_t i = 0; i < METHOD_COUNT; i++)
    {
        if (strcmp(METHODS[i].name, method) == 0)
        {
            char *error_msg = NULL;
            bm_json_value_t *result = METHODS[i].handler(config, params, &error_msg);
            char *resp = build_response(id, result, error_msg);
            free(error_msg);
            bm_json_free(req);
            return resp;
        }
    }

    char *resp = build_response(id, NULL, "Method not found");
    bm_json_free(req);
    return resp;
}

/* --- HTTPトランスポート --- */

static ssize_t read_until_double_crlf(int fd, unsigned char **buf, size_t *buf_len, size_t *buf_cap)
{
    static const char needle[] = "\r\n\r\n";
    const size_t needle_len = 4;

    for (;;)
    {
        if (*buf_len >= needle_len)
        {
            for (size_t i = 0; i + needle_len <= *buf_len; i++)
            {
                if (memcmp(*buf + i, needle, needle_len) == 0)
                {
                    return (ssize_t)(i + needle_len);
                }
            }
        }
        if (*buf_len + 4096 > *buf_cap)
        {
            *buf_cap = (*buf_cap == 0 ? 4096 : *buf_cap * 2);
            *buf = realloc(*buf, *buf_cap);
        }
        ssize_t n = read(fd, *buf + *buf_len, *buf_cap - *buf_len);
        if (n <= 0)
        {
            return -1;
        }
        *buf_len += (size_t)n;
        if (*buf_len > MAX_REQUEST_SIZE)
        {
            return -1;
        }
    }
}

static long find_header_value_long(const char *headers, size_t headers_len, const char *name)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i + name_len < headers_len; i++)
    {
        if (strncasecmp(headers + i, name, name_len) == 0 && headers[i + name_len] == ':')
        {
            const char *value = headers + i + name_len + 1;
            while (*value == ' ')
            {
                value++;
            }
            return strtol(value, NULL, 10);
        }
    }
    return -1;
}

static char *find_header_value_str(const char *headers, size_t headers_len, const char *name)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i + name_len < headers_len; i++)
    {
        if (strncasecmp(headers + i, name, name_len) == 0 && headers[i + name_len] == ':')
        {
            const char *value = headers + i + name_len + 1;
            while (*value == ' ')
            {
                value++;
            }
            const char *line_end = memchr(value, '\r', headers_len - (size_t)(value - headers));
            size_t len = line_end != NULL ? (size_t)(line_end - value) : strlen(value);
            char *out = malloc(len + 1);
            memcpy(out, value, len);
            out[len] = '\0';
            return out;
        }
    }
    return NULL;
}

static void write_http_response(int fd, int status, const char *status_text,
                                 const char *content_type, const char *body,
                                 const char *extra_header)
{
    char header[512];
    size_t body_len = body != NULL ? strlen(body) : 0;
    int header_len = snprintf(header, sizeof(header),
                               "HTTP/1.1 %d %s\r\n"
                               "Content-Type: %s\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: close\r\n"
                               "%s"
                               "\r\n",
                               status, status_text, content_type, body_len,
                               extra_header != NULL ? extra_header : "");
    /* §11 2026-08-24 backlog項目10(Releaseビルド検証)で発覚: 生のwrite()は
     * warn_unused_result属性が付いており、戻り値を無視すると-Wunused-resultが警告する
     * (-O2で有効化される_FORTIFY_SOURCE経由)。加えて生write()は部分書き込みの可能性も
     * 元々ハンドリングしていなかったため、既存のbm_network_write_all(部分書き込み対応・
     * タイムアウト付き、peer_registry.c等で使っているのと同じヘルパー)へ置き換えた。
     * レスポンス送信の失敗自体はこの後すぐclose(client_fd)するだけなので、戻り値は
     * 意図的に無視する(bm_network_write_all自体にはwarn_unused_result属性が無い)。 */
    bm_network_write_all(fd, (const unsigned char *)header, (size_t)header_len,
                          BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS, NULL, 0);
    if (body_len > 0)
    {
        bm_network_write_all(fd, (const unsigned char *)body, body_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS, NULL, 0);
    }
}

void bm_api_server_handle_connection(int client_fd, const struct bm_api_server_config *config)
{
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    size_t buf_cap = 0;

    ssize_t header_end = read_until_double_crlf(client_fd, &buf, &buf_len, &buf_cap);
    if (header_end < 0)
    {
        free(buf);
        close(client_fd);
        return;
    }

    /* リクエストラインの検証(POSTのみ受け付ける) */
    if (buf_len < 4 || memcmp(buf, "POST", 4) != 0)
    {
        write_http_response(client_fd, 405, "Method Not Allowed", "text/plain", "POST only\n", NULL);
        free(buf);
        close(client_fd);
        return;
    }

    char *headers = (char *)buf;
    size_t headers_len = (size_t)header_end;

    char *auth_header = find_header_value_str(headers, headers_len, "Authorization");
    int authorized = check_basic_auth(config, auth_header);
    free(auth_header);
    if (!authorized)
    {
        write_http_response(client_fd, 401, "Unauthorized", "text/plain", "Unauthorized\n",
                             "WWW-Authenticate: Basic realm=\"bitmessage\"\r\n");
        free(buf);
        close(client_fd);
        return;
    }

    long content_length = find_header_value_long(headers, headers_len, "Content-Length");
    if (content_length < 0 || (size_t)content_length > MAX_REQUEST_SIZE)
    {
        write_http_response(client_fd, 400, "Bad Request", "text/plain", "invalid Content-Length\n", NULL);
        free(buf);
        close(client_fd);
        return;
    }

    size_t body_already = buf_len - (size_t)header_end;
    size_t body_needed = (size_t)content_length;
    if (body_already < body_needed)
    {
        size_t to_read = body_needed - body_already;
        if (buf_len + to_read > buf_cap)
        {
            buf_cap = buf_len + to_read;
            buf = realloc(buf, buf_cap);
        }
        size_t got = 0;
        while (got < to_read)
        {
            ssize_t n = read(client_fd, buf + buf_len + got, to_read - got);
            if (n <= 0)
            {
                free(buf);
                close(client_fd);
                return;
            }
            got += (size_t)n;
        }
        buf_len += got;
    }

    const char *body = (const char *)buf + header_end;
    char *response_json = process_jsonrpc_request(config, body, body_needed);
    write_http_response(client_fd, 200, "OK", "application/json", response_json, NULL);
    free(response_json);

    free(buf);
    close(client_fd);
}

int bm_api_server_listen(const struct bm_api_server_config *config, int *out_listen_fd)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)config->port);
    if (inet_pton(AF_INET, config->bind_address, &addr.sin_addr) != 1)
    {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) != 0)
    {
        close(fd);
        return -1;
    }

    *out_listen_fd = fd;
    return 0;
}

void bm_api_server_serve_forever(int listen_fd, const struct bm_api_server_config *config,
                                  _Atomic sig_atomic_t *stop_flag)
{
    struct pollfd pfd;
    pfd.fd = listen_fd;
    pfd.events = POLLIN;

    while (*stop_flag == 0)
    {
        int rc = poll(&pfd, 1, 1000); /* 1秒タイムアウトでstop_flagを再チェックする */
        if (rc < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (rc == 0)
        {
            continue; /* タイムアウト、stop_flagを再チェックするだけ */
        }

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        bm_api_server_handle_connection(client_fd, config);
    }
}

void *bm_api_server_thread(void *arg)
{
    struct bm_api_server_thread_args *args = arg;
    const struct bm_api_server_config *config = args->config;

    char addr_buf[80];
    bm_network_format_host_port(config->bind_address, config->port, addr_buf, sizeof(addr_buf));

    int listen_fd = -1;
    if (bm_api_server_listen(config, &listen_fd) != 0)
    {
        bm_log_error("[api_server] failed to listen on %s\n", addr_buf);
        free(args);
        return NULL;
    }
    bm_log_info("[api_server] listening on %s\n", addr_buf);
    bm_api_server_serve_forever(listen_fd, config, args->stop_flag);
    close(listen_fd);
    bm_log_info("[api_server] stopped\n");
    free(args);
    return NULL;
}
