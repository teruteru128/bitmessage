#include "api_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/evp.h>
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
#include "address.h"
#include "identity_store.h"
#include "messages_store.h"
#include "pubkey_cache.h"
#include "send_pipeline.h"

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
    return bm_json_new_bool(rc == 0);
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
                                         gen.priv_signing, gen.priv_encryption, store_passphrase, 1000, 1000);
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
 * sendMessage: [fromAddress, toAddress, toPubEncryptionHex(130桁hex, 65byte)|null,
 *               subject, body, ttlSeconds?, ackStealthLevel?]
 *
 * toPubEncryptionHexはnull(またはJSON上省略)可。その場合pubkey_cache(§2.3、cachePubkeyメソッド
 * 参照)をto_addressのripeで検索する。見つからなければ送信失敗(getpubkey要求による自動取得は
 * 未実装、TODO)。
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

    uint64_t ttl_seconds = ttl_v != NULL ? (uint64_t)bm_json_as_number(ttl_v) : (uint64_t)(2 * 24 * 60 * 60);
    int ack_stealth_level = stealth_v != NULL ? (int)bm_json_as_number(stealth_v) : 1;

    unsigned char *object = NULL;
    size_t object_len = 0;
    int rc = bm_send_pipeline_send_message(config->keyring, config->identity_db, config->messages_db,
                                            from_address, to_address, to_pub_encryption_ptr,
                                            subject, body, ttl_seconds, ack_stealth_level,
                                            &object, &object_len);
    if (rc != 0)
    {
        *out_error = dup_cstr("send failed (is fromAddress unlocked? is toAddress valid? if "
                              "toPubEncryptionHex was omitted, is the recipient's key cached "
                              "via cachePubkey?)");
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
    /* TODO: ネットワーク層とのキュー結線後、broadcast_queueへの投入もここで行う */
    return result;
}

/* getInboxMessages: [folder?](省略時は全件、'inbox'/'trash'等で絞り込み可) */
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

static const struct bm_api_method METHODS[] = {
    {"unlockAddress", h_unlockAddress},
    {"lockAddress", h_lockAddress},
    {"lockAllAddresses", h_lockAllAddresses},
    {"deleteAddress", h_deleteAddress},
    {"listAddresses", h_listAddresses},
    {"createDeterministicAddress", h_createDeterministicAddress},
    {"cachePubkey", h_cachePubkey},
    {"sendMessage", h_sendMessage},
    {"getInboxMessages", h_getInboxMessages},
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
    write(fd, header, (size_t)header_len);
    if (body_len > 0)
    {
        write(fd, body, body_len);
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

void bm_api_server_serve_forever(int listen_fd, const struct bm_api_server_config *config)
{
    for (;;)
    {
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
    const struct bm_api_server_config *config = arg;
    int listen_fd = -1;
    if (bm_api_server_listen(config, &listen_fd) != 0)
    {
        fprintf(stderr, "[api_server] failed to listen on %s:%d\n", config->bind_address, config->port);
        return NULL;
    }
    fprintf(stderr, "[api_server] listening on %s:%d\n", config->bind_address, config->port);
    bm_api_server_serve_forever(listen_fd, config);
    close(listen_fd);
    return NULL;
}
