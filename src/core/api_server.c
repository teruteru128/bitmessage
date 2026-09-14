#include "api_server.h"

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <limits.h>
#include <microhttpd.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../common/broadcast_item.h"
#include "../common/hash.h"
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

/*
 * 定数時間比較(タイミング攻撃対策)。
 *
 * §11 2026-09-15 libmicrohttpd移行後もこれは残す。Authorizationヘッダの探索とbase64の
 * デコード(以前はEVP_DecodeBlockで自前実装していた)はMHD_basic_auth_get_username_password3()
 * が肩代わりするが、MHDが提供するのはそこまでで、照合そのものはアプリ側の責任だからである。
 * §6.1で「比較は定数時間で行う」と決めているため、単純なstrcmpに退化させてはならない。
 */
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

/*
 * §11 2026-09-15 config->usernameがNULLなら認証不要(テスト用、従来通り)。
 * ユーザー名とパスワードを"user:pass"に連結してから1回比較していた旧実装と違い、MHDが
 * 最初の':'で切り分けた各要素を個別に比較する(結果は同じだが、連結用の固定長bufferと
 * snprintfによる切り詰めの可能性が無くなる。旧実装はexpected[256]に収まらない長い
 * apipasswordを設定すると静かに切り詰められ、切り詰め後の値でも認証が通ってしまった)。
 * ユーザー名が違っていてもパスワードの比較を省略しない(&=で両方必ず評価する)のは、
 * 応答時間からユーザー名の当たり外れを推測されないようにするため。
 */
static int check_basic_auth(const struct bm_api_server_config *config, struct MHD_Connection *connection)
{
    if (config->username == NULL)
    {
        return 1; /* 認証設定なし(テスト用) */
    }
    struct MHD_BasicAuthInfo *info = MHD_basic_auth_get_username_password3(connection);
    if (info == NULL)
    {
        return 0; /* Authorizationヘッダが無い、またはBasicとして解釈できない */
    }
    /* passwordはクライアントが':'以降を送らなかった場合NULLになりうる(microhttpd.hの
     * struct MHD_BasicAuthInfoのコメント参照)ので空文字として扱う */
    const char *password = info->password != NULL ? info->password : "";
    size_t password_len = info->password != NULL ? info->password_len : 0;
    const char *expected_password = config->password != NULL ? config->password : "";

    int ok = constant_time_equal(info->username, info->username_len, config->username,
                                  strlen(config->username));
    ok &= constant_time_equal(password, password_len, expected_password, strlen(expected_password));

    MHD_free(info);
    return ok;
}

/* --- cJSONヘルパー(旧自前bm_json APIとの意味差を吸収する、§11 2026-09-15) --- */

/*
 * paramsが配列でなければNULLを返す。cJSON_GetArrayItem()はオブジェクトを渡されると
 * そのメンバを添字順に返してしまい、「型が違えばNULL」だった旧bm_json_array_getと
 * 挙動が変わる(params={"0":"..."}のようなリクエストで引数が通ってしまう)。配列要素の
 * 取得は必ずこのラッパー経由で行うこと。
 */
static const cJSON *param_at(const cJSON *params, size_t i)
{
    if (!cJSON_IsArray(params) || i > (size_t)INT_MAX)
    {
        return NULL;
    }
    return cJSON_GetArrayItem(params, (int)i);
}

/* 旧bm_json_as_string互換: 文字列でなければNULL */
static const char *json_cstr(const cJSON *v)
{
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

/* 旧bm_json_as_number互換: 数値でなければ0 */
static double json_num(const cJSON *v)
{
    return cJSON_IsNumber(v) ? v->valuedouble : 0.0;
}

/* 旧bm_json_object_get互換。cJSON_GetObjectItem()は大文字小文字を区別しないので、
 * 区別する方(旧実装と同じstrcmp相当)を明示的に使う */
static cJSON *json_obj_get(const cJSON *obj, const char *key)
{
    return cJSON_GetObjectItemCaseSensitive(obj, key);
}

/*
 * 旧bm_json_new_string互換だが、NULLを空文字として扱う。cJSON_CreateString(NULL)はNULLを
 * 返し、それをcJSON_AddItemToObject()へ渡すとキーごと黙って落ちる(旧bm_json_new_stringは
 * NULLでクラッシュしたので「NULLは来ない」前提のコードだが、DBのlabelがNULLになる等の
 * 想定外が起きたときにレスポンスのキーが消えるより空文字が入る方が呼び出し側に優しい)。
 */
static cJSON *json_str(const char *s)
{
    return cJSON_CreateString(s != NULL ? s : "");
}

/* --- ハンドラ辞書(§6.0-6.1) --- */

typedef cJSON *(*bm_api_handler_fn)(const struct bm_api_server_config *config,
                                               const cJSON *params, char **out_error);

struct bm_api_method
{
    const char *name;
    bm_api_handler_fn handler;
};

static const char *param_str(const cJSON *params, size_t i)
{
    return json_cstr(param_at(params, i));
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

static cJSON *h_unlockAddress(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
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
         * ため、trial_decryptが意味を持つのはこのunlockAddressのタイミングになる。
         *
         * §11 2026-08-31 addressを渡してこのidentity1件だけに絞る(以前はkeyring全体を
         * 対象にしていたが、unlock-all済みでkeyringに数千件規模のunlocked identityが
         * 積まれた状態だと「MSGオブジェクト数×既存unlockedアドレス数」の計算量になり、
         * 実運用で9時間以上RPCサーバーをブロックする問題が発覚したため。詳細はDESIGN.mdおよび
         * object_sync.hのbm_object_sync_backfill_trial_decryptコメント参照)。 */
        bm_object_sync_backfill_trial_decrypt(config->object_pool_db, config->messages_db, config->keyring, address);
    }
    return cJSON_CreateBool(rc == 0);
}

/*
 * §11 2026-08-29 数千件規模の一括インポート運用向け(DESIGN.md §11-19)。単一passphraseで
 * 全identityの一括unlockを試みる。各行のkdf_saltは個別のままなので、行ごとに独立して
 * passphraseの一致/不一致が判定される(bm_keyring_unlock_all参照)。戻り値はlistAddresses同様
 * [{address, unlocked}]の配列にし、呼び出し側が「どのアドレスが別passphraseだったか」を
 * 判別できるようにしてある。
 */
static cJSON *h_unlockAllAddresses(const struct bm_api_server_config *config,
                                              const cJSON *params, char **out_error)
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

    /*
     * §11 2026-08-29 h_unlockAddressと違い、ここではbm_object_sync_backfill_trial_decryptを
     * 意図的に呼ばない。実地検証(5143件規模)でユーザーから指摘され発覚: この関数は
     * object_pool.db内の全MSGオブジェクト×keyring内の全unlocked identityを線形探索で
     * 総当たりする(bm_trial_decrypt_msg、ECDH計算を伴う)ため、計算量は
     * 「MSGオブジェクト数×unlockedアドレス数」に比例する。数千件規模の一括unlockで
     * これを毎回実行すると、object_pool.dbにMSGオブジェクトが数百件溜まっているだけでも
     * 数十万回以上のECDH復号試行が同期的に発生し、APIリクエストが致命的に長時間ブロック
     * されうる。この一括backfill機能自体が本家PyBitmessage(全アドレス常時ロード済みで
     * 「後から再走査する」概念が無い)には無い本実装独自の追加であることも踏まえ、5000件
     * 規模の一括unlockでは省略する判断とした(単体のunlockAddressでは1identity分のコスト
     * で済むため、これまで通りbackfillを継続する)。
     */
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "address", json_str(results[i].address));
        cJSON_AddItemToObject(entry, "unlocked", cJSON_CreateBool(results[i].unlocked));
        cJSON_AddItemToArray(arr, entry);
    }
    free(results);
    return arr;
}

/*
 * §11 2026-08-29 exportAddress: [address, passphrase]。importAddressと対称
 * (DESIGN.md §6.2/§7、2026-08-25にユーザーと合意した「importとexportはペアであるべき」への対応)。
 * unlockAddressとは独立させ、既存keyringには一切触れずその場限りで復号してWIF文字列を
 * 返すだけの一回性操作にする。呼び出し元はレスポンスのWIFを渡したら即座に破棄すること
 * (ログ・エラーメッセージには絶対に載せない)。
 */
static cJSON *h_exportAddress(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *passphrase = param_str(params, 1);
    if (address == NULL || passphrase == NULL)
    {
        *out_error = dup_cstr("exportAddress requires [address, passphrase]");
        return NULL;
    }

    unsigned char priv_signing[BM_PRIVATE_KEY_LEN];
    unsigned char priv_encryption[BM_PRIVATE_KEY_LEN];
    if (bm_keyring_export(config->identity_db, address, passphrase, priv_signing, priv_encryption) != 0)
    {
        *out_error = dup_cstr("export failed (wrong passphrase or address not found)");
        return NULL;
    }

    char *signing_wif = bm_address_encode_wif(priv_signing);
    char *encryption_wif = bm_address_encode_wif(priv_encryption);
    OPENSSL_cleanse(priv_signing, sizeof(priv_signing));
    OPENSSL_cleanse(priv_encryption, sizeof(priv_encryption));

    if (signing_wif == NULL || encryption_wif == NULL)
    {
        free(signing_wif);
        free(encryption_wif);
        *out_error = dup_cstr("WIF encoding failed");
        return NULL;
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "signingWIF", json_str(signing_wif));
    cJSON_AddItemToObject(result, "encryptionWIF", json_str(encryption_wif));
    free(signing_wif);
    free(encryption_wif);
    return result;
}

static cJSON *h_lockAddress(const struct bm_api_server_config *config,
                                       const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("lockAddress requires [address]");
        return NULL;
    }
    int rc = bm_keyring_lock(config->keyring, address);
    return cJSON_CreateBool(rc == 0);
}

static cJSON *h_lockAllAddresses(const struct bm_api_server_config *config,
                                            const cJSON *params, char **out_error)
{
    (void)params;
    (void)out_error;
    bm_keyring_lock_all(config->keyring);
    return cJSON_CreateBool(1);
}

static cJSON *h_deleteAddress(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("deleteAddress requires [address]");
        return NULL;
    }
    int rc = bm_keyring_delete_identity(config->keyring, config->identity_db, address);
    return cJSON_CreateBool(rc == 0);
}

static cJSON *h_listAddresses(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
{
    (void)params;
    struct bm_identity_summary *list = NULL;
    size_t count = 0;
    if (bm_identity_store_list(config->identity_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list identities");
        return NULL;
    }

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        struct bm_unlocked_identity dummy;
        int unlocked = bm_keyring_find_by_address(config->keyring, list[i].address, &dummy) ? 1 : 0;

        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "address", json_str(list[i].address));
        cJSON_AddItemToObject(entry, "label", json_str(list[i].label));
        cJSON_AddItemToObject(entry, "enabled", cJSON_CreateBool(list[i].enabled));
        cJSON_AddItemToObject(entry, "unlocked", cJSON_CreateBool(unlocked));
        cJSON_AddItemToObject(entry, "isChan", cJSON_CreateBool(list[i].is_chan));
        cJSON_AddItemToArray(arr, entry);
    }
    free(list);
    return arr;
}

static cJSON *h_createDeterministicAddress(const struct bm_api_server_config *config,
                                                       const cJSON *params, char **out_error)
{
    const char *passphrase = param_str(params, 0);
    const cJSON *version_v = param_at(params, 1);
    const cJSON *stream_v = param_at(params, 2);
    const cJSON *null_bytes_v = param_at(params, 3);
    const char *label = param_str(params, 4);
    const char *store_passphrase = param_str(params, 5);

    if (passphrase == NULL || version_v == NULL || stream_v == NULL || null_bytes_v == NULL
        || store_passphrase == NULL)
    {
        *out_error = dup_cstr("createDeterministicAddress requires "
                               "[passphrase, addressVersion, stream, ripeNullBytes, label, storePassphrase]");
        return NULL;
    }

    uint64_t version = (uint64_t)json_num(version_v);
    uint64_t stream = (uint64_t)json_num(stream_v);
    int null_bytes = (int)json_num(null_bytes_v);
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

    cJSON *result = json_str(address);
    free(address);
    return result;
}

/*
 * §11 2026-08-29 setAddressLabel: [address, label]。PyBitmessage本家にはJSON-RPC API経由の
 * ラベル変更は存在しないが、GUI(bitmessageqt)は直接config.set(address, 'label', ...)で
 * 変更できているため、本実装独自の拡張としてAPI経由で提供する。秘密鍵には一切触れない
 * (identities.labelカラムのみ更新)。keys.datインポート時のUTF-8文字化けバグ修正後、
 * 既にインポート済みのラベルを正しい値へ再設定する用途を主に想定している。
 */
static cJSON *h_setAddressLabel(const struct bm_api_server_config *config,
                                           const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *label = param_str(params, 1);
    if (address == NULL || label == NULL)
    {
        *out_error = dup_cstr("setAddressLabel requires [address, label]");
        return NULL;
    }
    if (bm_identity_store_update_label(config->identity_db, address, label) != 0)
    {
        *out_error = dup_cstr("address not found");
        return NULL;
    }
    return cJSON_CreateBool(1);
}

/*
 * §11 2026-08-29 importAddress: [address, signingWIF, encryptionWIF, label, storePassphrase,
 * nonceTrialsPerByte?, payloadLengthExtraBytes?, isChan?]
 *
 * DESIGN.md §6.2の当初案は[signingWIF, encryptionWIF, storePassphrase]だったが、WIFは秘密鍵の
 * みでaddressVersion/streamを含まないため、addressそのものを引数に取る形に確定した(keys.dat
 * (PyBitmessage本家)もセクション名=address文字列という同じ形)。PyBitmessage本家にはWIFを
 * 直接インポートするAPI/UIが存在しない(決定論的/ランダム生成経由の保存のみ、2026-08-29調査)ため
 * 本実装独自の拡張。addressから復元したripeとWIFから導出した公開鍵のripeが一致するかを
 * 検証することで、address文字列とWIFの組み合わせ誤りを検出する。
 *
 * isChan(2026-08-29追記): ユーザーの指摘で発覚。keys.datインポート対象にchanアドレスが
 * 含まれる場合、is_chanフラグ(§11 chan仕様、暗号的には無意味だがUI/listAddressesの表示用
 * 識別フラグ)を再現できないと片手落ちになるため追加した。省略時false(通常アドレス扱い)。
 */
static cJSON *h_importAddress(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *signing_wif = param_str(params, 1);
    const char *encryption_wif = param_str(params, 2);
    const char *label = param_str(params, 3);
    const char *store_passphrase = param_str(params, 4);
    const cJSON *nonce_trials_v = param_at(params, 5);
    const cJSON *payload_extra_v = param_at(params, 6);
    const cJSON *is_chan_v = param_at(params, 7);

    if (address == NULL || signing_wif == NULL || encryption_wif == NULL || store_passphrase == NULL)
    {
        *out_error = dup_cstr("importAddress requires [address, signingWIF, encryptionWIF, label, "
                              "storePassphrase, nonceTrialsPerByte?, payloadLengthExtraBytes?]");
        return NULL;
    }

    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char ripe_from_address[BM_RIPE_LEN];
    if (bm_address_decode(address, &version, &stream, ripe_from_address) != 0)
    {
        *out_error = dup_cstr("invalid address");
        return NULL;
    }

    unsigned char priv_signing[BM_PRIVATE_KEY_LEN];
    unsigned char priv_encryption[BM_PRIVATE_KEY_LEN];
    if (bm_address_decode_wif(signing_wif, priv_signing) != 0
        || bm_address_decode_wif(encryption_wif, priv_encryption) != 0)
    {
        *out_error = dup_cstr("invalid WIF (signingWIF/encryptionWIF)");
        return NULL;
    }

    unsigned char pub_signing[BM_PUBLIC_KEY_LEN];
    unsigned char pub_encryption[BM_PUBLIC_KEY_LEN];
    if (bm_address_get_public_key(priv_signing, pub_signing) != 0
        || bm_address_get_public_key(priv_encryption, pub_encryption) != 0)
    {
        *out_error = dup_cstr("failed to derive public key from WIF");
        return NULL;
    }

    unsigned char ripe_computed[BM_RIPE_LEN];
    bm_address_calc_ripe(pub_signing, pub_encryption, ripe_computed);
    if (memcmp(ripe_computed, ripe_from_address, BM_RIPE_LEN) != 0)
    {
        *out_error = dup_cstr("WIF keys do not match the given address");
        return NULL;
    }

    uint64_t nonce_trials = (nonce_trials_v != NULL)
        ? (uint64_t)json_num(nonce_trials_v) : config->default_nonce_trials_per_byte;
    uint64_t payload_extra = (payload_extra_v != NULL)
        ? (uint64_t)json_num(payload_extra_v) : config->default_payload_length_extra_bytes;

    /* §11 2026-08-29 実測でscrypt(N=2^15)は1回161msかかり、5000件規模のkeys.datインポートを
     * bm_keyring_create_identity(個別scrypt)で行うと約17分かかることが判明したため、
     * importAddressはvault方式(§7.4)で保存する(bm_keyring_import_identity)。 */
    int rc = bm_keyring_import_identity(config->identity_db, address, label != NULL ? label : "",
                                         (int)version, (int)stream, pub_signing, pub_encryption,
                                         priv_signing, priv_encryption, store_passphrase,
                                         nonce_trials, payload_extra);
    if (rc != 0)
    {
        *out_error = dup_cstr("failed to store identity (duplicate address, or storePassphrase "
                              "does not match the existing vault passphrase?)");
        return NULL;
    }
    if (cJSON_IsTrue(is_chan_v))
    {
        bm_keyring_mark_as_chan(config->identity_db, address);
    }
    return cJSON_CreateBool(1);
}

/*
 * §11 2026-08-29 importAddressesBulk: [entries, storePassphrase]
 * entries = [{address, signingWIF, encryptionWIF, label?, nonceTrialsPerByte?,
 *             payloadLengthExtraBytes?, isChan?}, ...]
 *
 * 実測で判明した問題への対応: importAddressを1件ずつ個別のHTTPリクエストで呼ぶと、
 * リクエストごとにvaultのmaster KEK導出(scrypt、約161ms)が再実行されてしまい、
 * vault方式にした高速化の効果が全く出ない(5000件で約15分、単純ループ版と大差ない)。
 * このAPIは1回の呼び出し内でmaster KEKを1回だけ導出し、全entriesのHKDF-Expandに使い回す。
 * 戻り値は各entryの成否配列[{address, success, error?}]。1件の失敗(WIF不正・アドレス
 * 重複等)は他のentryの処理を中断しない。CLI(import-keys-dat)はHTTPリクエストボディの
 * 1MiB上限(MAX_REQUEST_SIZE)に収まるようentriesを数百件単位のチャンクに分けて
 * このAPIを複数回呼ぶ想定。
 */
static cJSON *h_importAddressesBulk(const struct bm_api_server_config *config,
                                               const cJSON *params, char **out_error)
{
    const cJSON *entries = param_at(params, 0);
    const char *store_passphrase = param_str(params, 1);
    if (!cJSON_IsArray(entries) || store_passphrase == NULL)
    {
        *out_error = dup_cstr("importAddressesBulk requires [entries, storePassphrase]");
        return NULL;
    }

    unsigned char master_kek[32];
    if (bm_keyring_resolve_or_create_vault_master_kek(config->identity_db, store_passphrase, master_kek) != 0)
    {
        *out_error = dup_cstr("storePassphrase does not match the existing vault passphrase");
        return NULL;
    }

    cJSON *results = cJSON_CreateArray();
    for (size_t i = 0; i < (size_t)cJSON_GetArraySize(entries); i++)
    {
        const cJSON *entry = param_at(entries, i);
        const char *address = json_cstr(json_obj_get(entry, "address"));
        const char *signing_wif = json_cstr(json_obj_get(entry, "signingWIF"));
        const char *encryption_wif = json_cstr(json_obj_get(entry, "encryptionWIF"));
        const char *label = json_cstr(json_obj_get(entry, "label"));
        const cJSON *nonce_v = json_obj_get(entry, "nonceTrialsPerByte");
        const cJSON *payload_v = json_obj_get(entry, "payloadLengthExtraBytes");
        const cJSON *is_chan_v = json_obj_get(entry, "isChan");

        cJSON *result_entry = cJSON_CreateObject();
        cJSON_AddItemToObject(result_entry, "address", json_str(address != NULL ? address : "(missing)"));

        const char *err = NULL;
        uint64_t version = 0;
        uint64_t stream = 0;
        unsigned char ripe_from_address[BM_RIPE_LEN];
        unsigned char priv_signing[BM_PRIVATE_KEY_LEN];
        unsigned char priv_encryption[BM_PRIVATE_KEY_LEN];
        unsigned char pub_signing[BM_PUBLIC_KEY_LEN];
        unsigned char pub_encryption[BM_PUBLIC_KEY_LEN];

        if (address == NULL || signing_wif == NULL || encryption_wif == NULL)
        {
            err = "missing address/signingWIF/encryptionWIF";
        }
        else if (bm_address_decode(address, &version, &stream, ripe_from_address) != 0)
        {
            err = "invalid address";
        }
        else if (bm_address_decode_wif(signing_wif, priv_signing) != 0
                 || bm_address_decode_wif(encryption_wif, priv_encryption) != 0)
        {
            err = "invalid WIF";
        }
        else if (bm_address_get_public_key(priv_signing, pub_signing) != 0
                 || bm_address_get_public_key(priv_encryption, pub_encryption) != 0)
        {
            err = "failed to derive public key from WIF";
        }
        else
        {
            unsigned char ripe_computed[BM_RIPE_LEN];
            bm_address_calc_ripe(pub_signing, pub_encryption, ripe_computed);
            if (memcmp(ripe_computed, ripe_from_address, BM_RIPE_LEN) != 0)
            {
                err = "WIF keys do not match the given address";
            }
        }

        if (err == NULL)
        {
            uint64_t nonce_trials = (nonce_v != NULL) ? (uint64_t)json_num(nonce_v)
                                                        : config->default_nonce_trials_per_byte;
            uint64_t payload_extra = (payload_v != NULL) ? (uint64_t)json_num(payload_v)
                                                            : config->default_payload_length_extra_bytes;
            int rc = bm_keyring_import_identity_with_master_kek(
                config->identity_db, address, label != NULL ? label : "", (int)version, (int)stream, pub_signing,
                pub_encryption, priv_signing, priv_encryption, master_kek, nonce_trials, payload_extra);
            if (rc != 0)
            {
                err = "failed to store identity (duplicate address?)";
            }
            else if (cJSON_IsTrue(is_chan_v))
            {
                bm_keyring_mark_as_chan(config->identity_db, address);
            }
        }

        cJSON_AddItemToObject(result_entry, "success", cJSON_CreateBool(err == NULL));
        if (err != NULL)
        {
            cJSON_AddItemToObject(result_entry, "error", json_str(err));
        }
        cJSON_AddItemToArray(results, result_entry);
    }

    OPENSSL_cleanse(master_kek, sizeof(master_kek));
    return results;
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
 * to_pub_encryptionを渡さなくてもfrom_id自身のpub_encryptionが自動的に使われる)。
 * 受信側はtrial_decrypt(core/trial_decrypt.c)が既にkeyring中の全identityを試すため、
 * chan用の鍵をunlockしてさえいれば新規の受信処理は不要で、他メンバーの投稿も自動的に
 * inboxへ復号される。
 */
static cJSON *h_joinChan(const struct bm_api_server_config *config,
                                    const cJSON *params, char **out_error)
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

    cJSON *result = json_str(address);
    free(address);
    return result;
}

/*
 * sendMessage: [fromAddress, toAddress, subject, body, ttlSeconds?, ackStealthLevel?]
 *
 * 宛先の公開暗号鍵は常にpubkey_cache(§2.3、cachePubkeyメソッド参照)をto_addressのripeで
 * 検索して使う。見つからなければ、能動的にgetpubkey要求を自動broadcastしたうえで送信失敗を
 * 返す(§5.0「getpubkey要求の自動化」参照)。応答が届き自動キャッシュされ次第、改めて
 * sendMessageを呼び直せば送信できる。
 *
 * §11 2026-08-30 toPubEncryptionHexを引数から削除した(呼び出し側が任意のhexを渡せる=
 * toAddressと無関係の鍵で暗号化できてしまい、①意図しない相手しか復号できないメッセージを
 * 送ってしまう、②検証されない鍵がそのままpubkey_cacheへ自動upsertされ以後の送信も汚染する、
 * という2つの実害があった(ユーザー指摘)。相手の鍵を事前に知っている場合はcachePubkeyで
 * 明示的に登録してからtoPubEncryptionHex省略でsendMessageする2段階操作に一本化する。
 */

/*
 * cachePubkey: [address, signingPubkeyHex(130桁hex), encryptionPubkeyHex(130桁hex)]
 *
 * 手動でpubkey_cacheへ相手の公開鍵を登録する。§11 2026-08-30以降、sendMessageは常に
 * pubkey_cache経由でしか宛先の鍵を解決しない(toPubEncryptionHex直接指定は廃止)ため、
 * 既に知っている相手の公開鍵を送信前に登録しておく唯一の手段になった。
 */
static cJSON *h_cachePubkey(const struct bm_api_server_config *config,
                                       const cJSON *params, char **out_error)
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
    return cJSON_CreateBool(1);
}

static cJSON *h_sendMessage(const struct bm_api_server_config *config,
                                       const cJSON *params, char **out_error)
{
    const char *from_address = param_str(params, 0);
    const char *to_address = param_str(params, 1);
    const char *subject = param_str(params, 2);
    const char *body = param_str(params, 3);
    const cJSON *ttl_v = param_at(params, 4);
    const cJSON *stealth_v = param_at(params, 5);

    if (from_address == NULL || to_address == NULL || subject == NULL || body == NULL)
    {
        *out_error = dup_cstr("sendMessage requires [fromAddress, toAddress, subject, body, "
                              "ttlSeconds?, ackStealthLevel?]. The recipient's public key is always "
                              "resolved from pubkey_cache; register it first via cachePubkey if needed.");
        return NULL;
    }

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

    uint64_t ttl_seconds = ttl_v != NULL ? (uint64_t)json_num(ttl_v) : (uint64_t)(2 * 24 * 60 * 60);
    int ack_stealth_level = stealth_v != NULL ? (int)json_num(stealth_v) : 1;

    unsigned char *object = NULL;
    size_t object_len = 0;
    int64_t next_resend_time = (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS;
    int rc = bm_send_pipeline_send_message(config->keyring, config->identity_db, config->messages_db,
                                            from_address, to_address,
                                            subject, body, ttl_seconds, ack_stealth_level,
                                            NULL, next_resend_time,
                                            &object, &object_len);
    if (rc != 0)
    {
        *out_error = dup_cstr("send failed (is fromAddress unlocked? is toAddress valid? if "
                              "the recipient's key was not yet cached, a getpubkey request was "
                              "broadcast automatically; retry sendMessage once it has been "
                              "received, or supply it directly via cachePubkey)");
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

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "objectLength", cJSON_CreateNumber((double)object_len));
    cJSON_AddItemToObject(result, "inventoryHash", json_str(inv_hex));
    return result;
}

/* sendBroadcast: [fromAddress, subject, body, ttlSeconds?]。§5.4/§11 */
static cJSON *h_sendBroadcast(const struct bm_api_server_config *config,
                                         const cJSON *params, char **out_error)
{
    const char *from_address = param_str(params, 0);
    const char *subject = param_str(params, 1);
    const char *body = param_str(params, 2);
    const cJSON *ttl_v = param_at(params, 3);

    if (from_address == NULL || subject == NULL || body == NULL)
    {
        *out_error = dup_cstr("sendBroadcast requires [fromAddress, subject, body, ttlSeconds?]");
        return NULL;
    }
    uint64_t ttl_seconds = ttl_v != NULL ? (uint64_t)json_num(ttl_v) : (uint64_t)(2 * 24 * 60 * 60);

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

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "objectLength", cJSON_CreateNumber((double)object_len));
    cJSON_AddItemToObject(result, "inventoryHash", json_str(inv_hex));
    return result;
}

/* getInboxMessages: [folder?](省略時は全件、'inbox'/'trash'等で絞り込み可) */
static cJSON *h_addSubscription(const struct bm_api_server_config *config,
                                           const cJSON *params, char **out_error)
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
    return cJSON_CreateBool(rc == 0);
}

static cJSON *h_removeSubscription(const struct bm_api_server_config *config,
                                              const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("removeSubscription requires [address]");
        return NULL;
    }
    int rc = bm_messages_store_remove_subscription(config->messages_db, address);
    return cJSON_CreateBool(rc == 0);
}

static cJSON *h_listSubscriptions(const struct bm_api_server_config *config,
                                             const cJSON *params, char **out_error)
{
    (void)params;

    struct bm_subscription *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_subscriptions(config->messages_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list subscriptions");
        return NULL;
    }

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "address", json_str(list[i].address));
        cJSON_AddItemToObject(entry, "label", json_str(list[i].label));
        cJSON_AddItemToArray(arr, entry);
    }
    bm_subscription_list_free(list);
    return arr;
}

/*
 * §11 2026-08-29 アドレス帳(address_book)。PyBitmessage本家api.pyの
 * addAddressBookEntry/deleteAddressBookEntry/listAddressBookEntries準拠(base64ラップは
 * 本実装のJSON-RPCでは不要なため省略)。addAddressBookEntryは本家同様、既に同じaddressが
 * あればエラーにする(UPSERTしない)。
 */
static cJSON *h_addAddressBookEntry(const struct bm_api_server_config *config,
                                               const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    const char *label = param_str(params, 1);
    if (address == NULL || label == NULL)
    {
        *out_error = dup_cstr("addAddressBookEntry requires [address, label]");
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

    if (bm_messages_store_add_address_book_entry(config->messages_db, address, label) != 0)
    {
        *out_error = dup_cstr("address already exists in address book");
        return NULL;
    }
    return cJSON_CreateBool(1);
}

static cJSON *h_deleteAddressBookEntry(const struct bm_api_server_config *config,
                                                  const cJSON *params, char **out_error)
{
    const char *address = param_str(params, 0);
    if (address == NULL)
    {
        *out_error = dup_cstr("deleteAddressBookEntry requires [address]");
        return NULL;
    }
    int rc = bm_messages_store_remove_address_book_entry(config->messages_db, address);
    return cJSON_CreateBool(rc == 0);
}

static cJSON *h_listAddressBookEntries(const struct bm_api_server_config *config,
                                                  const cJSON *params, char **out_error)
{
    (void)params;

    struct bm_address_book_entry *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_address_book(config->messages_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list address book");
        return NULL;
    }

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "address", json_str(list[i].address));
        cJSON_AddItemToObject(entry, "label", json_str(list[i].label));
        cJSON_AddItemToArray(arr, entry);
    }
    bm_address_book_list_free(list);
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

static cJSON *get_socks_proxy_common(const struct bm_api_server_config *config,
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

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "enabled", cJSON_CreateBool(proxy.enabled));
    cJSON_AddItemToObject(result, "host", json_str(proxy.host));
    cJSON_AddItemToObject(result, "port", cJSON_CreateNumber((double)proxy.port));
    return result;
}

static cJSON *set_socks_proxy_common(const struct bm_api_server_config *config,
                                                const cJSON *params, socks_proxy_setter_t setter,
                                                const char *usage_error, char **out_error)
{
    if (config->config_db == NULL)
    {
        *out_error = dup_cstr("config store is not available");
        return NULL;
    }

    const cJSON *enabled_v = param_at(params, 0);
    const char *host = param_str(params, 1);
    const cJSON *port_v = param_at(params, 2);
    if (enabled_v == NULL || host == NULL || port_v == NULL)
    {
        *out_error = dup_cstr(usage_error);
        return NULL;
    }

    struct bm_socks_proxy_config proxy;
    memset(&proxy, 0, sizeof(proxy));
    proxy.enabled = (json_num(enabled_v) != 0.0) ? 1 : 0;
    if (strlen(host) == 0 || strlen(host) >= sizeof(proxy.host))
    {
        *out_error = dup_cstr("host must be non-empty and shorter than 256 bytes");
        return NULL;
    }
    strncpy(proxy.host, host, sizeof(proxy.host) - 1);
    proxy.port = (int)json_num(port_v);
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
    return cJSON_CreateBool(1);
}

/* getSocksProxyOnion: [] -> {enabled, host, port}(onion peer(.onion宛)専用) */
static cJSON *h_getSocksProxyOnion(const struct bm_api_server_config *config,
                                              const cJSON *params, char **out_error)
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
static cJSON *h_setSocksProxyOnion(const struct bm_api_server_config *config,
                                              const cJSON *params, char **out_error)
{
    return set_socks_proxy_common(config, params, bm_config_store_set_socks_proxy_onion,
                                   "setSocksProxyOnion requires [enabled, host, port]", out_error);
}

/* getSocksProxyClearnet: [] -> {enabled, host, port}(クリアネットIP宛専用、既定disabled=直結) */
static cJSON *h_getSocksProxyClearnet(const struct bm_api_server_config *config,
                                                 const cJSON *params, char **out_error)
{
    (void)params;
    return get_socks_proxy_common(config, bm_config_store_get_socks_proxy_clearnet, out_error);
}

/* setSocksProxyClearnet: [enabled, host, port](クリアネットIP宛専用) */
static cJSON *h_setSocksProxyClearnet(const struct bm_api_server_config *config,
                                                 const cJSON *params, char **out_error)
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
static cJSON *h_addPeer(const struct bm_api_server_config *config,
                                   const cJSON *params, char **out_error)
{
    if (config->peers_db == NULL)
    {
        *out_error = dup_cstr("peer store is not available");
        return NULL;
    }

    const char *ip_address = param_str(params, 0);
    const cJSON *port_v = param_at(params, 1);
    const cJSON *stream_v = param_at(params, 2);
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

    int port = (int)json_num(port_v);
    if (port <= 0 || port > 65535)
    {
        *out_error = dup_cstr("port must be between 1 and 65535");
        return NULL;
    }
    int stream = stream_v != NULL ? (int)json_num(stream_v) : 1;

    if (bm_peer_manager_upsert_learned(config->peers_db, ip_address, port, stream, 1,
                                        (int64_t)time(NULL), "manual") != 0)
    {
        *out_error = dup_cstr("failed to store peer");
        return NULL;
    }
    return cJSON_CreateBool(1);
}

/*
 * listConnections: [] -> {inbound: [{host,port,fullyEstablished,userAgent}], outbound: [...]}
 * §11 2026-08-23 backlog項目5。PyBitmessage(api.pyのHandleListConnections)と同じ形。
 * ヘッドレスdaemonのGUI Network Statusタブ相当として、現在接続中のpeer一覧を返す。
 */
struct list_connections_ctx
{
    cJSON *inbound;
    cJSON *outbound;
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

    cJSON *entry = cJSON_CreateObject();
    cJSON_AddItemToObject(entry, "host", json_str(ip));
    cJSON_AddItemToObject(entry, "port", cJSON_CreateNumber((double)port));
    /* §11 2026-09-05: デバッグ用にregistry上の実fd番号を追加(ユーザー要望、"failed to send
     * inv to fd=N"ログ調査中に必要になった)。broadcast_inv側のログに出るfdはpeer_registry.c
     * のdup()で複製した使い捨て番号(書き込み後すぐclose()される)であり、この値とは無関係
     * なので、他の接続と誤って対応付けないよう混同しないこと。 */
    cJSON_AddItemToObject(entry, "fd", cJSON_CreateNumber((double)conn->fd));
    cJSON_AddItemToObject(entry, "fullyEstablished", cJSON_CreateBool(conn->handshake_complete));
    cJSON_AddItemToObject(entry, "userAgent", json_str(conn->user_agent != NULL ? conn->user_agent : ""));
    /* §11 2026-08-23 backlog項目5(送受信バイト数、後半分)。PyBitmessage自体には
     * 無い機能(本家のadvanceddispatcher.pyのsentBytes/receivedBytesはどこからも
     * 参照・表示されない実質デッドなフィールドだった、DESIGN.md参照)。受信バイト数は
     * 全経路を正確に集計できるが、送信バイト数はbroadcast_inv経由(dup()したfdへの
     * 書き込み、connを持たない)の分だけこの接続の集計に含められない(ユーザー了承済み、
     * 全体累積のgetNetworkStatsには含まれる)。 */
    cJSON_AddItemToObject(entry, "sentBytes", cJSON_CreateNumber((double)conn->bytes_sent));
    cJSON_AddItemToObject(entry, "receivedBytes", cJSON_CreateNumber((double)conn->bytes_received));

    cJSON_AddItemToArray(conn->type == BM_FD_SERVER_SOCKET ? ctx->inbound : ctx->outbound, entry);
}

static cJSON *h_listConnections(const struct bm_api_server_config *config,
                                           const cJSON *params, char **out_error)
{
    (void)params;
    if (config->registry == NULL)
    {
        *out_error = dup_cstr("connection registry is not available");
        return NULL;
    }

    struct list_connections_ctx ctx;
    ctx.inbound = cJSON_CreateArray();
    ctx.outbound = cJSON_CreateArray();
    /* §11 2026-08-23: for_each_locked(APIサーバスレッドからの呼び出し専用の変種)を使う。
     * 通常のfor_eachはロックを早期解放するため、network_epoll_thread側で該当connが
     * close_connection経由でfree()されるuse-after-freeを起こしうる(peer_registry.h参照)。 */
    bm_peer_registry_for_each_locked(config->registry, list_connections_one, &ctx);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "inbound", ctx.inbound);
    cJSON_AddItemToObject(result, "outbound", ctx.outbound);
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
static cJSON *h_getNetworkStats(const struct bm_api_server_config *config,
                                           const cJSON *params, char **out_error)
{
    (void)config;
    (void)params;
    (void)out_error;

    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    bm_network_get_stats(&bytes_sent, &bytes_received);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "sentBytes", cJSON_CreateNumber((double)bytes_sent));
    cJSON_AddItemToObject(result, "receivedBytes", cJSON_CreateNumber((double)bytes_received));
    return result;
}

static cJSON *h_getInboxMessages(const struct bm_api_server_config *config,
                                            const cJSON *params, char **out_error)
{
    const char *folder = param_str(params, 0);

    struct bm_inbox_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_inbox(config->messages_db, folder, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list inbox");
        return NULL;
    }

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        char msg_id_hex[65];
        hex_encode(list[i].msg_id, sizeof(list[i].msg_id), msg_id_hex);

        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "msgId", json_str(msg_id_hex));
        cJSON_AddItemToObject(entry, "toAddress", json_str(list[i].to_address));
        cJSON_AddItemToObject(entry, "fromAddress", json_str(list[i].from_address));
        cJSON_AddItemToObject(entry, "subject", json_str(list[i].subject));
        cJSON_AddItemToObject(entry, "body", json_str(list[i].body));
        cJSON_AddItemToObject(entry, "receivedTime", cJSON_CreateNumber((double)list[i].received_time));
        cJSON_AddItemToObject(entry, "read", cJSON_CreateBool(list[i].read));
        cJSON_AddItemToObject(entry, "folder", json_str(list[i].folder));
        cJSON_AddItemToArray(arr, entry);
    }
    bm_inbox_message_list_free(list, count);
    return arr;
}

/* §11 2026-08-25: getSentMessages: [] -> [{msgId,toAddress,fromAddress,subject,body,status,
 * sentTime,ttl,resendCount}, ...]。sentテーブルはこれまでack追跡専用でユーザー向けの一覧
 * 手段が無かった(getInboxMessagesに相当するものが未実装だった)ため追加。 */
static cJSON *h_getSentMessages(const struct bm_api_server_config *config,
                                           const cJSON *params, char **out_error)
{
    (void)params;

    struct bm_sent_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_sent(config->messages_db, &list, &count) != 0)
    {
        *out_error = dup_cstr("failed to list sent");
        return NULL;
    }

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
    {
        char msg_id_hex[65];
        hex_encode(list[i].msg_id, sizeof(list[i].msg_id), msg_id_hex);

        cJSON *entry = cJSON_CreateObject();
        cJSON_AddItemToObject(entry, "msgId", json_str(msg_id_hex));
        cJSON_AddItemToObject(entry, "toAddress", json_str(list[i].to_address));
        cJSON_AddItemToObject(entry, "fromAddress", json_str(list[i].from_address));
        cJSON_AddItemToObject(entry, "subject", json_str(list[i].subject));
        cJSON_AddItemToObject(entry, "body", json_str(list[i].body));
        cJSON_AddItemToObject(entry, "status", json_str(list[i].status));
        cJSON_AddItemToObject(entry, "sentTime", cJSON_CreateNumber((double)list[i].sent_time));
        cJSON_AddItemToObject(entry, "ttl", cJSON_CreateNumber((double)list[i].ttl));
        cJSON_AddItemToObject(entry, "resendCount", cJSON_CreateNumber((double)list[i].resend_count));
        cJSON_AddItemToArray(arr, entry);
    }
    bm_sent_message_list_free(list, count);
    return arr;
}

/* §11 2026-08-30: trashMessage: [msgId(hex)] -> bool。PyBitmessage本家api.pyの
 * HandleTrashMessage準拠。msgIdがinbox/sentのどちらの行を指しているか呼び出し側は
 * 意識しなくてよいよう、両テーブルに対してfolder='trash'更新を無条件に試みる(該当行が
 * 無くてもエラーにしない、「存在したと仮定して削除した」という本家と同じ応答仕様)。
 * SQL自体が失敗した場合(DBエラー等)のみエラーを返す。 */
static cJSON *h_trashMessage(const struct bm_api_server_config *config,
                                        const cJSON *params, char **out_error)
{
    const char *msg_id_hex = param_str(params, 0);
    if (msg_id_hex == NULL)
    {
        *out_error = dup_cstr("trashMessage requires [msgId]");
        return NULL;
    }
    unsigned char msg_id[32];
    if (hex_decode_fixed(msg_id_hex, msg_id, sizeof(msg_id)) != 0)
    {
        *out_error = dup_cstr("msgId must be a 64-character hex string");
        return NULL;
    }

    int inbox_rc = bm_messages_store_trash_inbox_message(config->messages_db, msg_id);
    int sent_rc = bm_messages_store_trash_sent_message(config->messages_db, msg_id);
    if (inbox_rc != 0 && sent_rc != 0)
    {
        *out_error = dup_cstr("failed to trash message");
        return NULL;
    }
    return cJSON_CreateBool(1);
}

static const struct bm_api_method METHODS[] = {
    {"unlockAddress", h_unlockAddress},
    {"unlockAllAddresses", h_unlockAllAddresses},
    {"exportAddress", h_exportAddress},
    {"lockAddress", h_lockAddress},
    {"lockAllAddresses", h_lockAllAddresses},
    {"deleteAddress", h_deleteAddress},
    {"listAddresses", h_listAddresses},
    {"createDeterministicAddress", h_createDeterministicAddress},
    {"setAddressLabel", h_setAddressLabel},
    {"importAddress", h_importAddress},
    {"importAddressesBulk", h_importAddressesBulk},
    {"joinChan", h_joinChan},
    {"cachePubkey", h_cachePubkey},
    {"sendMessage", h_sendMessage},
    {"sendBroadcast", h_sendBroadcast},
    {"getInboxMessages", h_getInboxMessages},
    {"getSentMessages", h_getSentMessages},
    {"trashMessage", h_trashMessage},
    {"addSubscription", h_addSubscription},
    {"removeSubscription", h_removeSubscription},
    {"listSubscriptions", h_listSubscriptions},
    {"addAddressBookEntry", h_addAddressBookEntry},
    {"deleteAddressBookEntry", h_deleteAddressBookEntry},
    {"listAddressBookEntries", h_listAddressBookEntries},
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

/*
 * §11 2026-09-15 エラーコードを仕様(JSON-RPC 2.0 Specification §5.1)の予約値へ整理した。
 * 以前は全て-32000(実装定義のServer error)を返していたため、クライアント側が
 * 「JSONが壊れている」「メソッド名を間違えた」「メソッドは正しいが引数が不正」を
 * コードで区別できなかった。ハンドラが返すアプリケーション由来のエラーだけは引き続き
 * -32000とする(仕様上-32000〜-32099が実装定義用に予約されている)。
 */
#define BM_JSONRPC_ERR_PARSE (-32700)
#define BM_JSONRPC_ERR_INVALID_REQUEST (-32600)
#define BM_JSONRPC_ERR_METHOD_NOT_FOUND (-32601)
#define BM_JSONRPC_ERR_SERVER (-32000)

/*
 * §11 2026-09-15 バッチリクエスト1件あたりの上限。仕様に上限の定めは無いが、ボディの
 * 1MiB上限(MAX_REQUEST_SIZE)いっぱいまで最小サイズのリクエストを詰めると3万件強が入り、
 * それが全てunlockAddress(1件あたりscryptで約161ms)だと1リクエストでRPCサーバーを
 * 1時間以上占有できてしまう(ハンドラは直列実行のため、その間他のAPI呼び出しは待たされる)。
 * 認証済みクライアントしか到達できない経路とはいえ、事故(スクリプトのループミス)でも
 * 起きうるので上限を設ける。数千件規模の一括処理には専用のimportAddressesBulkのように
 * 「1メソッド呼び出しで多件数を扱う」設計を使うこと。
 */
#define BM_JSONRPC_MAX_BATCH_SIZE 256

/* 応答オブジェクトを1つ組み立てる。resultの所有権はこの関数が受け取る(error_msgが
 * 非NULLなら破棄される)。idはリクエストの値を複製して返す */
static cJSON *build_response(const cJSON *id, cJSON *result, int error_code, const char *error_msg)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "jsonrpc", json_str("2.0"));
    if (error_msg != NULL)
    {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddItemToObject(err, "code", cJSON_CreateNumber(error_code));
        cJSON_AddItemToObject(err, "message", json_str(error_msg));
        cJSON_AddItemToObject(resp, "error", err);
        cJSON_Delete(result);
    }
    else
    {
        cJSON_AddItemToObject(resp, "result", result != NULL ? result : cJSON_CreateNull());
    }

    /* idはリクエストの値をそのまま複製して返す(仕様上string/number/nullのみ。
     * それ以外の型が来た場合はnullにする) */
    if (cJSON_IsString(id) || cJSON_IsNumber(id))
    {
        cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));
    }
    else
    {
        cJSON_AddItemToObject(resp, "id", cJSON_CreateNull());
    }
    return resp;
}

/*
 * リクエストオブジェクト1件を処理する。応答オブジェクトを返す。
 *
 * §11 2026-09-15 通知(notification)対応。JSON-RPC 2.0では"id"メンバを持たないリクエストは
 * 通知であり、サーバーは応答を返してはならない(仕様§4.1)。以前は"id"が無くても
 * "id":nullを付けた応答を返していた。通知の場合はNULLを返し、呼び出し側が応答を
 * 組み立てないようにする。なお"id":nullは「idを明示的にnullにしたリクエスト」であって
 * 通知ではないため、従来通り応答する(cJSONでは前者はメンバ自体が無く、後者は
 * cJSON_NULL型のメンバとして存在するので区別できる)。
 */
static cJSON *process_one_request(const struct bm_api_server_config *config, const cJSON *req)
{
    if (!cJSON_IsObject(req))
    {
        return build_response(NULL, NULL, BM_JSONRPC_ERR_INVALID_REQUEST,
                               "Invalid request: not a JSON object");
    }

    const cJSON *id = json_obj_get(req, "id");
    int is_notification = (id == NULL);
    const char *method = json_cstr(json_obj_get(req, "method"));
    const cJSON *params = json_obj_get(req, "params");

    if (method == NULL)
    {
        if (is_notification)
        {
            return NULL;
        }
        return build_response(id, NULL, BM_JSONRPC_ERR_INVALID_REQUEST, "Invalid request: missing method");
    }

    for (size_t i = 0; i < METHOD_COUNT; i++)
    {
        if (strcmp(METHODS[i].name, method) == 0)
        {
            char *error_msg = NULL;
            cJSON *result = METHODS[i].handler(config, params, &error_msg);
            if (is_notification)
            {
                /* 通知でも副作用(ハンドラの実行)は起こした上で、応答だけを捨てる */
                cJSON_Delete(result);
                free(error_msg);
                return NULL;
            }
            cJSON *resp = build_response(id, result, BM_JSONRPC_ERR_SERVER, error_msg);
            free(error_msg);
            return resp;
        }
    }

    if (is_notification)
    {
        return NULL;
    }
    return build_response(id, NULL, BM_JSONRPC_ERR_METHOD_NOT_FOUND, "Method not found");
}

/*
 * リクエストボディ全体を処理し、応答本文(cJSONのアロケータで確保されたNUL終端文字列、
 * 呼び出し側がcJSON_freeで解放)を返す。応答を返してはならない場合(全て通知だった
 * バッチ、および単一の通知)はNULLを返す。
 *
 * §11 2026-09-15 バッチリクエスト対応(JSON-RPC 2.0 Specification §6)。以前はボディが
 * JSONオブジェクトであることを要求しており、仕様で定められたバッチ(リクエストオブジェクトの
 * 配列)を送ると"Parse error: invalid JSON"で拒否していた。libmicrohttpd + cJSONへの
 * 移行でディスパッチ層を書き直すのに合わせて実装した。応答は仕様通り、通知を除いた
 * 各リクエストの応答オブジェクトを要素とする配列で返す(順序はリクエスト順。仕様上
 * 順不同でよいがクライアント側の突き合わせが楽なので揃えておく)。
 */
static char *process_jsonrpc_request(const struct bm_api_server_config *config,
                                      const char *body, size_t body_len)
{
    cJSON *root = cJSON_ParseWithLength(body, body_len);
    if (root == NULL)
    {
        /* cJSONは構文エラーのほかCJSON_NESTING_LIMIT(既定1000)を超える深いネストでも
         * NULLを返す。自前パーサ時代はここに深さ制限が無く、深いネストを送りつけると
         * 再帰でスタックオーバーフローしdaemonごと落とせた(§11参照) */
        cJSON *resp = build_response(NULL, NULL, BM_JSONRPC_ERR_PARSE, "Parse error: invalid JSON");
        char *text = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return text;
    }

    if (!cJSON_IsArray(root))
    {
        cJSON *resp = process_one_request(config, root);
        cJSON_Delete(root);
        if (resp == NULL)
        {
            return NULL; /* 単一の通知: 応答なし */
        }
        char *text = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return text;
    }

    int count = cJSON_GetArraySize(root);
    if (count == 0 || count > BM_JSONRPC_MAX_BATCH_SIZE)
    {
        /* 空配列は仕様上Invalid Request(単一の応答オブジェクトを返す、配列では包まない) */
        char msg_buf[96];
        const char *msg;
        if (count == 0)
        {
            msg = "Invalid request: empty batch";
        }
        else
        {
            snprintf(msg_buf, sizeof(msg_buf), "Invalid request: batch too large (max %d requests)",
                      BM_JSONRPC_MAX_BATCH_SIZE);
            msg = msg_buf;
        }
        cJSON *resp = build_response(NULL, NULL, BM_JSONRPC_ERR_INVALID_REQUEST, msg);
        cJSON_Delete(root);
        char *text = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return text;
    }

    cJSON *responses = cJSON_CreateArray();
    for (int i = 0; i < count; i++)
    {
        cJSON *resp = process_one_request(config, cJSON_GetArrayItem(root, i));
        if (resp != NULL)
        {
            cJSON_AddItemToArray(responses, resp);
        }
    }
    cJSON_Delete(root);

    if (cJSON_GetArraySize(responses) == 0)
    {
        /* 全て通知だった場合、仕様上サーバーは何も返してはならない */
        cJSON_Delete(responses);
        return NULL;
    }
    char *text = cJSON_PrintUnformatted(responses);
    cJSON_Delete(responses);
    return text;
}

/* --- HTTPトランスポート(libmicrohttpd) --- */

/*
 * §11 2026-09-15 自前HTTP実装(ブロッキングread+自前のヘッダ探索)からlibmicrohttpdへ移行した。
 * 動機は「自前なので依存が減る」という抽象論ではなく、実際に確認できた次の2件の欠陥:
 *
 *  (1) 認証前DoS。旧read_until_double_crlf()はaccept済みfdに読み取りタイムアウトを一切
 *      設定せずread()でブロックし、accept loopもシングルスレッドだったため、TCP接続だけ
 *      して1バイトも送らないクライアント1つでRPCサーバー全体が無期限に停止した。しかも
 *      この停止はBasic認証の検証より手前で起きるので、apiusername/apipasswordを知らない
 *      相手でも発動できた。
 *  (2) Transfer-Encoding: chunked非対応。Content-Lengthヘッダが無いリクエストは
 *      400で拒否していたため、chunkedで送る汎用HTTPクライアントから使えなかった。
 *
 * MHDはノンブロッキングI/O+接続タイムアウト(MHD_OPTION_CONNECTION_TIMEOUT)でこれらを
 * 解決する。加えてkeep-alive・同時接続数制限(MHD_OPTION_CONNECTION_LIMIT)も得られる。
 *
 * スレッドモデルはMHD_USE_INTERNAL_POLLING_THREAD単独とし、MHD_USE_THREAD_PER_CONNECTIONも
 * スレッドプール(MHD_OPTION_THREAD_POOL_SIZE)も使わない。これはMHDが内部スレッド1本で
 * poll/epollループを回して複数接続を多重化しつつ、コールバックは常にその1本から直列に
 * 呼ぶモデルで、「同時に処理するリクエストは常に1件」という旧実装の前提をそのまま維持できる。
 * METHODS[]の各ハンドラはkeyring・registry・各DBハンドルといった共有状態を触っており、
 * 並列化するならそれら全ての排他制御を見直す必要があるため、今回の移行では意図的に
 * 直列のままにした(将来並列化したくなったら、このフラグを変える前に全ハンドラの
 * スレッド安全性を検証すること)。
 *
 * なお、これによりkeep-aliveが有効になったため「レスポンスを読んだ後EOFまで読む」実装の
 * クライアントは接続タイムアウトまで待たされる。本リポジトリのbitmessage-cli
 * (cli/http_client.c)とテストのHTTPヘルパーがまさにその実装だったので、リクエストに
 * Connection: closeを付けるよう合わせて修正してある。
 */

/* 接続がアイドルのまま維持される上限。keep-aliveで繋ぎっぱなしのクライアントを
 * 無制限に抱え込まないための値で、旧実装(1リクエストごとにclose)より厳しくはならない */
#define BM_API_CONNECTION_TIMEOUT_SECONDS 30
/* 同時接続数の上限。ローカルのフロントエンド/CLIしか繋がない想定なので小さめでよい */
#define BM_API_CONNECTION_LIMIT 64
/* stop_flagを見に行く間隔。MHDは内部スレッドで動くので、api_server_threadはこの間隔で
 * 停止指示だけを監視する(旧実装のpoll()タイムアウト1秒より短くし、停止を早めた) */
#define BM_API_STOP_POLL_INTERVAL_MS 250

/* リクエストごとの状態。MHDはボディを複数回のコールバックに分けて渡してくるので、
 * ここに連結して溜めてから一括でJSON-RPC処理へ回す */
struct api_request_ctx
{
    char *body;
    size_t body_len;
    size_t body_cap;
    int too_large; /* MAX_REQUEST_SIZE超過を検出したら1(以後のボディは捨てて413を返す) */
};

static enum MHD_Result queue_text_response(struct MHD_Connection *connection, unsigned int status,
                                            const char *body)
{
    /* MHD_RESPMEM_MUST_COPYなのでbodyが静的文字列でなくても安全 */
    struct MHD_Response *response =
        MHD_create_response_from_buffer(strlen(body), (void *)(uintptr_t)body, MHD_RESPMEM_MUST_COPY);
    if (response == NULL)
    {
        return MHD_NO;
    }
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
    enum MHD_Result rc = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return rc;
}

static enum MHD_Result queue_auth_required(struct MHD_Connection *connection)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen("Unauthorized\n"), (void *)(uintptr_t) "Unauthorized\n", MHD_RESPMEM_PERSISTENT);
    if (response == NULL)
    {
        return MHD_NO;
    }
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
    /* WWW-Authenticateヘッダの付与と401の設定はMHD側が行う(realmのクォート等も含めて
     * RFC 7617準拠に組み立ててくれるので自前で書式を作らない)。prefer_utf8=MHD_YESで
     * charset="UTF-8"を付け、非ASCIIのapipasswordでもクライアントの解釈が揺れないようにする */
    enum MHD_Result rc = MHD_queue_basic_auth_required_response3(connection, "bitmessage", MHD_YES, response);
    MHD_destroy_response(response);
    return rc;
}

static enum MHD_Result api_access_handler(void *cls, struct MHD_Connection *connection,
                                           const char *url, const char *method, const char *version,
                                           const char *upload_data, size_t *upload_data_size,
                                           void **req_cls)
{
    const struct bm_api_server_config *config = cls;
    (void)url;     /* パスは見ない(旧実装同様、どのパスでもJSON-RPCとして受ける) */
    (void)version;

    struct api_request_ctx *ctx = *req_cls;
    if (ctx == NULL)
    {
        /*
         * MHDはリクエストごとに、まずヘッダだけが揃った時点で1回このコールバックを呼ぶ
         * (この時点ではボディは未受信)。ここで応答をqueueすればボディの受信完了を待たずに
         * 返せるので、405・401はこのタイミングで返す。
         */
        if (strcmp(method, MHD_HTTP_METHOD_POST) != 0)
        {
            return queue_text_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "POST only\n");
        }
        if (!check_basic_auth(config, connection))
        {
            return queue_auth_required(connection);
        }
        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL)
        {
            return MHD_NO;
        }
        *req_cls = ctx;
        return MHD_YES;
    }

    if (*upload_data_size > 0)
    {
        size_t chunk = *upload_data_size;
        *upload_data_size = 0; /* 受け取った分は消費したとMHDへ伝える */
        if (ctx->too_large || ctx->body_len + chunk > MAX_REQUEST_SIZE)
        {
            ctx->too_large = 1;
            return MHD_YES;
        }
        if (ctx->body_len + chunk + 1 > ctx->body_cap)
        {
            size_t new_cap = ctx->body_cap == 0 ? 4096 : ctx->body_cap;
            while (new_cap < ctx->body_len + chunk + 1)
            {
                new_cap *= 2;
            }
            char *grown = realloc(ctx->body, new_cap);
            if (grown == NULL)
            {
                ctx->too_large = 1; /* 確保できないほど大きい、として413で返す */
                return MHD_YES;
            }
            ctx->body = grown;
            ctx->body_cap = new_cap;
        }
        memcpy(ctx->body + ctx->body_len, upload_data, chunk);
        ctx->body_len += chunk;
        return MHD_YES;
    }

    /* upload_data_size == 0 かつ2回目以降の呼び出し = ボディ受信完了 */
    if (ctx->too_large)
    {
        return queue_text_response(connection, MHD_HTTP_CONTENT_TOO_LARGE, "request body too large\n");
    }

    char *response_json = process_jsonrpc_request(config, ctx->body != NULL ? ctx->body : "", ctx->body_len);
    if (response_json == NULL)
    {
        /* JSON-RPCの通知のみだった場合、仕様上ボディを返してはならない(§6) */
        struct MHD_Response *response =
            MHD_create_response_from_buffer(0, (void *)(uintptr_t) "", MHD_RESPMEM_PERSISTENT);
        if (response == NULL)
        {
            return MHD_NO;
        }
        enum MHD_Result rc = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
        MHD_destroy_response(response);
        return rc;
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_json), response_json, MHD_RESPMEM_MUST_COPY);
    cJSON_free(response_json); /* cJSON_PrintUnformattedの戻り値はcJSONのアロケータ管理 */
    if (response == NULL)
    {
        return MHD_NO;
    }
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
    enum MHD_Result rc = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return rc;
}

/*
 * MHDの内部エラーログをbm_logへ流す(MHD_OPTION_EXTERNAL_LOGGER)。MHD_USE_ERROR_LOGだけを
 * 指定するとMHDが素のstderrへ直接書き、タイムスタンプもレベルタグも付かない行が
 * journalに混ざる。しかもその大半は"Connection was closed by remote side with incomplete
 * request."のような、ローカルの任意プロセスが接続と切断を繰り返すだけで出させられる
 * 内容なので、運用時のログを汚さないようDEBUGレベルへ落としてある(起動失敗のような
 * 本当に重要な事象はMHD_start_daemon()のNULL戻り値として別途bm_log_errorしている)。
 * MHDのメッセージは末尾に改行を含むため、こちらでは付け足さない。
 */
static void api_mhd_logger(void *cls, const char *fmt, va_list ap)
{
    (void)cls;
    bm_log_vleveled(BM_LOG_DEBUG, fmt, ap);
}

static void api_request_completed(void *cls, struct MHD_Connection *connection, void **req_cls,
                                   enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)connection;
    (void)toe;
    struct api_request_ctx *ctx = *req_cls;
    if (ctx != NULL)
    {
        free(ctx->body);
        free(ctx);
        *req_cls = NULL;
    }
}

void *bm_api_server_thread(void *arg)
{
    struct bm_api_server_thread_args *args = arg;
    const struct bm_api_server_config *config = args->config;

    char addr_buf[80];
    bm_network_format_host_port(config->bind_address, config->port, addr_buf, sizeof(addr_buf));

    /* MHD_OPTION_SOCK_ADDRで明示的にbindアドレスを指定する(省略するとINADDR_ANYになり、
     * 既定の127.0.0.1バインドという§6.1の決定を破ってしまう)。MHDはMHD_start_daemon()の
     * 実行中にこのsockaddrをbind()へ渡すだけでポインタを保持しないので、スタック変数でよい */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)config->port);
    if (inet_pton(AF_INET, config->bind_address, &addr.sin_addr) != 1)
    {
        bm_log_error("[api_server] invalid bind address %s\n", config->bind_address);
        free(args);
        return NULL;
    }

    struct MHD_Daemon *daemon =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, (uint16_t)config->port,
                          NULL, NULL, &api_access_handler, (void *)(uintptr_t)config,
                          /* EXTERNAL_LOGGERは必ず先頭に置く。後ろに置くと
                           * 「MHD_OPTION_EXTERNAL_LOGGER is not the first option specified
                           * for the daemon. Some messages may be printed by the standard
                           * MHD logger.」という警告が出て、それ以前の処理で出たメッセージは
                           * 素のstderrへ流れてしまう */
                          MHD_OPTION_EXTERNAL_LOGGER, &api_mhd_logger, NULL,
                          MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&addr,
                          MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)BM_API_CONNECTION_TIMEOUT_SECONDS,
                          MHD_OPTION_CONNECTION_LIMIT, (unsigned int)BM_API_CONNECTION_LIMIT,
                          MHD_OPTION_NOTIFY_COMPLETED, &api_request_completed, NULL,
                          MHD_OPTION_END);
    if (daemon == NULL)
    {
        bm_log_error("[api_server] failed to listen on %s\n", addr_buf);
        free(args);
        return NULL;
    }
    bm_log_info("[api_server] listening on %s\n", addr_buf);

    /*
     * MHDは内部スレッドで動くので、このスレッド自身はstop_flagの監視だけを行う
     * (peer_connector_thread等と同じポーリング方式)。poll(NULL, 0, ms)を単なるsleepとして
     * 使っている。EINTRで早く起きても次のループでstop_flagを見直すだけなので害はない。
     */
    while (*args->stop_flag == 0)
    {
        poll(NULL, 0, BM_API_STOP_POLL_INTERVAL_MS);
    }

    MHD_stop_daemon(daemon);
    bm_log_info("[api_server] stopped\n");
    free(args);
    return NULL;
}
