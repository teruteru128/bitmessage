#ifndef BM_CORE_IDENTITY_STORE_H
#define BM_CORE_IDENTITY_STORE_H

/* identity.db(§2.3)の操作。秘密鍵は常にラップ済み(§7.1)の状態でのみこのモジュールを通る。
 * 平文鍵の復号(unlock)自体はkeyring.cの責務。 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#define BM_IDENTITY_ADDRESS_MAX 40
#define BM_IDENTITY_LABEL_MAX 128
#define BM_IDENTITY_KDF_ALGO_MAX 16
#define BM_IDENTITY_KDF_PARAMS_MAX 128
#define BM_IDENTITY_KDF_SALT_LEN 16
#define BM_IDENTITY_WRAPPED_KEY_LEN 60 /* AES-256-GCM: nonce(12)+ciphertext(32)+tag(16) */

struct bm_identity_row
{
    char address[BM_IDENTITY_ADDRESS_MAX];
    char label[BM_IDENTITY_LABEL_MAX];
    int enabled;
    int is_chan;
    int address_version;
    int stream;
    unsigned char signing_pubkey[65];
    unsigned char encryption_pubkey[65];
    char kdf_algo[BM_IDENTITY_KDF_ALGO_MAX];
    unsigned char kdf_salt[BM_IDENTITY_KDF_SALT_LEN];
    char kdf_params[BM_IDENTITY_KDF_PARAMS_MAX]; /* 例: {"N":32768,"r":8,"p":1} */
    unsigned char wrapped_priv_signing_key[BM_IDENTITY_WRAPPED_KEY_LEN];
    unsigned char wrapped_priv_encryption_key[BM_IDENTITY_WRAPPED_KEY_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    int64_t created_time;
};

int bm_identity_store_init_schema(sqlite3 *db);

/* 成功時0。既に同じaddressが存在する場合は失敗する(INSERT、UPSERTしない) */
int bm_identity_store_insert(sqlite3 *db, const struct bm_identity_row *row);

/* 見つかれば0、見つからない/エラー時は非0 */
int bm_identity_store_load(sqlite3 *db, const char *address, struct bm_identity_row *out);

int bm_identity_store_delete(sqlite3 *db, const char *address);

/* §11 chan仕様: is_chanフラグを更新する。該当行が無くてもエラーにしない。成功時0 */
int bm_identity_store_set_is_chan(sqlite3 *db, const char *address, int is_chan);

struct bm_identity_summary
{
    char address[BM_IDENTITY_ADDRESS_MAX];
    char label[BM_IDENTITY_LABEL_MAX];
    int enabled;
    int is_chan;
};

/*
 * 全identityの一覧を取得する(malloc、呼び出し側でfreeすること)。成功時0、
 * *out_countに件数を設定する(0件でも成功)。
 */
int bm_identity_store_list(sqlite3 *db, struct bm_identity_summary **out_list, size_t *out_count);

#endif /* BM_CORE_IDENTITY_STORE_H */
