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

/*
 * §11 2026-08-29 setAddressLabel用。PyBitmessage本家にはJSON-RPC API経由でのラベル変更は
 * 無いが、GUI(bitmessageqt)は`config.set(address, 'label', newLabel)`で直接変更できており、
 * 本実装ではこれをAPI経由で提供する独自拡張として追加した(keys.datインポート時のUTF-8文字化け
 * バグ(§11参照)修正後、既にインポート済みのラベルを正しい値へ再設定する用途)。
 * 該当addressが存在しなければ非0(sqlite3_changes==0を検出)。成功時0。
 */
int bm_identity_store_update_label(sqlite3 *db, const char *address, const char *label);

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

/*
 * §7.4 2026-08-29 数千件規模の一括unlock向け2段階KDF方式(DESIGN.md §11-19)。
 * kdf_vaultは単一行のみ(id=0固定)。全identityで共有するvault_saltを保持し、
 * ここからpassphrase→master KEKの重いKDF(scrypt)を1回だけ行う。各identity行の
 * 実ラップ鍵はmaster KEK + その行のkdf_saltをHKDF-Expandした軽量な派生で導出する
 * (identities.kdf_algo='vault-hkdf'の行がこの方式、'scrypt'は従来の個別KDF方式)。
 */
#define BM_IDENTITY_VAULT_SALT_LEN BM_IDENTITY_KDF_SALT_LEN

/*
 * kdf_vaultを読む。まだ作られていなければ非0を返す(vault未作成、旧方式のみの状態)。
 * out_canaryは「master KEKが正しいか」を呼び出し側(keyring.c)が検証するための
 * 既知平文のラップ値(§7.4、下記コメント参照)。
 */
int bm_identity_store_load_vault(sqlite3 *db, unsigned char out_vault_salt[BM_IDENTITY_VAULT_SALT_LEN],
                                  char out_kdf_params[BM_IDENTITY_KDF_PARAMS_MAX],
                                  unsigned char out_canary[BM_IDENTITY_WRAPPED_KEY_LEN]);

/*
 * kdf_vaultを新規作成する(既に存在する場合は失敗させる、INSERT)。成功時0。
 *
 * §7.4 2026-08-29 canaryを持たせる理由: scryptは誤ったpassphraseでも必ず何らかの
 * 32byte値を返すため、「vaultは既にあるが異なるpassphraseでunlockAllAddressesを
 * 呼んだ」場合にmaster KEKの正誤を判定する手段が無いと、たまたま旧方式(個別scrypt)の
 * 行がその誤ったpassphraseと一致した際、誤ったmaster KEKでre-wrapしてvault全体を
 * 破壊しかねない(以後正しいpassphraseでも復号不能になる)。vault作成時に既知の固定
 * 平文をmaster KEKでラップしたcanaryを保存しておき、以後の呼び出しでは必ずこの
 * canaryを復号できることを確認してからmaster KEKを使う。
 */
int bm_identity_store_create_vault(sqlite3 *db, const unsigned char vault_salt[BM_IDENTITY_VAULT_SALT_LEN],
                                    const char *kdf_params, const unsigned char canary[BM_IDENTITY_WRAPPED_KEY_LEN]);

/*
 * 既存行のKDF方式・salt・ラップ済み鍵を書き換える(旧scrypt方式からvault-hkdf方式へのre-wrap用)。
 * 成功時0。
 */
int bm_identity_store_update_wrapped_keys(sqlite3 *db, const char *address, const char *kdf_algo,
                                           const unsigned char kdf_salt[BM_IDENTITY_KDF_SALT_LEN],
                                           const unsigned char wrapped_priv_signing_key[BM_IDENTITY_WRAPPED_KEY_LEN],
                                           const unsigned char wrapped_priv_encryption_key[BM_IDENTITY_WRAPPED_KEY_LEN]);

#endif /* BM_CORE_IDENTITY_STORE_H */
