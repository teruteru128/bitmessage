#ifndef BM_CORE_KEYRING_INTERNAL_H
#define BM_CORE_KEYRING_INTERNAL_H

/*
 * §11 2026-11-04 項目55の段3: keyring.cの内部処理のうち、v5(ポスト量子)identityを扱う
 * pq_keyring.cからも使うものだけを公開する内部ヘッダ。keyring.cとpq_keyring.c以外から
 * includeしないこと(秘密鍵のラップの詳細をcoreの他のモジュールへ広げないため)。
 *
 * v5の秘密鍵(成分seed、160byte)を、v4以前の秘密鍵と全く同じ規則でラップするために
 * 切り出した: KEKはscrypt(行ごとのsalt)またはvaultのHKDF(DESIGN.md §7.4)、
 * ラップはAES-256-GCMでAAD=アドレス文字列(§7.1)。別の規則を作ると、片方だけ脆弱な
 * 実装が残りうるうえ、将来vaultへの移行等を両方に実装する羽目になるため。
 */

#include <sqlite3.h>
#include <stddef.h>

#include "identity_store.h"

/* nonce(12) + GCMタグ(16) */
#define BM_KEYRING_WRAP_OVERHEAD 28

/* out(pt_len + BM_KEYRING_WRAP_OVERHEAD byte) = nonce || 暗号文 || タグ。成功時0 */
int bm_keyring_internal_wrap(const unsigned char kek[32], const unsigned char *aad, size_t aad_len,
                             const unsigned char *plaintext, size_t pt_len, unsigned char *out);

/* inをunwrapしてout_plaintext(in_len - BM_KEYRING_WRAP_OVERHEAD byte)へ書く。
 * 鍵違い・改竄・AAD違いはGCMタグの検証で失敗する。成功時0 */
int bm_keyring_internal_unwrap(const unsigned char kek[32], const unsigned char *aad, size_t aad_len,
                               const unsigned char *in, size_t in_len, unsigned char *out_plaintext);

/*
 * 行のKDF情報(kdf_algo/kdf_salt/kdf_params)とアドレスとpassphraseからKEKを求める。
 * kdf_algoが"vault-hkdf"ならvaultのmaster KEKを導出してcanaryを検証し、HKDFで行のKEKを作る。
 * それ以外("scrypt")なら行のsaltとparamsでscryptする。成功時0。
 */
int bm_keyring_internal_resolve_kek(sqlite3 *db, const char *kdf_algo,
                                    const unsigned char kdf_salt[BM_IDENTITY_KDF_SALT_LEN], const char *kdf_params,
                                    const char *address, const char *passphrase, unsigned char out_kek[32]);

/* 新規identity用: 新しいsaltと既定のscryptパラメータ(JSON文字列)を作り、KEKを導出する。成功時0 */
int bm_keyring_internal_new_scrypt_kek(const char *passphrase, unsigned char out_salt[BM_IDENTITY_KDF_SALT_LEN],
                                       char out_params[BM_IDENTITY_KDF_PARAMS_MAX], unsigned char out_kek[32]);

#endif /* BM_CORE_KEYRING_INTERNAL_H */
