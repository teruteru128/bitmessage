#ifndef BM_CORE_CRYPTO_H
#define BM_CORE_CRYPTO_H

/*
 * ECIES暗号化・ECDSA署名。DESIGN.md §3.1, §3.2。
 * v1スコープでは未実装(TODO)。bm_crypto.c(libstudy側、空ファイル)と同じ立ち位置。
 * §3.5の規律に従い、OpenSSLの型はこのヘッダに一切出さない。
 */

#include <stddef.h>

/*
 * §3.1: IV(16) || 一時公開鍵TLV(70, curve_id=714固定) || ciphertext || HMAC-SHA256(32)
 * 成功時0。*out はmalloc済み(呼び出し側でfree)。
 */
int bm_crypto_ecies_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                             const unsigned char recipient_pub[65],
                             unsigned char **out, size_t *out_len);

int bm_crypto_ecies_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                             const unsigned char priv[32],
                             unsigned char **out, size_t *out_len);

/* §3.2: secp256k1 + SHA256、DER形式の署名を返す(malloc、呼び出し側でfree) */
int bm_crypto_sign(const unsigned char *data, size_t data_len,
                    const unsigned char priv[32],
                    unsigned char **out_sig, size_t *out_sig_len);

/* 検証成功時1、失敗時0 */
int bm_crypto_verify(const unsigned char *data, size_t data_len,
                      const unsigned char *sig, size_t sig_len,
                      const unsigned char pub[65]);

#endif /* BM_CORE_CRYPTO_H */
