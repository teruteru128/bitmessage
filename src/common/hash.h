#ifndef BM_COMMON_HASH_H
#define BM_COMMON_HASH_H

/*
 * ハッシュ関数のラッパー群。DESIGN.md §3.4 のまとめに対応。
 */

#include <stddef.h>

void bm_sha256(const unsigned char *data, size_t len, unsigned char out[32]);
void bm_sha512(const unsigned char *data, size_t len, unsigned char out[64]);
void bm_double_sha256(const unsigned char *data, size_t len, unsigned char out[32]);
void bm_double_sha512(const unsigned char *data, size_t len, unsigned char out[64]);
void bm_ripemd160(const unsigned char *data, size_t len, unsigned char out[20]);

/* inventory hash = double_sha512(payload)[0:32] (§5.0) */
void bm_inventory_hash(const unsigned char *payload, size_t len, unsigned char out[32]);

/* 成功時0、失敗時非0 */
int bm_hmac_sha256(const unsigned char *key, size_t key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char out[32]);

#endif /* BM_COMMON_HASH_H */
