#ifndef BM_COMMON_BASE58_H
#define BM_COMMON_BASE58_H

/*
 * Base58エンコード/デコード。BMアドレス(§3.3)・WIF鍵エクスポート(§7)で使用。
 * encodeは移植元: study/libstudy/src/changebase.c の base58encode。
 */

#include <stddef.h>

/* 成功時はmalloc済みのNUL終端文字列を返す(呼び出し側でfree)。失敗時はNULL */
char *bm_base58_encode(const unsigned char *input, size_t length);

/*
 * TODO(§6.2 importAddress): WIF鍵インポートに必要。まだ未実装。
 * 成功時は *out に malloc 済みバイト列、*out_len にその長さを設定し 0 を返す。
 * 失敗時は非0を返す。
 */
int bm_base58_decode(const char *input, unsigned char **out, size_t *out_len);

#endif /* BM_COMMON_BASE58_H */
