#ifndef BM_COMMON_VARINT_H
#define BM_COMMON_VARINT_H

/*
 * Bitmessageプロトコルのvarint/varstr/varbytesコーデック。DESIGN.md §5.0。
 * 移植元: study/libstudy/src/bm_sonota.c (encodeVarint系), bm_protocol.c (decodeVarint)。
 *
 * decodeはネットワーク受信バッファを直接読むため、移植元と異なりバッファ長を
 * 受け取り範囲外アクセスを防ぐ(既存コードにはこのチェックがなかった)。
 */

#include <stddef.h>
#include <stdint.h>

/* エンコード後のバイト数(1, 3, 5, 9のいずれか) */
size_t bm_varint_size(uint64_t v);

/* out には最低 bm_varint_size(v) バイトの領域が必要。out を返す */
unsigned char *bm_varint_encode(unsigned char *out, uint64_t v);

/*
 * data[0..data_len) から varint を1個読む。
 * 戻り値: 消費したバイト数(成功時は1/3/5/9のいずれか)。data_len不足なら0を返し
 * *value は変更しない。
 */
size_t bm_varint_decode(const unsigned char *data, size_t data_len, uint64_t *value);

/* varstr(varint長 + UTF-8文字列本体, NUL終端は含まない)のエンコード後バイト数 */
size_t bm_varstr_size(const char *str);
unsigned char *bm_varstr_encode(unsigned char *out, const char *str);

/* varbytes(varint長 + 生バイト列)のエンコード後バイト数 */
size_t bm_varbytes_size(size_t len);
unsigned char *bm_varbytes_encode(unsigned char *out, const unsigned char *data, size_t len);

#endif /* BM_COMMON_VARINT_H */
