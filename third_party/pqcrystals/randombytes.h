#ifndef BM_PQ_RANDOMBYTES_H
#define BM_PQ_RANDOMBYTES_H

/*
 * pq-crystals参照実装(kyber/kem.c, dilithium/sign.c)が要求するrandombytes()の
 * 差し替え実装のヘッダ。DESIGN-PQ.md §6。
 *
 * 上流の各リポジトリにもref/randombytes.cが同梱されているが、
 * (1) kyber側とdilithium側で同名の非namespaceシンボル randombytes() を定義しており、
 *     両方をリンクすると重複定義になる
 * (2) 上流実装はLinuxではgetrandom(2)を直接叩く独自実装で、このプロジェクトが
 *     既に依存しているOpenSSLのCSPRNGと二重になる
 * という2点の理由から、vendorする際に両方を除外し、この1本に差し替えている。
 */

#include <stddef.h>
#include <stdint.h>

void randombytes(uint8_t *out, size_t outlen);

#endif /* BM_PQ_RANDOMBYTES_H */
