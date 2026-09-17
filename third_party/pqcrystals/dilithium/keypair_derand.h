#ifndef BM_PQ_DILITHIUM_KEYPAIR_DERAND_H
#define BM_PQ_DILITHIUM_KEYPAIR_DERAND_H

/* keypair_derand.c の説明を参照(vendorしたdilithium参照実装への唯一の追加ファイル)。 */

#include <stdint.h>

#include "params.h"

#define crypto_sign_keypair_derand DILITHIUM_NAMESPACE(keypair_derand)
int crypto_sign_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t seed[SEEDBYTES]);

#endif /* BM_PQ_DILITHIUM_KEYPAIR_DERAND_H */
