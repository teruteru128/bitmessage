/*
 * ML-DSA.KeyGen_internal(ξ) — 外から32byteのseed ξ を与える決定性鍵生成。
 * DESIGN-PQ.md §4.2(パスフレーズ由来の決定性アドレス生成)で必要になる。
 *
 * 上流のdilithium参照実装には ML-KEM側の crypto_kem_keypair_derand に相当する
 * 「seedを外から渡す」APIが公開されていない(sign.c の crypto_sign_keypair が
 * 内部で randombytes() を呼ぶ形しかない)。そのため、vendorしたsign.cを書き換えて
 * upstreamとの差分を作るのではなく、crypto_sign_keypair の中身をそのまま複製し
 * randombytes(seedbuf, SEEDBYTES) の1行だけを memcpy に置き換えたこのファイルを
 * 追加する方式にした(vendorしたファイル群は無改変に保ち、diffで追跡できるようにする)。
 *
 * この処理はFIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) そのもので、
 * ξ をランダムに選べば crypto_sign_keypair と同一の鍵分布になる。
 */

#include <stdint.h>
#include <string.h>

#include "keypair_derand.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"

int crypto_sign_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t seed[SEEDBYTES])
{
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* ここだけが上流 crypto_sign_keypair との差分(randombytes → 引数のseed) */
    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}
