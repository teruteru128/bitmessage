/* pq_crypto.h の説明を参照。DESIGN-PQ.md §6。 */

#include "pq_crypto.h"

#include <stdint.h>
#include <stddef.h>

/*
 * vendorしたpq-crystals参照実装の公開シンボルをここで直接宣言する。
 * third_party/pqcrystals/{kyber,dilithium}/api.hをインクルードしないのは、
 * 両者のヘッダ名が完全に衝突する(api.h・params.h・poly.h・polyvec.h・ntt.h・
 * reduce.h・symmetric.h・fips202.h)ため。CMake側でもvendorのインクルードパスは
 * PRIVATEに閉じてあり、このプロジェクトの他のファイルからは見えない。
 *
 * 宣言はthird_party/pqcrystals/{dilithium,kyber}/api.hと一対一で対応する。
 * サイズ定数も同ファイルの値をそのまま写したもの(FIPS 203/204の規定値)。
 */
int pqcrystals_dilithium2_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqcrystals_dilithium3_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqcrystals_dilithium5_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

int pqcrystals_kyber512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber768_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber1024_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static const struct bm_pq_sig_params g_sig_params[BM_PQ_SIG_ALG_COUNT] = {
    { "ML-DSA-44", 1312, 2560, 2420 },
    { "ML-DSA-65", 1952, 4032, 3309 },
    { "ML-DSA-87", 2592, 4896, 4627 },
};

static const struct bm_pq_kem_params g_kem_params[BM_PQ_KEM_ALG_COUNT] = {
    { "ML-KEM-512", 800, 1632, 768 },
    { "ML-KEM-768", 1184, 2400, 1088 },
    { "ML-KEM-1024", 1568, 3168, 1568 },
};

const struct bm_pq_sig_params *bm_pq_sig_get_params(enum bm_pq_sig_alg alg)
{
    if ((int)alg < 0 || alg >= BM_PQ_SIG_ALG_COUNT)
    {
        return NULL;
    }
    return &g_sig_params[alg];
}

const struct bm_pq_kem_params *bm_pq_kem_get_params(enum bm_pq_kem_alg alg)
{
    if ((int)alg < 0 || alg >= BM_PQ_KEM_ALG_COUNT)
    {
        return NULL;
    }
    return &g_kem_params[alg];
}

int bm_pq_sig_keypair_from_seed(enum bm_pq_sig_alg alg, const unsigned char *seed,
                                 unsigned char *out_pk, unsigned char *out_sk)
{
    switch (alg)
    {
    case BM_PQ_SIG_ML_DSA_44:
        return pqcrystals_dilithium2_ref_keypair_derand(out_pk, out_sk, seed);
    case BM_PQ_SIG_ML_DSA_65:
        return pqcrystals_dilithium3_ref_keypair_derand(out_pk, out_sk, seed);
    case BM_PQ_SIG_ML_DSA_87:
        return pqcrystals_dilithium5_ref_keypair_derand(out_pk, out_sk, seed);
    default:
        return -1;
    }
}

int bm_pq_kem_keypair_from_seed(enum bm_pq_kem_alg alg, const unsigned char *seed,
                                 unsigned char *out_pk, unsigned char *out_sk)
{
    switch (alg)
    {
    case BM_PQ_KEM_ML_KEM_512:
        return pqcrystals_kyber512_ref_keypair_derand(out_pk, out_sk, seed);
    case BM_PQ_KEM_ML_KEM_768:
        return pqcrystals_kyber768_ref_keypair_derand(out_pk, out_sk, seed);
    case BM_PQ_KEM_ML_KEM_1024:
        return pqcrystals_kyber1024_ref_keypair_derand(out_pk, out_sk, seed);
    default:
        return -1;
    }
}

int bm_pq_sig_sign(enum bm_pq_sig_alg alg, const unsigned char *msg, size_t msg_len,
                    const unsigned char *sk, unsigned char *out_sig, size_t *out_sig_len)
{
    switch (alg)
    {
    case BM_PQ_SIG_ML_DSA_44:
        return pqcrystals_dilithium2_ref_signature(out_sig, out_sig_len, msg, msg_len, NULL, 0, sk);
    case BM_PQ_SIG_ML_DSA_65:
        return pqcrystals_dilithium3_ref_signature(out_sig, out_sig_len, msg, msg_len, NULL, 0, sk);
    case BM_PQ_SIG_ML_DSA_87:
        return pqcrystals_dilithium5_ref_signature(out_sig, out_sig_len, msg, msg_len, NULL, 0, sk);
    default:
        return -1;
    }
}

int bm_pq_sig_verify(enum bm_pq_sig_alg alg, const unsigned char *sig, size_t sig_len,
                      const unsigned char *msg, size_t msg_len, const unsigned char *pk)
{
    int rc;
    switch (alg)
    {
    case BM_PQ_SIG_ML_DSA_44:
        rc = pqcrystals_dilithium2_ref_verify(sig, sig_len, msg, msg_len, NULL, 0, pk);
        break;
    case BM_PQ_SIG_ML_DSA_65:
        rc = pqcrystals_dilithium3_ref_verify(sig, sig_len, msg, msg_len, NULL, 0, pk);
        break;
    case BM_PQ_SIG_ML_DSA_87:
        rc = pqcrystals_dilithium5_ref_verify(sig, sig_len, msg, msg_len, NULL, 0, pk);
        break;
    default:
        return 0;
    }
    /* 参照実装は成功で0、失敗で-1を返す。このプロジェクトの検証系(bm_crypto_verify)は
     * 成功1・失敗0なので、そちらの慣習へ合わせる */
    return rc == 0 ? 1 : 0;
}

int bm_pq_kem_encaps(enum bm_pq_kem_alg alg, const unsigned char *pk,
                      unsigned char *out_ct, unsigned char *out_ss)
{
    switch (alg)
    {
    case BM_PQ_KEM_ML_KEM_512:
        return pqcrystals_kyber512_ref_enc(out_ct, out_ss, pk);
    case BM_PQ_KEM_ML_KEM_768:
        return pqcrystals_kyber768_ref_enc(out_ct, out_ss, pk);
    case BM_PQ_KEM_ML_KEM_1024:
        return pqcrystals_kyber1024_ref_enc(out_ct, out_ss, pk);
    default:
        return -1;
    }
}

int bm_pq_kem_decaps(enum bm_pq_kem_alg alg, const unsigned char *ct,
                      const unsigned char *sk, unsigned char *out_ss)
{
    /* ML-KEMのDecapsは「失敗」を返さない(implicit rejection: 不正なctに対しては
     * 攻撃者に区別できない擬似ランダムな共有秘密を返す、FIPS 203 §7.3)。
     * つまりここで0が返っても平文が復号できるとは限らず、実際の可否はAEADタグの
     * 検証で決まる。この性質はpq_hybrid.cのseal/openの設計前提になっている。 */
    switch (alg)
    {
    case BM_PQ_KEM_ML_KEM_512:
        return pqcrystals_kyber512_ref_dec(out_ss, ct, sk);
    case BM_PQ_KEM_ML_KEM_768:
        return pqcrystals_kyber768_ref_dec(out_ss, ct, sk);
    case BM_PQ_KEM_ML_KEM_1024:
        return pqcrystals_kyber1024_ref_dec(out_ss, ct, sk);
    default:
        return -1;
    }
}
