#ifndef BM_PQ_CRYPTO_H
#define BM_PQ_CRYPTO_H

/*
 * ML-DSA(FIPS 204)/ML-KEM(FIPS 203)の薄いラッパ。DESIGN-PQ.md §6。
 *
 * §3.5の規律(公開ヘッダに外部ライブラリの型を出さない)をPQ側でも守る。呼び出し側は
 * 生バイト列と長さだけを扱い、OpenSSLの型(EVP_PKEY等)には一切触れない。
 *
 * このファイルは「どのバックエンドを使うか」を隠蔽する層でもある。当初は
 * vendorしたpq-crystals参照実装を使い、「OpenSSL 3.5以降が使える環境になったら
 * pq_crypto.cの中身だけをEVP呼び出しへ差し替える」想定で設計していた。§PQ 2026-10-01
 * にその差し替えを実施し、プロトコル側(pq_hybrid.c等)は実際に無変更で済んだ。
 * OpenSSL 3.5未満ではこのモジュール自体がビルドされない(DESIGN-PQ.md §6)。
 */

#include <stddef.h>

enum bm_pq_sig_alg
{
    BM_PQ_SIG_ML_DSA_44 = 0,
    BM_PQ_SIG_ML_DSA_65,
    BM_PQ_SIG_ML_DSA_87,
    BM_PQ_SIG_ALG_COUNT
};

enum bm_pq_kem_alg
{
    BM_PQ_KEM_ML_KEM_512 = 0,
    BM_PQ_KEM_ML_KEM_768,
    BM_PQ_KEM_ML_KEM_1024,
    BM_PQ_KEM_ALG_COUNT
};

/* 全パラメータセット中の最大値。スタック上のバッファ確保用 */
#define BM_PQ_SIG_PK_MAX 2592
#define BM_PQ_SIG_SK_MAX 4896
#define BM_PQ_SIG_MAX 4627
#define BM_PQ_KEM_PK_MAX 1568
#define BM_PQ_KEM_SK_MAX 3168
#define BM_PQ_KEM_CT_MAX 1568

/* ML-DSA.KeyGen_internalのξ、ML-KEM.KeyGen_internalの(d,z)の長さ */
#define BM_PQ_SIG_SEED_LEN 32
#define BM_PQ_KEM_SEED_LEN 64
/* ML-KEMの共有秘密長(FIPS 203で32byte固定) */
#define BM_PQ_KEM_SS_LEN 32

struct bm_pq_sig_params
{
    const char *name;
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
};

struct bm_pq_kem_params
{
    const char *name;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
};

/* 未知のalgならNULL */
const struct bm_pq_sig_params *bm_pq_sig_get_params(enum bm_pq_sig_alg alg);
const struct bm_pq_kem_params *bm_pq_kem_get_params(enum bm_pq_kem_alg alg);

/*
 * 決定性鍵生成。seedは呼び出し側が用意する(パスフレーズ由来のアドレス生成では
 * このseedがアドレスの全てを決める)。成功時0。
 */
int bm_pq_sig_keypair_from_seed(enum bm_pq_sig_alg alg, const unsigned char *seed /* 32 */,
                                 unsigned char *out_pk, unsigned char *out_sk);
int bm_pq_kem_keypair_from_seed(enum bm_pq_kem_alg alg, const unsigned char *seed /* 64 */,
                                 unsigned char *out_pk, unsigned char *out_sk);

/*
 * 署名。ML-DSAのcontext string(FIPS 204 §5.2)は空で呼ぶ。ドメイン分離は
 * 上位(pq_hybrid.c)がメッセージ先頭へラベルを連結する形で行う(Ed25519側に
 * context stringが無く、両者で同じ入力に署名させたいため)。
 * hedged signing(FIPS 204の既定、OpenSSLでもdeterministic=0が既定)なので、
 * 同じ入力でも毎回異なる署名になる。out_sigはsig_len byte以上を用意すること
 * (*out_sig_lenは出力専用で、入力値は見ない)。成功時0。
 */
int bm_pq_sig_sign(enum bm_pq_sig_alg alg, const unsigned char *msg, size_t msg_len,
                    const unsigned char *sk, unsigned char *out_sig, size_t *out_sig_len);

/* 検証成功時1、失敗時0 */
int bm_pq_sig_verify(enum bm_pq_sig_alg alg, const unsigned char *sig, size_t sig_len,
                      const unsigned char *msg, size_t msg_len, const unsigned char *pk);

/* KEM。ss_lenは常にBM_PQ_KEM_SS_LEN。成功時0 */
int bm_pq_kem_encaps(enum bm_pq_kem_alg alg, const unsigned char *pk,
                      unsigned char *out_ct, unsigned char *out_ss);
int bm_pq_kem_decaps(enum bm_pq_kem_alg alg, const unsigned char *ct,
                      const unsigned char *sk, unsigned char *out_ss);

#endif /* BM_PQ_CRYPTO_H */
