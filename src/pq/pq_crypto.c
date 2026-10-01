/* pq_crypto.h の説明を参照。DESIGN-PQ.md §6。 */

#include "pq_crypto.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

/*
 * §PQ 2026-10-01 バックエンドをvendorしたpq-crystals参照実装からOpenSSL 3.5の
 * EVP_PKEY-ML-DSA/ML-KEMへ差し替えた(DESIGN-PQ.md §6)。開発機がOpenSSL 3.5へ
 * 上がり、vendorした理由(「ディストロにPQを提供する選択肢が無い」)が消えたため。
 * 参照実装を実行時フォールバックとして残す案は採らなかった:暗号実装が2系統になり、
 * CIで回っていない側が「ビルドは通るが誰も検証していない」状態になるため。
 * OpenSSL 3.5未満の環境ではsrc/pq自体をビルドしない(ルートCMakeLists.txtの
 * BM_ENABLE_PQ)。
 *
 * 鍵・署名・暗号文のバイト表現はFIPS 203/204の規定そのもので、参照実装と完全に
 * 同一であることを差し替え時に実装間の突き合わせで確認した(同じseedから同じpk/sk、
 * 相互の署名検証、相互のencaps/decaps、implicit rejectionの出力まで一致)。
 * したがってsk/pkの長さ・形式(展開済みの秘密鍵)は呼び出し側から見て変わらない。
 *
 * パラメータ表のnameはOpenSSLのアルゴリズム名と一致させてあり、そのままfetchに使う。
 */
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

/*
 * seedを鍵生成パラメータとして渡す決定性鍵生成(ML-DSA.KeyGen_internal(ξ) /
 * ML-KEM.KeyGen_internal(d,z))。参照実装時代はML-DSA側に公開APIが無く
 * keypair_derandをvendorへ追加していたが、OpenSSLはどちらも"seed"パラメータで
 * 受け付ける(ML-KEMのseedはd||zの順、FIPS 203と同じ)。
 */
static int keypair_from_seed(const char *alg_name, const char *seed_param,
                              const unsigned char *seed, size_t seed_len,
                              unsigned char *out_pk, size_t pk_len,
                              unsigned char *out_sk, size_t sk_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    size_t len;
    int rc = -1;

    params[0] = OSSL_PARAM_construct_octet_string(seed_param, (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL &&
        EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
        EVP_PKEY_generate(ctx, &pkey) == 1)
    {
        len = pk_len;
        if (EVP_PKEY_get_raw_public_key(pkey, out_pk, &len) == 1 && len == pk_len)
        {
            len = sk_len;
            if (EVP_PKEY_get_raw_private_key(pkey, out_sk, &len) == 1 && len == sk_len)
            {
                rc = 0;
            }
        }
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int bm_pq_sig_keypair_from_seed(enum bm_pq_sig_alg alg, const unsigned char *seed,
                                 unsigned char *out_pk, unsigned char *out_sk)
{
    const struct bm_pq_sig_params *p = bm_pq_sig_get_params(alg);
    if (p == NULL)
    {
        return -1;
    }
    return keypair_from_seed(p->name, OSSL_PKEY_PARAM_ML_DSA_SEED, seed, BM_PQ_SIG_SEED_LEN,
                             out_pk, p->pk_len, out_sk, p->sk_len);
}

int bm_pq_kem_keypair_from_seed(enum bm_pq_kem_alg alg, const unsigned char *seed,
                                 unsigned char *out_pk, unsigned char *out_sk)
{
    const struct bm_pq_kem_params *p = bm_pq_kem_get_params(alg);
    if (p == NULL)
    {
        return -1;
    }
    return keypair_from_seed(p->name, OSSL_PKEY_PARAM_ML_KEM_SEED, seed, BM_PQ_KEM_SEED_LEN,
                             out_pk, p->pk_len, out_sk, p->sk_len);
}

/*
 * 署名・検証はpq_hybrid.cのEd25519と同じEVP_DigestSign/Verifyのワンショット形式。
 * OpenSSLのML-DSAの既定値は、context string空・pure ML-DSA(message-encoding=1、
 * 事前ハッシュしない)・hedged signing(deterministic=0)で、いずれもpq_crypto.hの
 * 契約(参照実装時代と同じ)と一致するので明示的な設定はしない。
 *
 * 呼び出しごとに秘密鍵をEVP_PKEYへ取り込むコストが乗る(展開済みskからの取り込みでは
 * OpenSSLがskから公開鍵を再計算して整合性を検査する)。EVP_PKEYをキャッシュするには
 * 公開APIを生バイト列から不透明ハンドルへ変える必要があるため、プロトタイプの段階では
 * 見送り、コストはDESIGN-PQ.md §8.1.1に実測値として記録した。
 */
int bm_pq_sig_sign(enum bm_pq_sig_alg alg, const unsigned char *msg, size_t msg_len,
                    const unsigned char *sk, unsigned char *out_sig, size_t *out_sig_len)
{
    const struct bm_pq_sig_params *p = bm_pq_sig_get_params(alg);
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    int rc = -1;

    if (p == NULL)
    {
        return -1;
    }
    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, p->name, NULL, sk, p->sk_len);
    ctx = EVP_MD_CTX_new();
    /* 参照実装は*out_sig_lenを出力専用として扱っていたため、呼び出し側は未初期化や0で
     * 渡してくる(pq_hybrid.c)。EVPでは入力時のバッファ長として解釈されるので、
     * 契約どおりsig_len分のバッファがある前提でここで設定する */
    *out_sig_len = p->sig_len;
    if (pkey != NULL && ctx != NULL &&
        EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) == 1 &&
        EVP_DigestSign(ctx, out_sig, out_sig_len, msg, msg_len) == 1 &&
        *out_sig_len == p->sig_len)
    {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int bm_pq_sig_verify(enum bm_pq_sig_alg alg, const unsigned char *sig, size_t sig_len,
                      const unsigned char *msg, size_t msg_len, const unsigned char *pk)
{
    const struct bm_pq_sig_params *p = bm_pq_sig_get_params(alg);
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    int ok = 0;

    if (p == NULL || sig_len != p->sig_len)
    {
        return 0;
    }
    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, p->name, NULL, pk, p->pk_len);
    ctx = EVP_MD_CTX_new();
    /* EVP_DigestVerifyは成功1・署名不一致0・エラー負値。このプロジェクトの検証系
     * (bm_crypto_verify)は成功1・失敗0なので、1以外は全て失敗として扱う */
    if (pkey != NULL && ctx != NULL &&
        EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) == 1 &&
        EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1)
    {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/*
 * 参照実装との挙動差: OpenSSLは鍵の取り込み時にFIPS 203 §7.2/§7.3の入力検査
 * (ekの係数がq未満であること、dkに埋め込まれたH(ek)の一致)を行うため、不正な
 * pk/skに対してはencaps/decapsが-1を返す。参照実装はこの検査をしておらず黙って
 * 計算していた。v5では相手のpubkeyオブジェクトから取り出したekをそのまま渡すので、
 * 検査が入るのはむしろ望ましい方向の変化である。
 */
int bm_pq_kem_encaps(enum bm_pq_kem_alg alg, const unsigned char *pk,
                      unsigned char *out_ct, unsigned char *out_ss)
{
    const struct bm_pq_kem_params *p = bm_pq_kem_get_params(alg);
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx = NULL;
    size_t ct_len;
    size_t ss_len = BM_PQ_KEM_SS_LEN;
    int rc = -1;

    if (p == NULL)
    {
        return -1;
    }
    ct_len = p->ct_len;
    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, p->name, NULL, pk, p->pk_len);
    if (pkey != NULL)
    {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    }
    if (ctx != NULL &&
        EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_encapsulate(ctx, out_ct, &ct_len, out_ss, &ss_len) == 1 &&
        ct_len == p->ct_len && ss_len == BM_PQ_KEM_SS_LEN)
    {
        rc = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int bm_pq_kem_decaps(enum bm_pq_kem_alg alg, const unsigned char *ct,
                      const unsigned char *sk, unsigned char *out_ss)
{
    /* ML-KEMのDecapsは「失敗」を返さない(implicit rejection: 不正なctに対しては
     * 攻撃者に区別できない擬似ランダムな共有秘密を返す、FIPS 203 §7.3)。
     * つまりここで0が返っても平文が復号できるとは限らず、実際の可否はAEADタグの
     * 検証で決まる。この性質はpq_hybrid.cのseal/openの設計前提になっている。
     * OpenSSLも同じで、ここで-1になるのは鍵の取り込み失敗等の内部エラーのみ。 */
    const struct bm_pq_kem_params *p = bm_pq_kem_get_params(alg);
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx = NULL;
    size_t ss_len = BM_PQ_KEM_SS_LEN;
    int rc = -1;

    if (p == NULL)
    {
        return -1;
    }
    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, p->name, NULL, sk, p->sk_len);
    if (pkey != NULL)
    {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    }
    if (ctx != NULL &&
        EVP_PKEY_decapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_decapsulate(ctx, out_ss, &ss_len, ct, p->ct_len) == 1 &&
        ss_len == BM_PQ_KEM_SS_LEN)
    {
        rc = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}
