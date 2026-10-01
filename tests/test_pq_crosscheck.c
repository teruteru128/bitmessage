/*
 * src/pq/pq_crypto.c(OpenSSL 3.5のEVP_PKEY-ML-DSA/ML-KEM)と、それ以前に使っていた
 * vendorのpq-crystals参照実装(third_party/pqcrystals)の突き合わせ。DESIGN-PQ.md §6。
 *
 * §PQ 2026-10-01 バックエンド差し替えの検証のためだけに書いた一時的なテスト。
 * 2つの独立な実装が同じバイト列を出すことを確認できれば、どちらかの仕様解釈の
 * 取り違え(FIPS 203/204の最終版とRound 3版の混同、ML-KEMのseedの(d,z)の並び順、
 * ML-DSAのcontext string/事前ハッシュの既定値等)が無いと言える。確認が済んだら
 * 参照実装と一緒に削除する(結果はDESIGN-PQ.md §6に記録する)。
 *
 * 検証観点:
 *   - 同じseedから生成した鍵(pk・展開済みsk)がバイト単位で一致すること
 *     (パスフレーズ由来のv5アドレスが実装を替えても同じになることの直接の確認)
 *   - 署名を相互に検証できること(OpenSSLで署名→参照実装で検証、その逆)。
 *     両者ともhedged signingで署名のバイト列は毎回変わるので、比較ではなく相互検証で見る
 *   - 改竄した署名をどちらも弾くこと
 *   - encaps/decapsを相互に行って共有秘密が一致すること
 *   - 改竄した暗号文に対するimplicit rejectionの出力(J(z||c))まで一致すること。
 *     これは乱数を含まない決定的な値なので、展開済みskの中のzの位置まで含めて一致を見られる
 *
 * seedは固定パターン(全0・全0xff・連番)と乱数の両方を使う。失敗時はseedを16進で
 * 出力するので、乱数側で落ちても再現できる。
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include "../src/pq/pq_crypto.h"

/* 参照実装の公開シンボル(third_party/pqcrystals/{dilithium,kyber}/api.h と
 * dilithium/keypair_derand.h)。両ファミリのヘッダ名が衝突するため直接宣言する */
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

struct ref_sig
{
    enum bm_pq_sig_alg alg;
    int (*keypair)(uint8_t *, uint8_t *, const uint8_t *);
    int (*sign)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
    int (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
};

struct ref_kem
{
    enum bm_pq_kem_alg alg;
    int (*keypair)(uint8_t *, uint8_t *, const uint8_t *);
    int (*enc)(uint8_t *, uint8_t *, const uint8_t *);
    int (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
};

static const struct ref_sig g_ref_sig[] = {
    { BM_PQ_SIG_ML_DSA_44, pqcrystals_dilithium2_ref_keypair_derand,
      pqcrystals_dilithium2_ref_signature, pqcrystals_dilithium2_ref_verify },
    { BM_PQ_SIG_ML_DSA_65, pqcrystals_dilithium3_ref_keypair_derand,
      pqcrystals_dilithium3_ref_signature, pqcrystals_dilithium3_ref_verify },
    { BM_PQ_SIG_ML_DSA_87, pqcrystals_dilithium5_ref_keypair_derand,
      pqcrystals_dilithium5_ref_signature, pqcrystals_dilithium5_ref_verify },
};

static const struct ref_kem g_ref_kem[] = {
    { BM_PQ_KEM_ML_KEM_512, pqcrystals_kyber512_ref_keypair_derand,
      pqcrystals_kyber512_ref_enc, pqcrystals_kyber512_ref_dec },
    { BM_PQ_KEM_ML_KEM_768, pqcrystals_kyber768_ref_keypair_derand,
      pqcrystals_kyber768_ref_enc, pqcrystals_kyber768_ref_dec },
    { BM_PQ_KEM_ML_KEM_1024, pqcrystals_kyber1024_ref_keypair_derand,
      pqcrystals_kyber1024_ref_enc, pqcrystals_kyber1024_ref_dec },
};

/* 固定パターン3種 + 乱数 */
#define FIXED_SEEDS 3
#define RANDOM_SEEDS 20

static void make_seed(int idx, unsigned char *seed, size_t len)
{
    size_t i;
    if (idx == 0)
    {
        memset(seed, 0x00, len);
    }
    else if (idx == 1)
    {
        memset(seed, 0xff, len);
    }
    else if (idx == 2)
    {
        for (i = 0; i < len; i++)
        {
            seed[i] = (unsigned char)i;
        }
    }
    else if (RAND_bytes(seed, (int)len) != 1)
    {
        memset(seed, 0x5a, len);
    }
}

static void print_seed(const char *what, const char *alg, const unsigned char *seed, size_t len)
{
    size_t i;
    fprintf(stderr, "FAIL: %s (%s) seed=", what, alg);
    for (i = 0; i < len; i++)
    {
        fprintf(stderr, "%02x", seed[i]);
    }
    fprintf(stderr, "\n");
}

static int check_sig(const struct ref_sig *r)
{
    const struct bm_pq_sig_params *p = bm_pq_sig_get_params(r->alg);
    static const unsigned char msg[] = "bitmessage v5 pq crosscheck";
    unsigned char seed[BM_PQ_SIG_SEED_LEN];
    unsigned char pk_o[BM_PQ_SIG_PK_MAX], sk_o[BM_PQ_SIG_SK_MAX];
    unsigned char pk_r[BM_PQ_SIG_PK_MAX], sk_r[BM_PQ_SIG_SK_MAX];
    unsigned char sig[BM_PQ_SIG_MAX];
    size_t sig_len;
    int i;

    for (i = 0; i < FIXED_SEEDS + RANDOM_SEEDS; i++)
    {
        make_seed(i, seed, sizeof(seed));

        if (bm_pq_sig_keypair_from_seed(r->alg, seed, pk_o, sk_o) != 0 ||
            r->keypair(pk_r, sk_r, seed) != 0)
        {
            print_seed("keygen failed", p->name, seed, sizeof(seed));
            return 1;
        }
        if (memcmp(pk_o, pk_r, p->pk_len) != 0)
        {
            print_seed("pk mismatch", p->name, seed, sizeof(seed));
            return 1;
        }
        if (memcmp(sk_o, sk_r, p->sk_len) != 0)
        {
            print_seed("sk mismatch", p->name, seed, sizeof(seed));
            return 1;
        }

        /* OpenSSLで署名 → 参照実装で検証(context stringは空) */
        if (bm_pq_sig_sign(r->alg, msg, sizeof(msg), sk_o, sig, &sig_len) != 0 ||
            sig_len != p->sig_len ||
            r->verify(sig, sig_len, msg, sizeof(msg), NULL, 0, pk_r) != 0)
        {
            print_seed("openssl sign -> ref verify", p->name, seed, sizeof(seed));
            return 1;
        }
        sig[sig_len / 2] ^= 0x01;
        if (r->verify(sig, sig_len, msg, sizeof(msg), NULL, 0, pk_r) == 0 ||
            bm_pq_sig_verify(r->alg, sig, sig_len, msg, sizeof(msg), pk_o) != 0)
        {
            print_seed("tampered openssl sig accepted", p->name, seed, sizeof(seed));
            return 1;
        }

        /* 参照実装で署名 → OpenSSLで検証 */
        if (r->sign(sig, &sig_len, msg, sizeof(msg), NULL, 0, sk_r) != 0 ||
            sig_len != p->sig_len ||
            bm_pq_sig_verify(r->alg, sig, sig_len, msg, sizeof(msg), pk_o) != 1)
        {
            print_seed("ref sign -> openssl verify", p->name, seed, sizeof(seed));
            return 1;
        }
        sig[0] ^= 0x80;
        if (bm_pq_sig_verify(r->alg, sig, sig_len, msg, sizeof(msg), pk_o) != 0 ||
            r->verify(sig, sig_len, msg, sizeof(msg), NULL, 0, pk_r) == 0)
        {
            print_seed("tampered ref sig accepted", p->name, seed, sizeof(seed));
            return 1;
        }
    }
    return 0;
}

static int check_kem(const struct ref_kem *r)
{
    const struct bm_pq_kem_params *p = bm_pq_kem_get_params(r->alg);
    unsigned char seed[BM_PQ_KEM_SEED_LEN];
    unsigned char pk_o[BM_PQ_KEM_PK_MAX], sk_o[BM_PQ_KEM_SK_MAX];
    unsigned char pk_r[BM_PQ_KEM_PK_MAX], sk_r[BM_PQ_KEM_SK_MAX];
    unsigned char ct[BM_PQ_KEM_CT_MAX];
    unsigned char ss_a[BM_PQ_KEM_SS_LEN], ss_b[BM_PQ_KEM_SS_LEN], ss_c[BM_PQ_KEM_SS_LEN];
    int i;

    for (i = 0; i < FIXED_SEEDS + RANDOM_SEEDS; i++)
    {
        make_seed(i, seed, sizeof(seed));

        if (bm_pq_kem_keypair_from_seed(r->alg, seed, pk_o, sk_o) != 0 ||
            r->keypair(pk_r, sk_r, seed) != 0)
        {
            print_seed("keygen failed", p->name, seed, sizeof(seed));
            return 1;
        }
        if (memcmp(pk_o, pk_r, p->pk_len) != 0)
        {
            print_seed("pk mismatch", p->name, seed, sizeof(seed));
            return 1;
        }
        if (memcmp(sk_o, sk_r, p->sk_len) != 0)
        {
            print_seed("sk mismatch", p->name, seed, sizeof(seed));
            return 1;
        }

        /* OpenSSLでencaps → 参照実装でdecaps */
        if (bm_pq_kem_encaps(r->alg, pk_o, ct, ss_a) != 0 ||
            r->dec(ss_b, ct, sk_r) != 0 ||
            memcmp(ss_a, ss_b, sizeof(ss_a)) != 0)
        {
            print_seed("openssl encaps -> ref decaps", p->name, seed, sizeof(seed));
            return 1;
        }

        /* 参照実装でencaps → OpenSSLでdecaps */
        if (r->enc(ct, ss_a, pk_r) != 0 ||
            bm_pq_kem_decaps(r->alg, ct, sk_o, ss_b) != 0 ||
            memcmp(ss_a, ss_b, sizeof(ss_a)) != 0)
        {
            print_seed("ref encaps -> openssl decaps", p->name, seed, sizeof(seed));
            return 1;
        }

        /* 改竄した暗号文: 両実装とも同じimplicit rejection値を返し、それは正規の
         * 共有秘密とは異なること */
        ct[p->ct_len - 1] ^= 0x01;
        if (bm_pq_kem_decaps(r->alg, ct, sk_o, ss_b) != 0 ||
            r->dec(ss_c, ct, sk_r) != 0 ||
            memcmp(ss_b, ss_c, sizeof(ss_b)) != 0 ||
            memcmp(ss_a, ss_b, sizeof(ss_a)) == 0)
        {
            print_seed("implicit rejection mismatch", p->name, seed, sizeof(seed));
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof(g_ref_sig) / sizeof(g_ref_sig[0]); i++)
    {
        failures += check_sig(&g_ref_sig[i]);
    }
    for (i = 0; i < sizeof(g_ref_kem) / sizeof(g_ref_kem[0]); i++)
    {
        failures += check_kem(&g_ref_kem[i]);
    }

    if (failures != 0)
    {
        fprintf(stderr, "%d crosscheck(s) failed\n", failures);
        return 1;
    }
    printf("OK: OpenSSL and pq-crystals reference agree on ML-DSA-44/65/87 and ML-KEM-512/768/1024 "
           "(%d seeds each)\n", FIXED_SEEDS + RANDOM_SEEDS);
    return 0;
}
