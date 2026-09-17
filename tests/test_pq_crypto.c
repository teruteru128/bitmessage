/*
 * src/pq/pq_crypto.c(ML-DSA/ML-KEM参照実装のラッパ)と src/pq/pq_hybrid.c
 * (ML-DSA-65+Ed25519のハイブリッド署名、X-Wing、AES-256-GCM封緘)の検証。
 * DESIGN-PQ.md §5・§6。
 *
 * 検証観点:
 *   - FIPS 203/204が定める鍵・暗号文・署名の長さが実際に出てくること
 *   - 決定性鍵生成が本当に決定性であること(同じseed→同じ鍵、違うseed→違う鍵)。
 *     パスフレーズ由来のアドレスがこの性質に完全に依存しているため
 *   - ハイブリッドが「両方通って初めて有効」になっていること(片側だけ改竄した
 *     署名を弾けること)。ここが壊れるとハイブリッドにした意味が消える
 *   - 封緘がAADに束縛されていること(ヘッダを差し替えた封緘を弾けること)
 */

#include <stdio.h>
#include <string.h>

#include "../src/pq/pq_crypto.h"
#include "../src/pq/pq_hybrid.h"

#define MLDSA65_SIG_LEN 3309
#define MLDSA65_PK_LEN 1952

static int test_sizes(void)
{
    static const struct
    {
        enum bm_pq_sig_alg alg;
        const char *name;
        size_t pk;
        size_t sk;
        size_t sig;
    } sig_expected[] = {
        { BM_PQ_SIG_ML_DSA_44, "ML-DSA-44", 1312, 2560, 2420 },
        { BM_PQ_SIG_ML_DSA_65, "ML-DSA-65", 1952, 4032, 3309 },
        { BM_PQ_SIG_ML_DSA_87, "ML-DSA-87", 2592, 4896, 4627 },
    };
    static const struct
    {
        enum bm_pq_kem_alg alg;
        const char *name;
        size_t pk;
        size_t sk;
        size_t ct;
    } kem_expected[] = {
        { BM_PQ_KEM_ML_KEM_512, "ML-KEM-512", 800, 1632, 768 },
        { BM_PQ_KEM_ML_KEM_768, "ML-KEM-768", 1184, 2400, 1088 },
        { BM_PQ_KEM_ML_KEM_1024, "ML-KEM-1024", 1568, 3168, 1568 },
    };
    size_t i;

    for (i = 0; i < sizeof(sig_expected) / sizeof(sig_expected[0]); i++)
    {
        const struct bm_pq_sig_params *p = bm_pq_sig_get_params(sig_expected[i].alg);
        if (p == NULL || strcmp(p->name, sig_expected[i].name) != 0 ||
            p->pk_len != sig_expected[i].pk || p->sk_len != sig_expected[i].sk ||
            p->sig_len != sig_expected[i].sig)
        {
            fprintf(stderr, "FAIL: sig params mismatch for %s\n", sig_expected[i].name);
            return 1;
        }
    }
    for (i = 0; i < sizeof(kem_expected) / sizeof(kem_expected[0]); i++)
    {
        const struct bm_pq_kem_params *p = bm_pq_kem_get_params(kem_expected[i].alg);
        if (p == NULL || strcmp(p->name, kem_expected[i].name) != 0 ||
            p->pk_len != kem_expected[i].pk || p->sk_len != kem_expected[i].sk ||
            p->ct_len != kem_expected[i].ct)
        {
            fprintf(stderr, "FAIL: kem params mismatch for %s\n", kem_expected[i].name);
            return 1;
        }
    }
    if (bm_pq_sig_get_params(BM_PQ_SIG_ALG_COUNT) != NULL ||
        bm_pq_kem_get_params(BM_PQ_KEM_ALG_COUNT) != NULL)
    {
        fprintf(stderr, "FAIL: out-of-range alg should return NULL\n");
        return 1;
    }
    return 0;
}

static int test_mldsa_roundtrip(void)
{
    unsigned char seed[32];
    unsigned char pk[BM_PQ_SIG_PK_MAX];
    unsigned char pk2[BM_PQ_SIG_PK_MAX];
    unsigned char sk[BM_PQ_SIG_SK_MAX];
    unsigned char sk2[BM_PQ_SIG_SK_MAX];
    unsigned char sig[BM_PQ_SIG_MAX];
    size_t sig_len = 0;
    const unsigned char msg[] = "post-quantum bitmessage";
    int i;

    for (i = 0; i < 32; i++)
    {
        seed[i] = (unsigned char)i;
    }
    if (bm_pq_sig_keypair_from_seed(BM_PQ_SIG_ML_DSA_65, seed, pk, sk) != 0 ||
        bm_pq_sig_keypair_from_seed(BM_PQ_SIG_ML_DSA_65, seed, pk2, sk2) != 0)
    {
        fprintf(stderr, "FAIL: ML-DSA keypair\n");
        return 1;
    }
    if (memcmp(pk, pk2, MLDSA65_PK_LEN) != 0 || memcmp(sk, sk2, 4032) != 0)
    {
        fprintf(stderr, "FAIL: ML-DSA keygen is not deterministic\n");
        return 1;
    }
    seed[0] ^= 0xff;
    if (bm_pq_sig_keypair_from_seed(BM_PQ_SIG_ML_DSA_65, seed, pk2, sk2) != 0 ||
        memcmp(pk, pk2, MLDSA65_PK_LEN) == 0)
    {
        fprintf(stderr, "FAIL: different seed produced the same ML-DSA key\n");
        return 1;
    }

    if (bm_pq_sig_sign(BM_PQ_SIG_ML_DSA_65, msg, sizeof(msg), sk, sig, &sig_len) != 0 ||
        sig_len != MLDSA65_SIG_LEN)
    {
        fprintf(stderr, "FAIL: ML-DSA sign (len=%zu)\n", sig_len);
        return 1;
    }
    if (bm_pq_sig_verify(BM_PQ_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg), pk) != 1)
    {
        fprintf(stderr, "FAIL: ML-DSA verify\n");
        return 1;
    }
    sig[100] ^= 0x01;
    if (bm_pq_sig_verify(BM_PQ_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg), pk) != 0)
    {
        fprintf(stderr, "FAIL: tampered ML-DSA signature accepted\n");
        return 1;
    }
    return 0;
}

static int test_mlkem_roundtrip(void)
{
    unsigned char seed[64];
    unsigned char pk[BM_PQ_KEM_PK_MAX];
    unsigned char sk[BM_PQ_KEM_SK_MAX];
    unsigned char ct[BM_PQ_KEM_CT_MAX];
    unsigned char ss_a[BM_PQ_KEM_SS_LEN];
    unsigned char ss_b[BM_PQ_KEM_SS_LEN];
    int i;

    for (i = 0; i < 64; i++)
    {
        seed[i] = (unsigned char)(0x40 + i);
    }
    if (bm_pq_kem_keypair_from_seed(BM_PQ_KEM_ML_KEM_768, seed, pk, sk) != 0 ||
        bm_pq_kem_encaps(BM_PQ_KEM_ML_KEM_768, pk, ct, ss_a) != 0 ||
        bm_pq_kem_decaps(BM_PQ_KEM_ML_KEM_768, ct, sk, ss_b) != 0)
    {
        fprintf(stderr, "FAIL: ML-KEM roundtrip call\n");
        return 1;
    }
    if (memcmp(ss_a, ss_b, BM_PQ_KEM_SS_LEN) != 0)
    {
        fprintf(stderr, "FAIL: ML-KEM shared secrets differ\n");
        return 1;
    }
    /* implicit rejection: 改竄されたctでもDecapsは成功を返すが、共有秘密は一致しない */
    ct[10] ^= 0x01;
    if (bm_pq_kem_decaps(BM_PQ_KEM_ML_KEM_768, ct, sk, ss_b) != 0)
    {
        fprintf(stderr, "FAIL: ML-KEM decaps should not fail on bad ct\n");
        return 1;
    }
    if (memcmp(ss_a, ss_b, BM_PQ_KEM_SS_LEN) == 0)
    {
        fprintf(stderr, "FAIL: tampered ct produced the same shared secret\n");
        return 1;
    }
    return 0;
}

static int test_hybrid_signature(void)
{
    unsigned char seed[BM_PQV5_SEED_LEN];
    unsigned char pk[BM_PQV5_SIG_PK_LEN];
    unsigned char pk2[BM_PQV5_SIG_PK_LEN];
    unsigned char sk[BM_PQV5_SIG_SK_LEN];
    unsigned char sk2[BM_PQV5_SIG_SK_LEN];
    unsigned char sig[BM_PQV5_SIG_LEN];
    const unsigned char msg[] = "hybrid signature test";
    int i;

    memset(seed, 0x5a, sizeof(seed));
    if (bm_pqv5_sig_keypair_from_seed(seed, pk, sk) != 0 ||
        bm_pqv5_sig_keypair_from_seed(seed, pk2, sk2) != 0 ||
        memcmp(pk, pk2, sizeof(pk)) != 0 || memcmp(sk, sk2, sizeof(sk)) != 0)
    {
        fprintf(stderr, "FAIL: hybrid keygen determinism\n");
        return 1;
    }
    if (bm_pqv5_sign("label-a", msg, sizeof(msg), sk, sig) != 0)
    {
        fprintf(stderr, "FAIL: hybrid sign\n");
        return 1;
    }
    if (bm_pqv5_verify("label-a", msg, sizeof(msg), sig, pk) != 1)
    {
        fprintf(stderr, "FAIL: hybrid verify\n");
        return 1;
    }
    /* ドメイン分離: ラベルが違えば同じ署名は通らない */
    if (bm_pqv5_verify("label-b", msg, sizeof(msg), sig, pk) != 0)
    {
        fprintf(stderr, "FAIL: signature verified under a different label\n");
        return 1;
    }

    /* ML-DSA側だけを壊す / Ed25519側だけを壊す。どちらも拒否されること */
    for (i = 0; i < 2; i++)
    {
        size_t pos = (i == 0) ? 64 : (size_t)MLDSA65_SIG_LEN + 10;
        sig[pos] ^= 0x01;
        if (bm_pqv5_verify("label-a", msg, sizeof(msg), sig, pk) != 0)
        {
            fprintf(stderr, "FAIL: hybrid verify accepted a half-tampered signature (part %d)\n", i);
            return 1;
        }
        sig[pos] ^= 0x01;
    }
    if (bm_pqv5_verify("label-a", msg, sizeof(msg), sig, pk) != 1)
    {
        fprintf(stderr, "FAIL: restore check\n");
        return 1;
    }
    return 0;
}

static int test_hybrid_seal(void)
{
    unsigned char seed[BM_PQV5_SEED_LEN];
    unsigned char pk[BM_PQV5_KEM_PK_LEN];
    unsigned char sk[BM_PQV5_KEM_SK_LEN];
    unsigned char other_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char other_sk[BM_PQV5_KEM_SK_LEN];
    const unsigned char pt[] = "sealed payload";
    const unsigned char aad[] = "object header";
    unsigned char sealed[BM_PQV5_SEAL_OVERHEAD + sizeof(pt)];
    unsigned char opened[sizeof(pt)];
    size_t sealed_len = 0;
    size_t opened_len = 0;

    memset(seed, 0x11, sizeof(seed));
    if (bm_pqv5_kem_keypair_from_seed(seed, pk, sk) != 0)
    {
        fprintf(stderr, "FAIL: kem keypair\n");
        return 1;
    }
    memset(seed, 0x22, sizeof(seed));
    if (bm_pqv5_kem_keypair_from_seed(seed, other_pk, other_sk) != 0)
    {
        fprintf(stderr, "FAIL: other kem keypair\n");
        return 1;
    }

    if (bm_pqv5_seal(pk, aad, sizeof(aad), pt, sizeof(pt), sealed, &sealed_len) != 0 ||
        sealed_len != BM_PQV5_SEAL_OVERHEAD + sizeof(pt))
    {
        fprintf(stderr, "FAIL: seal (len=%zu)\n", sealed_len);
        return 1;
    }
    if (bm_pqv5_open(sk, aad, sizeof(aad), sealed, sealed_len, opened, &opened_len) != 0 ||
        opened_len != sizeof(pt) || memcmp(opened, pt, sizeof(pt)) != 0)
    {
        fprintf(stderr, "FAIL: open\n");
        return 1;
    }
    /* 他人の鍵では開かない(msgのトライアル復号が空振りする経路) */
    if (bm_pqv5_open(other_sk, aad, sizeof(aad), sealed, sealed_len, opened, &opened_len) == 0)
    {
        fprintf(stderr, "FAIL: opened with the wrong key\n");
        return 1;
    }
    /* AADが違えば開かない(ヘッダ差し替えの検出) */
    if (bm_pqv5_open(sk, (const unsigned char *)"different", 9, sealed, sealed_len, opened,
                     &opened_len) == 0)
    {
        fprintf(stderr, "FAIL: opened with a different AAD\n");
        return 1;
    }
    /* 暗号文本体の改竄 */
    sealed[BM_PQV5_KEM_CT_LEN] ^= 0x01;
    if (bm_pqv5_open(sk, aad, sizeof(aad), sealed, sealed_len, opened, &opened_len) == 0)
    {
        fprintf(stderr, "FAIL: opened tampered ciphertext\n");
        return 1;
    }
    sealed[BM_PQV5_KEM_CT_LEN] ^= 0x01;
    /* KEM暗号文の改竄(X25519側) */
    sealed[BM_PQV5_KEM_CT_LEN - 1] ^= 0x01;
    if (bm_pqv5_open(sk, aad, sizeof(aad), sealed, sealed_len, opened, &opened_len) == 0)
    {
        fprintf(stderr, "FAIL: opened tampered KEM ciphertext\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_sizes() != 0)
    {
        return 1;
    }
    if (test_mldsa_roundtrip() != 0)
    {
        return 1;
    }
    if (test_mlkem_roundtrip() != 0)
    {
        return 1;
    }
    if (test_hybrid_signature() != 0)
    {
        return 1;
    }
    if (test_hybrid_seal() != 0)
    {
        return 1;
    }
    printf("test_pq_crypto: OK\n");
    return 0;
}
