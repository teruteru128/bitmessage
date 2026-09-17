/*
 * ポスト量子(v5)プロファイルと現行(v4)の比較ベンチマーク。DESIGN-PQ.md §8。
 *
 * 測るもの:
 *   1. 暗号プリミティブ単体(ML-DSA全パラメータ・ML-KEM全パラメータ・Ed25519・X25519・
 *      現行のsecp256k1 ECDSA/ECIES)
 *   2. アドレス生成(v4決定性 vs v5決定性)とアドレス文字列長
 *   3. オブジェクトサイズ(pubkey/msg/broadcast、本文長を変えながらv4とv5を並べる)
 *   4. PoWコスト(サイズ増加が期待試行回数と所要時間へどう効くか)
 *
 * 実行: build-Debug/src/pq/bm-pq-bench [--pow]
 *   --pow を付けると(3)で作った実際のv4/v5 msgオブジェクトに対して
 *   ネットワーク既定難易度(1000/1000)の本物のPoWを回して実測する(数分かかりうる)。
 */

#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "address.h"
#include "address_v5.h"
#include "crypto.h"
#include "hash.h"
#include "message_builder.h"
#include "pow_engine.h"
#include "pq_crypto.h"
#include "pq_hybrid.h"
#include "pq_object.h"

#define NETWORK_NONCE_TRIALS 1000
#define NETWORK_EXTRA_BYTES 1000
#define TTL_MSG (4 * 24 * 60 * 60)
#define TTL_PUBKEY (28 * 24 * 60 * 60)

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* 最低min_secか、max_itersに達するまで回して1回あたりのマイクロ秒を返す */
static double bench(void (*fn)(void *), void *arg, int max_iters, double min_sec)
{
    double start = now_sec();
    int i = 0;
    double elapsed;
    do
    {
        fn(arg);
        i++;
        elapsed = now_sec() - start;
    } while (i < max_iters && elapsed < min_sec);
    return elapsed / i * 1e6;
}

static void print_row(const char *label, const char *op, double usec)
{
    printf("  %-14s %-10s %10.1f us  %12.0f ops/s\n", label, op, usec, 1e6 / usec);
}

/* --- 1. プリミティブ --- */

struct sig_ctx
{
    enum bm_pq_sig_alg alg;
    unsigned char seed[32];
    unsigned char pk[BM_PQ_SIG_PK_MAX];
    unsigned char sk[BM_PQ_SIG_SK_MAX];
    unsigned char sig[BM_PQ_SIG_MAX];
    size_t sig_len;
    unsigned char msg[256];
};

static void sig_keygen_fn(void *arg)
{
    struct sig_ctx *c = arg;
    bm_pq_sig_keypair_from_seed(c->alg, c->seed, c->pk, c->sk);
    c->seed[0]++;
}

static void sig_sign_fn(void *arg)
{
    struct sig_ctx *c = arg;
    bm_pq_sig_sign(c->alg, c->msg, sizeof(c->msg), c->sk, c->sig, &c->sig_len);
}

static void sig_verify_fn(void *arg)
{
    struct sig_ctx *c = arg;
    if (bm_pq_sig_verify(c->alg, c->sig, c->sig_len, c->msg, sizeof(c->msg), c->pk) != 1)
    {
        fprintf(stderr, "ML-DSA verify failed\n");
        exit(1);
    }
}

struct kem_ctx
{
    enum bm_pq_kem_alg alg;
    unsigned char seed[64];
    unsigned char pk[BM_PQ_KEM_PK_MAX];
    unsigned char sk[BM_PQ_KEM_SK_MAX];
    unsigned char ct[BM_PQ_KEM_CT_MAX];
    unsigned char ss[BM_PQ_KEM_SS_LEN];
};

static void kem_keygen_fn(void *arg)
{
    struct kem_ctx *c = arg;
    bm_pq_kem_keypair_from_seed(c->alg, c->seed, c->pk, c->sk);
    c->seed[0]++;
}

static void kem_encaps_fn(void *arg)
{
    struct kem_ctx *c = arg;
    bm_pq_kem_encaps(c->alg, c->pk, c->ct, c->ss);
}

static void kem_decaps_fn(void *arg)
{
    struct kem_ctx *c = arg;
    bm_pq_kem_decaps(c->alg, c->ct, c->sk, c->ss);
}

struct v4_ctx
{
    unsigned char priv[32];
    unsigned char pub[65];
    unsigned char *sig;
    size_t sig_len;
    unsigned char msg[256];
    unsigned char *ct;
    size_t ct_len;
};

static void v4_sign_fn(void *arg)
{
    struct v4_ctx *c = arg;
    free(c->sig);
    c->sig = NULL;
    bm_crypto_sign(c->msg, sizeof(c->msg), c->priv, &c->sig, &c->sig_len);
}

static void v4_verify_fn(void *arg)
{
    struct v4_ctx *c = arg;
    if (bm_crypto_verify(c->msg, sizeof(c->msg), c->sig, c->sig_len, c->pub) != 1)
    {
        fprintf(stderr, "ECDSA verify failed\n");
        exit(1);
    }
}

static void v4_encrypt_fn(void *arg)
{
    struct v4_ctx *c = arg;
    free(c->ct);
    c->ct = NULL;
    bm_crypto_ecies_encrypt(c->msg, sizeof(c->msg), c->pub, &c->ct, &c->ct_len);
}

static void v4_decrypt_fn(void *arg)
{
    struct v4_ctx *c = arg;
    unsigned char *pt = NULL;
    size_t pt_len = 0;
    if (bm_crypto_ecies_decrypt(c->ct, c->ct_len, c->priv, &pt, &pt_len) != 0)
    {
        fprintf(stderr, "ECIES decrypt failed\n");
        exit(1);
    }
    free(pt);
}

struct hybrid_ctx
{
    unsigned char seed[BM_PQV5_SEED_LEN];
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char sig_sk[BM_PQV5_SIG_SK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char sig[BM_PQV5_SIG_LEN];
    unsigned char msg[256];
    unsigned char sealed[BM_PQV5_SEAL_OVERHEAD + 256];
    size_t sealed_len;
};

static void hybrid_sign_fn(void *arg)
{
    struct hybrid_ctx *c = arg;
    bm_pqv5_sign(c->msg, sizeof(c->msg), c->sig_sk, c->sig);
}

static void hybrid_verify_fn(void *arg)
{
    struct hybrid_ctx *c = arg;
    if (bm_pqv5_verify(c->msg, sizeof(c->msg), c->sig, c->sig_pk) != 1)
    {
        fprintf(stderr, "hybrid verify failed\n");
        exit(1);
    }
}

static void hybrid_seal_fn(void *arg)
{
    struct hybrid_ctx *c = arg;
    bm_pqv5_seal(c->kem_pk, NULL, 0, c->msg, sizeof(c->msg), c->sealed, &c->sealed_len);
}

static void hybrid_open_fn(void *arg)
{
    struct hybrid_ctx *c = arg;
    unsigned char pt[256];
    size_t pt_len = 0;
    if (bm_pqv5_open(c->kem_sk, NULL, 0, c->sealed, c->sealed_len, pt, &pt_len) != 0)
    {
        fprintf(stderr, "hybrid open failed\n");
        exit(1);
    }
}

static void bench_primitives(void)
{
    static const enum bm_pq_sig_alg sig_algs[] = { BM_PQ_SIG_ML_DSA_44, BM_PQ_SIG_ML_DSA_65,
                                                   BM_PQ_SIG_ML_DSA_87 };
    static const enum bm_pq_kem_alg kem_algs[] = { BM_PQ_KEM_ML_KEM_512, BM_PQ_KEM_ML_KEM_768,
                                                   BM_PQ_KEM_ML_KEM_1024 };
    struct sig_ctx sc;
    struct kem_ctx kc;
    struct v4_ctx vc;
    struct hybrid_ctx hc;
    size_t i;

    printf("== 1. 暗号プリミティブ ==\n");
    printf("  %-14s %-10s %10s  %12s\n", "alg", "op", "time", "throughput");

    for (i = 0; i < sizeof(sig_algs) / sizeof(sig_algs[0]); i++)
    {
        const struct bm_pq_sig_params *p = bm_pq_sig_get_params(sig_algs[i]);
        memset(&sc, 0, sizeof(sc));
        sc.alg = sig_algs[i];
        RAND_bytes(sc.seed, sizeof(sc.seed));
        RAND_bytes(sc.msg, sizeof(sc.msg));
        bm_pq_sig_keypair_from_seed(sc.alg, sc.seed, sc.pk, sc.sk);
        bm_pq_sig_sign(sc.alg, sc.msg, sizeof(sc.msg), sc.sk, sc.sig, &sc.sig_len);
        print_row(p->name, "keygen", bench(sig_keygen_fn, &sc, 2000, 0.3));
        print_row(p->name, "sign", bench(sig_sign_fn, &sc, 2000, 0.3));
        print_row(p->name, "verify", bench(sig_verify_fn, &sc, 5000, 0.3));
    }

    for (i = 0; i < sizeof(kem_algs) / sizeof(kem_algs[0]); i++)
    {
        const struct bm_pq_kem_params *p = bm_pq_kem_get_params(kem_algs[i]);
        memset(&kc, 0, sizeof(kc));
        kc.alg = kem_algs[i];
        RAND_bytes(kc.seed, sizeof(kc.seed));
        bm_pq_kem_keypair_from_seed(kc.alg, kc.seed, kc.pk, kc.sk);
        bm_pq_kem_encaps(kc.alg, kc.pk, kc.ct, kc.ss);
        print_row(p->name, "keygen", bench(kem_keygen_fn, &kc, 5000, 0.3));
        print_row(p->name, "encaps", bench(kem_encaps_fn, &kc, 5000, 0.3));
        print_row(p->name, "decaps", bench(kem_decaps_fn, &kc, 5000, 0.3));
    }

    memset(&hc, 0, sizeof(hc));
    RAND_bytes(hc.seed, sizeof(hc.seed));
    RAND_bytes(hc.msg, sizeof(hc.msg));
    bm_pqv5_sig_keypair_from_seed(hc.seed, hc.sig_pk, hc.sig_sk);
    bm_pqv5_kem_keypair_from_seed(hc.seed, hc.kem_pk, hc.kem_sk);
    bm_pqv5_sign(hc.msg, sizeof(hc.msg), hc.sig_sk, hc.sig);
    bm_pqv5_seal(hc.kem_pk, NULL, 0, hc.msg, sizeof(hc.msg), hc.sealed, &hc.sealed_len);
    print_row("v5 hybrid", "sign", bench(hybrid_sign_fn, &hc, 2000, 0.3));
    print_row("v5 hybrid", "verify", bench(hybrid_verify_fn, &hc, 5000, 0.3));
    print_row("v5 hybrid", "seal", bench(hybrid_seal_fn, &hc, 5000, 0.3));
    print_row("v5 hybrid", "open", bench(hybrid_open_fn, &hc, 5000, 0.3));

    memset(&vc, 0, sizeof(vc));
    RAND_bytes(vc.priv, sizeof(vc.priv));
    vc.priv[0] &= 0x7f; /* 群位数未満にするための雑な処置(ベンチ用途) */
    RAND_bytes(vc.msg, sizeof(vc.msg));
    if (bm_address_get_public_key(vc.priv, vc.pub) != 0)
    {
        fprintf(stderr, "secp256k1 pubkey derive failed\n");
        exit(1);
    }
    bm_crypto_sign(vc.msg, sizeof(vc.msg), vc.priv, &vc.sig, &vc.sig_len);
    bm_crypto_ecies_encrypt(vc.msg, sizeof(vc.msg), vc.pub, &vc.ct, &vc.ct_len);
    print_row("v4 secp256k1", "sign", bench(v4_sign_fn, &vc, 5000, 0.3));
    print_row("v4 secp256k1", "verify", bench(v4_verify_fn, &vc, 5000, 0.3));
    print_row("v4 ECIES", "encrypt", bench(v4_encrypt_fn, &vc, 5000, 0.3));
    print_row("v4 ECIES", "decrypt", bench(v4_decrypt_fn, &vc, 5000, 0.3));
    free(vc.sig);
    free(vc.ct);
    printf("\n");
}

/* --- 2. アドレス生成 --- */

/*
 * 実際に使う2経路(決定性・ランダム)のアドレス生成コスト。
 * 決定性はKEM鍵ペアをX-Wing仕様通りseedから毎回作り直し、ランダムはX25519だけを
 * 引き直す(address_v5.hの説明)。候補数は幾何分布なので単発ではぶれるため、
 * 1候補あたりのコストと、そこから計算した期待所要時間を併記する。
 */
static void bench_v5_deterministic(const char *label, int null_bytes, struct bm_pqv5_identity *out)
{
    double t0 = now_sec();
    double t1;
    char *addr;
    uint64_t candidates;

    if (bm_pqv5_identity_generate_deterministic("bm-pq-bench passphrase", 1, 0, null_bytes, out) != 0)
    {
        fprintf(stderr, "v5 deterministic address generation failed\n");
        exit(1);
    }
    t1 = now_sec();
    candidates = (out->kem_nonce - 1) / 2 + 1;
    addr = bm_pqv5_address_encode(out->version, out->stream, out->id);
    printf("  %-32s %6" PRIu64 "候補 %9.1f ms  %6.3f ms/候補  期待%8.1f ms  %zu文字\n", label,
           candidates, (t1 - t0) * 1e3, (t1 - t0) * 1e3 / (double)candidates,
           (t1 - t0) * 1e3 / (double)candidates * (null_bytes == 0 ? 1.0 : (double)(1u << (8 * null_bytes))),
           strlen(addr));
    free(addr);
}

static void bench_v5_random(const char *label, int null_bytes)
{
    struct bm_pqv5_identity id;
    double t0 = now_sec();
    double elapsed;
    int i;
    const int rounds = 50;
    char *addr;

    /* ランダム生成は候補数を記録しないので、複数回まわして1本あたりの平均所要時間を出す
     * (1本あたりが幾何分布なので、少ない回数だと平均が大きくぶれる) */
    for (i = 0; i < rounds; i++)
    {
        if (bm_pqv5_identity_generate_random(1, null_bytes, &id) != 0)
        {
            fprintf(stderr, "v5 random address generation failed\n");
            exit(1);
        }
    }
    elapsed = (now_sec() - t0) / rounds;
    addr = bm_pqv5_address_encode(id.version, id.stream, id.id);
    printf("  %-32s %6s %9s  %6s          実測%8.1f ms  %zu文字\n", label, "-", "-", "-",
           elapsed * 1e3, strlen(addr));
    free(addr);
}

/*
 * 参考測定: 探索で片方の鍵ペアだけ / id計算だけを回した場合の1候補あたりコスト。
 * 採用した方式(決定性=両鍵、ランダム=X25519のみ)の位置づけを示すための比較対象。
 * 決定性側で「安いKEM鍵だけ回す」最適化を撤回した経緯はDESIGN-PQ.md §4.2.1。
 */
static void bench_whole_keypair_redraw(const struct bm_pqv5_identity *base)
{
    unsigned char seed[BM_PQV5_SEED_LEN];
    unsigned char pk[BM_PQV5_KEM_PK_LEN];
    unsigned char sk[BM_PQV5_KEM_SK_LEN];
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char sig_sk[BM_PQV5_SIG_SK_LEN];
    unsigned char id[BM_PQV5_ID_LEN];
    double t0;
    double per;
    int i;
    const int iters = 2000;

    memset(seed, 0x33, sizeof(seed));

    t0 = now_sec();
    for (i = 0; i < iters; i++)
    {
        bm_pq_shake128(seed, sizeof(seed), seed, sizeof(seed));
        bm_pqv5_sig_keypair_from_seed(seed, sig_pk, sig_sk);
        bm_pqv5_calc_id(sig_pk, base->kem_pk, id);
    }
    per = (now_sec() - t0) * 1e3 / iters;
    printf("  %-32s %6s %9s  %6.3f ms/候補  期待%8.1f ms\n", "(参考) 署名鍵まるごと", "-", "-",
           per, per * 256.0);

    t0 = now_sec();
    for (i = 0; i < iters; i++)
    {
        bm_pq_shake128(seed, sizeof(seed), seed, sizeof(seed));
        bm_pqv5_kem_keypair_from_seed(seed, pk, sk);
        bm_pqv5_calc_id(base->sig_pk, pk, id);
    }
    per = (now_sec() - t0) * 1e3 / iters;
    printf("  %-32s %6s %9s  %6.3f ms/候補  期待%8.1f ms\n", "(参考) KEM鍵まるごと(撤回案)", "-", "-",
           per, per * 256.0);

    t0 = now_sec();
    for (i = 0; i < iters; i++)
    {
        bm_pqv5_calc_id(base->sig_pk, base->kem_pk, id);
    }
    per = (now_sec() - t0) * 1e3 / iters;
    printf("  %-32s %6s %9s  %6.3f ms/候補  期待%8.1f ms\n", "(参考) id計算のみ=探索の下限", "-", "-",
           per, per * 256.0);
}

static void bench_addresses(struct bm_pqv5_identity *out_v5, struct bm_generated_address *out_v4)
{
    double t0;
    double t1;
    char *addr4;
    struct bm_pqv5_identity tmp;

    printf("== 2. アドレス生成(null_bytes=id先頭に要求する0x00バイト数) ==\n");

    t0 = now_sec();
    if (bm_address_generate_deterministic("bm-pq-bench passphrase", 1, out_v4) != 0)
    {
        fprintf(stderr, "v4 address generation failed\n");
        exit(1);
    }
    t1 = now_sec();
    addr4 = bm_address_encode(4, 1, out_v4->ripe, BM_RIPE_LEN);
    printf("  %-32s %6" PRIu64 "候補 %9.1f ms  %6.3f ms/候補  期待%8.1f ms  %zu文字\n",
           "v4 決定性 null=1 (両鍵を引き直す)", out_v4->signing_nonce / 2 + 1, (t1 - t0) * 1e3,
           (t1 - t0) * 1e3 / (double)(out_v4->signing_nonce / 2 + 1),
           (t1 - t0) * 1e3 / (double)(out_v4->signing_nonce / 2 + 1) * 256.0, strlen(addr4));
    free(addr4);

    bench_v5_deterministic("v5 決定性 null=0 (探索なし)", 0, &tmp);
    bench_v5_deterministic("v5 決定性 null=1 (両鍵、v4と同じ)", BM_PQV5_DEFAULT_NULL_BYTES, out_v5);
    bench_v5_deterministic("v5 決定性 null=2 (両鍵)", 2, &tmp);
    bench_v5_random("v5 ランダム null=1 (X25519のみ)", BM_PQV5_DEFAULT_NULL_BYTES);
    bench_whole_keypair_redraw(out_v5);

    printf("\n");
}

/* --- 3. オブジェクトサイズ --- */

static void fill_v4_identity(struct bm_identity_info *info, const struct bm_generated_address *v4)
{
    memset(info, 0, sizeof(*info));
    info->address_version = 4;
    info->stream = 1;
    memcpy(info->pub_signing, v4->pub_signing, 65);
    memcpy(info->pub_encryption, v4->pub_encryption, 65);
    memcpy(info->priv_signing, v4->priv_signing, 32);
    info->nonce_trials_per_byte = NETWORK_NONCE_TRIALS;
    info->payload_length_extra_bytes = NETWORK_EXTRA_BYTES;
    info->does_ack = 1;
}

static void fill_v5_sender(struct bm_pq_sender_info *info, const struct bm_pqv5_identity *v5)
{
    memset(info, 0, sizeof(*info));
    info->identity = v5;
    info->bitfield = 1u << 1; /* DOESACK相当。v5のbitfield定義はDESIGN-PQ.md §7.2 */
    info->nonce_trials_per_byte = NETWORK_NONCE_TRIALS;
    info->payload_length_extra_bytes = NETWORK_EXTRA_BYTES;
}

static void bench_objects(const struct bm_pqv5_identity *v5, const struct bm_generated_address *v4)
{
    static const size_t body_lens[] = { 0, 100, 1000, 10000 };
    struct bm_identity_info v4_info;
    struct bm_pq_sender_info v5_info;
    unsigned char *obj4;
    unsigned char *obj5;
    size_t len4 = 0;
    size_t len5 = 0;
    size_t i;
    char *body;
    unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char to_kem_sk[BM_PQV5_KEM_SK_LEN];

    fill_v4_identity(&v4_info, v4);
    fill_v5_sender(&v5_info, v5);

    if (bm_pqv5_kem_keypair_from_seed(v5->id, to_kem_pk, to_kem_sk) != 0)
    {
        fprintf(stderr, "recipient KEM keypair failed\n");
        exit(1);
    }

    printf("== 3. オブジェクトサイズ(PoW nonce込み、byte) ==\n");

    obj4 = bm_build_pubkey_v4(&v4_info, v4->ripe, (uint64_t)time(NULL) + TTL_PUBKEY, &len4);
    obj5 = bm_pq_build_pubkey(&v5_info, (uint64_t)time(NULL) + TTL_PUBKEY, &len5);
    if (obj4 == NULL || obj5 == NULL)
    {
        fprintf(stderr, "pubkey build failed\n");
        exit(1);
    }
    printf("  pubkey            v4=%7zu  v5=%7zu  (x%.1f)\n", len4 + 8, len5 + 8,
           (double)(len5 + 8) / (double)(len4 + 8));
    free(obj4);
    free(obj5);

    printf("  --- msg(本文長別) ---\n");
    for (i = 0; i < sizeof(body_lens) / sizeof(body_lens[0]); i++)
    {
        body = malloc(body_lens[i] + 1);
        memset(body, 'a', body_lens[i]);
        body[body_lens[i]] = '\0';

        obj4 = bm_build_msg(&v4_info, 1, v4->ripe, v4->pub_encryption, "s", body, NULL, 0,
                            (uint64_t)time(NULL) + TTL_MSG, &len4);
        obj5 = bm_pq_build_msg(&v5_info, 1, v5->id, to_kem_pk, 2, (const unsigned char *)body,
                               body_lens[i], NULL, 0, (uint64_t)time(NULL) + TTL_MSG, &len5);
        if (obj4 == NULL || obj5 == NULL)
        {
            fprintf(stderr, "msg build failed\n");
            exit(1);
        }
        printf("  body=%6zu       v4=%7zu  v5=%7zu  (x%.1f, +%zu)\n", body_lens[i], len4 + 8, len5 + 8,
               (double)(len5 + 8) / (double)(len4 + 8), (len5 + 8) - (len4 + 8));
        free(obj4);
        free(obj5);
        free(body);
    }

    obj5 = bm_pq_build_broadcast(&v5_info, 2, (const unsigned char *)"hello", 5,
                                 (uint64_t)time(NULL) + TTL_MSG, &len5);
    obj4 = bm_build_broadcast(&v4_info, v4->ripe, "s", "hello", (uint64_t)time(NULL) + TTL_MSG, &len4);
    if (obj4 == NULL || obj5 == NULL)
    {
        fprintf(stderr, "broadcast build failed\n");
        exit(1);
    }
    printf("  broadcast(本文5)  v4=%7zu  v5=%7zu  (x%.1f)\n", len4 + 8, len5 + 8,
           (double)(len5 + 8) / (double)(len4 + 8));
    free(obj4);
    free(obj5);

    obj5 = bm_pq_build_getpubkey(v5->version, v5->stream, v5->id, (uint64_t)time(NULL) + TTL_MSG, &len5);
    obj4 = bm_build_getpubkey(4, 1, v4->ripe, (uint64_t)time(NULL) + TTL_MSG, &len4);
    printf("  getpubkey         v4=%7zu  v5=%7zu\n", len4 + 8, len5 + 8);
    free(obj4);
    free(obj5);

    /* 2^18(MAX_OBJECT_PAYLOAD_SIZE)に収まる本文長の上限 */
    {
        size_t v5_overhead;
        obj5 = bm_pq_build_msg(&v5_info, 1, v5->id, to_kem_pk, 2, (const unsigned char *)"", 0, NULL, 0,
                               (uint64_t)time(NULL) + TTL_MSG, &len5);
        v5_overhead = len5 + 8;
        free(obj5);
        printf("  msgの固定オーバーヘッド: v5=%zu byte → 2^18制限下での本文上限 %zu byte\n",
               v5_overhead, (size_t)(1u << 18) - v5_overhead);
    }
    OPENSSL_cleanse(to_kem_sk, sizeof(to_kem_sk));
    printf("\n");
}

/* --- 4. オブジェクト発行のPoW --- */

struct pow_ctx
{
    unsigned char initial_hash[64];
    uint64_t nonce;
};

static void pow_trial_fn(void *arg)
{
    struct pow_ctx *c = arg;
    bm_pow_trial_value(c->nonce++, c->initial_hash);
}

/*
 * 全コアを同時に回したときの合計ハッシュレートを測る。
 *
 * §11 2026-09-17: 当初は「1コアの実測値 × コア数」で推定していたが、実PoWの
 * 所要時間と4倍ずれた。単一スレッド測定はturbo boostが効いた状態の値であり、
 * 全コア負荷時のクロック低下・SMTによる実効コア数の目減りを無視していたため。
 * PoWは常に全コアを使い切る処理なので、その条件で測らないと意味が無い。
 */
struct hashrate_worker
{
    pthread_t thread;
    unsigned char initial_hash[64];
    uint64_t start;
    double duration;
    uint64_t count;
};

static void *hashrate_worker_fn(void *arg)
{
    struct hashrate_worker *w = arg;
    double t0 = now_sec();
    uint64_t nonce = w->start;
    uint64_t count = 0;

    do
    {
        int i;
        for (i = 0; i < 4096; i++)
        {
            bm_pow_trial_value(nonce++, w->initial_hash);
        }
        count += 4096;
    } while (now_sec() - t0 < w->duration);
    w->count = count;
    return NULL;
}

static double measure_parallel_hashrate(long cores, double seconds)
{
    struct hashrate_worker *workers = calloc((size_t)cores, sizeof(*workers));
    unsigned char initial_hash[64];
    double t0;
    double elapsed;
    uint64_t total = 0;
    long i;

    RAND_bytes(initial_hash, sizeof(initial_hash));
    t0 = now_sec();
    for (i = 0; i < cores; i++)
    {
        memcpy(workers[i].initial_hash, initial_hash, sizeof(initial_hash));
        workers[i].start = (uint64_t)i << 40;
        workers[i].duration = seconds;
        pthread_create(&workers[i].thread, NULL, hashrate_worker_fn, &workers[i]);
    }
    for (i = 0; i < cores; i++)
    {
        pthread_join(workers[i].thread, NULL);
        total += workers[i].count;
    }
    elapsed = now_sec() - t0;
    free(workers);
    return (double)total / elapsed;
}

/* bm_pow_get_targetと同じ式の逆数(期待試行回数)。payload_lenはnonce抜きの長さ */
static double pow_expected_trials(size_t payload_len, uint64_t ttl)
{
    double l = (double)payload_len + 8.0 + NETWORK_EXTRA_BYTES;
    return NETWORK_NONCE_TRIALS * (l + ((double)ttl * l) / 65536.0);
}

/*
 * 実オブジェクトに対してネットワーク既定難易度のPoWを実際に回す。
 *
 * 1回の所要時間は指数分布に従うので単発の実測値はぶれる(期待値の1/6から3倍程度は
 * 普通に出る)。そこで実測時は「見つかったnonce ÷ 所要時間」を実効ハッシュレートとして
 * 併記する。nonceは試した回数そのものなので、こちらは大数の法則が効いて安定した
 * スループット指標になる。
 */
static void pow_one(const char *label, const unsigned char *payload, size_t payload_len,
                     uint64_t ttl, double rate, int run_real_pow)
{
    double expected = pow_expected_trials(payload_len, ttl);

    printf("  %-24s %7zu  %10.3e  %9.1f s", label, payload_len + 8, expected, expected / rate);
    fflush(stdout);
    if (run_real_pow)
    {
        uint64_t target = bm_pow_get_target(payload_len, ttl, NETWORK_NONCE_TRIALS, NETWORK_EXTRA_BYTES);
        double t0 = now_sec();
        uint64_t nonce = bm_pow_run(payload, payload_len, target);
        double elapsed = now_sec() - t0;
        printf("   %9.1f s  %6.2f M/s", elapsed, (double)nonce / elapsed / 1e6);
    }
    printf("\n");
}

static void bench_object_pow(const struct bm_pqv5_identity *v5, const struct bm_generated_address *v4,
                              int run_real_pow)
{
    struct pow_ctx pc;
    double usec;
    double rate;
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct bm_identity_info v4_info;
    struct bm_pq_sender_info v5_info;
    unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char to_kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char *obj;
    size_t len = 0;
    char *body = malloc(1001);
    uint64_t now = (uint64_t)time(NULL);

    memset(&pc, 0, sizeof(pc));
    RAND_bytes(pc.initial_hash, sizeof(pc.initial_hash));
    usec = bench(pow_trial_fn, &pc, 2000000, 0.5);
    if (cores < 1)
    {
        cores = 1;
    }
    rate = measure_parallel_hashrate(cores, 1.0);

    memset(body, 'a', 1000);
    body[1000] = '\0';
    fill_v4_identity(&v4_info, v4);
    fill_v5_sender(&v5_info, v5);
    if (bm_pqv5_kem_keypair_from_seed(v5->id, to_kem_pk, to_kem_sk) != 0)
    {
        fprintf(stderr, "recipient KEM keypair failed\n");
        exit(1);
    }

    printf("== 4. オブジェクト発行のPoW(nonceTrialsPerByte=%d, extraBytes=%d) ==\n",
           NETWORK_NONCE_TRIALS, NETWORK_EXTRA_BYTES);
    printf("  ハッシュレート: 単一スレッド %.2f M/s、全%ldコア同時 %.2f M/s"
           "(単純な%ld倍より%.1f倍低い: turbo低下とSMTのため)\n",
           1e6 / usec / 1e6, cores, rate / 1e6, cores, (1e6 / usec) * (double)cores / rate);
    printf("  %-24s %7s  %10s  %11s%s\n", "オブジェクト", "byte", "期待試行", "期待所要",
           run_real_pow ? "     実測(1回)   実効レート" : "  (--powで実測)");

    obj = bm_build_pubkey_v4(&v4_info, v4->ripe, now + TTL_PUBKEY, &len);
    pow_one("v4 pubkey (TTL 28日)", obj, len, TTL_PUBKEY, rate, run_real_pow);
    free(obj);

    obj = bm_pq_build_pubkey(&v5_info, now + TTL_PUBKEY, &len);
    pow_one("v5 pubkey (TTL 28日)", obj, len, TTL_PUBKEY, rate, run_real_pow);
    free(obj);

    obj = bm_build_msg(&v4_info, 1, v4->ripe, v4->pub_encryption, "s", body, NULL, 0, now + TTL_MSG, &len);
    pow_one("v4 msg 本文1000 (4日)", obj, len, TTL_MSG, rate, run_real_pow);
    free(obj);

    obj = bm_pq_build_msg(&v5_info, 1, v5->id, to_kem_pk, 2, (const unsigned char *)body, 1000, NULL, 0,
                          now + TTL_MSG, &len);
    pow_one("v5 msg 本文1000 (4日)", obj, len, TTL_MSG, rate, run_real_pow);
    free(obj);

    obj = bm_pq_build_getpubkey(v5->version, v5->stream, v5->id, now + TTL_PUBKEY, &len);
    pow_one("v5 getpubkey (28日)", obj, len, TTL_PUBKEY, rate, run_real_pow);
    free(obj);

    obj = bm_pq_build_broadcast(&v5_info, 2, (const unsigned char *)body, 1000, now + TTL_MSG, &len);
    pow_one("v5 broadcast 1000 (4日)", obj, len, TTL_MSG, rate, run_real_pow);
    free(obj);

    OPENSSL_cleanse(to_kem_sk, sizeof(to_kem_sk));
    free(body);
    printf("\n");
}

int main(int argc, char **argv)
{
    struct bm_pqv5_identity v5;
    struct bm_generated_address v4;
    int run_real_pow = (argc > 1 && strcmp(argv[1], "--pow") == 0);

    /* 長時間走るので、パイプ/ファイルへリダイレクトされていても途中経過が見えるように行バッファへ */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("bm-pq-bench (DESIGN-PQ.md §8) — v5プロファイル: ML-DSA-65 + Ed25519 / "
           "X-Wing(ML-KEM-768 + X25519) / AES-256-GCM\n\n");

    bench_primitives();
    bench_addresses(&v5, &v4);
    bench_objects(&v5, &v4);
    bench_object_pow(&v5, &v4, run_real_pow);
    return 0;
}
