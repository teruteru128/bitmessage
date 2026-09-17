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
    bm_pqv5_sign("bench", c->msg, sizeof(c->msg), c->sig_sk, c->sig);
}

static void hybrid_verify_fn(void *arg)
{
    struct hybrid_ctx *c = arg;
    if (bm_pqv5_verify("bench", c->msg, sizeof(c->msg), c->sig, c->sig_pk) != 1)
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
    bm_pqv5_sign("bench", hc.msg, sizeof(hc.msg), hc.sig_sk, hc.sig);
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

static void bench_addresses(struct bm_pqv5_identity *out_v5, struct bm_generated_address *out_v4)
{
    double t0;
    double t1;
    char *addr4;
    char *addr5;
    struct bm_pqv5_identity tmp;

    printf("== 2. アドレス生成 ==\n");

    t0 = now_sec();
    if (bm_address_generate_deterministic("bm-pq-bench passphrase", 1, out_v4) != 0)
    {
        fprintf(stderr, "v4 address generation failed\n");
        exit(1);
    }
    t1 = now_sec();
    addr4 = bm_address_encode(4, 1, out_v4->ripe, BM_RIPE_LEN);
    printf("  v4 決定性生成(null_bytes=1, nonce=%" PRIu64 "): %8.1f ms  address=%s (%zu文字)\n",
           out_v4->signing_nonce, (t1 - t0) * 1e3, addr4, strlen(addr4));

    t0 = now_sec();
    if (bm_pqv5_identity_generate_deterministic("bm-pq-bench passphrase", 1, 0, 0, out_v5) != 0)
    {
        fprintf(stderr, "v5 address generation failed\n");
        exit(1);
    }
    t1 = now_sec();
    addr5 = bm_pqv5_address_encode(out_v5->version, out_v5->stream, out_v5->id);
    printf("  v5 決定性生成(null_bytes=0, nonce=%" PRIu64 "): %8.1f ms  address=%s (%zu文字)\n",
           out_v5->sig_nonce, (t1 - t0) * 1e3, addr5, strlen(addr5));

    t0 = now_sec();
    if (bm_pqv5_identity_generate_deterministic("bm-pq-bench passphrase", 1, 0, 1, &tmp) != 0)
    {
        fprintf(stderr, "v5 vanity address generation failed\n");
        exit(1);
    }
    t1 = now_sec();
    printf("  v5 決定性生成(null_bytes=1, nonce=%" PRIu64 "): %8.1f ms  (参考: v5では既定で要求しない)\n",
           tmp.sig_nonce, (t1 - t0) * 1e3);

    free(addr4);
    free(addr5);
    printf("\n");
}

/* --- 3. オブジェクトサイズ --- */

static uint64_t pow_expected_trials(size_t payload_len, uint64_t ttl)
{
    /* §4.1のtarget式の逆数。payload_lenはnonce込みの完成object長 */
    double length = (double)payload_len + NETWORK_EXTRA_BYTES;
    return (uint64_t)(NETWORK_NONCE_TRIALS * (length + ((double)ttl * length) / 65536.0));
}

struct object_sizes
{
    size_t v4_msg;
    size_t v5_msg;
};

static struct object_sizes bench_objects(const struct bm_pqv5_identity *v5,
                                          const struct bm_generated_address *v4)
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
    struct object_sizes sizes;
    unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char to_kem_sk[BM_PQV5_KEM_SK_LEN];

    memset(&sizes, 0, sizeof(sizes));
    memset(&v4_info, 0, sizeof(v4_info));
    v4_info.address_version = 4;
    v4_info.stream = 1;
    memcpy(v4_info.pub_signing, v4->pub_signing, 65);
    memcpy(v4_info.pub_encryption, v4->pub_encryption, 65);
    memcpy(v4_info.priv_signing, v4->priv_signing, 32);
    v4_info.nonce_trials_per_byte = NETWORK_NONCE_TRIALS;
    v4_info.payload_length_extra_bytes = NETWORK_EXTRA_BYTES;
    v4_info.does_ack = 1;

    memset(&v5_info, 0, sizeof(v5_info));
    v5_info.identity = v5;
    v5_info.bitfield = 1u << 1; /* DOESACK相当。v5のbitfield定義はDESIGN-PQ.md §7.2 */
    v5_info.nonce_trials_per_byte = NETWORK_NONCE_TRIALS;
    v5_info.payload_length_extra_bytes = NETWORK_EXTRA_BYTES;

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
        if (body_lens[i] == 1000)
        {
            sizes.v4_msg = len4 + 8;
            sizes.v5_msg = len5 + 8;
        }
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
    return sizes;
}

/* --- 4. PoW --- */

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

static void bench_pow(const struct object_sizes *sizes, int run_real_pow)
{
    struct pow_ctx pc;
    double usec;
    double per_core;
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t trials4;
    uint64_t trials5;

    memset(&pc, 0, sizeof(pc));
    RAND_bytes(pc.initial_hash, sizeof(pc.initial_hash));
    usec = bench(pow_trial_fn, &pc, 2000000, 0.5);
    per_core = 1e6 / usec;
    if (cores < 1)
    {
        cores = 1;
    }

    printf("== 4. PoWコスト(nonceTrialsPerByte=%d, extraBytes=%d) ==\n", NETWORK_NONCE_TRIALS,
           NETWORK_EXTRA_BYTES);
    printf("  実測ハッシュレート: %.2f Mtrial/s/core × %ld core = %.2f Mtrial/s\n", per_core / 1e6,
           cores, per_core * (double)cores / 1e6);

    trials4 = pow_expected_trials(sizes->v4_msg, TTL_MSG);
    trials5 = pow_expected_trials(sizes->v5_msg, TTL_MSG);
    printf("  msg(本文1000, TTL 4日)  v4: %10" PRIu64 " trials → %6.1f 秒\n", trials4,
           (double)trials4 / (per_core * (double)cores));
    printf("                          v5: %10" PRIu64 " trials → %6.1f 秒  (x%.2f)\n", trials5,
           (double)trials5 / (per_core * (double)cores), (double)trials5 / (double)trials4);

    if (run_real_pow)
    {
        unsigned char payload[64];
        double t0;
        uint64_t target;
        uint64_t nonce;
        /* 実PoWは「同じ長さ・同じ難易度」なら中身に依らないので、長さだけ合わせた
         * ダミーpayloadで測る(オブジェクトの中身はPoWの所要時間に影響しない) */
        unsigned char *dummy = calloc(sizes->v5_msg - 8, 1);
        RAND_bytes(payload, sizeof(payload));
        RAND_bytes(dummy, 32);
        target = bm_pow_get_target(sizes->v5_msg, TTL_MSG, NETWORK_NONCE_TRIALS, NETWORK_EXTRA_BYTES);
        t0 = now_sec();
        nonce = bm_pow_run(dummy, sizes->v5_msg - 8, target);
        printf("  実測PoW(v5 msgサイズ): %.1f 秒 (nonce=%" PRIu64 ")\n", now_sec() - t0, nonce);
        free(dummy);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    struct bm_pqv5_identity v5;
    struct bm_generated_address v4;
    struct object_sizes sizes;
    int run_real_pow = (argc > 1 && strcmp(argv[1], "--pow") == 0);

    /* 長時間走るので、パイプ/ファイルへリダイレクトされていても途中経過が見えるように行バッファへ */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("bm-pq-bench (DESIGN-PQ.md §8) — v5プロファイル: ML-DSA-65 + Ed25519 / "
           "X-Wing(ML-KEM-768 + X25519) / AES-256-GCM\n\n");

    bench_primitives();
    bench_addresses(&v5, &v4);
    sizes = bench_objects(&v5, &v4);
    bench_pow(&sizes, run_real_pow);
    return 0;
}
