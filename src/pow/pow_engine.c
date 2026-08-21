#include "pow_engine.h"

#include <endian.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/hash.h"

uint64_t bm_pow_get_target(size_t payload_length, uint64_t ttl,
                            uint64_t nonce_trials_per_byte, uint64_t payload_length_extra_bytes)
{
    __uint128_t l = (__uint128_t)payload_length + 8 + payload_length_extra_bytes;
    __uint128_t denom = (__uint128_t)nonce_trials_per_byte * (l + (((__uint128_t)ttl * l) >> 16));
    __uint128_t target = (((__uint128_t)1) << 64) / denom;
    if (target > UINT64_MAX)
    {
        target = UINT64_MAX;
    }
    return (uint64_t)target;
}

uint64_t bm_pow_trial_value(uint64_t nonce, const unsigned char initial_hash[64])
{
    unsigned char buf[8 + 64];
    uint64_t be_nonce = htobe64(nonce);
    memcpy(buf, &be_nonce, 8);
    memcpy(buf + 8, initial_hash, 64);

    unsigned char digest[64];
    bm_double_sha512(buf, sizeof(buf), digest);

    uint64_t value;
    memcpy(&value, digest, 8);
    return be64toh(value);
}

struct pow_worker_arg
{
    const unsigned char *initial_hash; /* 64byte、全ワーカーで共有(読み取り専用) */
    uint64_t target;
    uint64_t start_nonce; /* ワーカー番号(0〜num_threads-1) */
    uint64_t stride;      /* num_threads */
    atomic_bool *found;
    atomic_uint_fast64_t *result_nonce;
};

static void *pow_worker(void *arg_)
{
    struct pow_worker_arg *arg = arg_;
    uint64_t nonce = arg->start_nonce;

    /* found確認は毎回だとメモリバリアのコストが無視できないほど探索が軽いケースもあるので、
     * 適度に間引く(64回に1回)。取りこぼしても他ワーカーの結果を待つだけで正しさには影響しない */
    for (uint64_t i = 0;; i++, nonce += arg->stride)
    {
        if ((i & 0x3f) == 0 && atomic_load_explicit(arg->found, memory_order_relaxed))
        {
            return NULL;
        }
        if (bm_pow_trial_value(nonce, arg->initial_hash) <= arg->target)
        {
            bool expected = false;
            if (atomic_compare_exchange_strong(arg->found, &expected, true))
            {
                atomic_store_explicit(arg->result_nonce, nonce, memory_order_relaxed);
            }
            return NULL;
        }
    }
}

uint64_t bm_pow_run(const unsigned char *payload, size_t payload_len, uint64_t target)
{
    unsigned char initial_hash[64];
    bm_sha512(payload, payload_len, initial_hash);

    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    size_t num_threads = (num_cpus >= 1) ? (size_t)num_cpus : 1;

    if (num_threads <= 1)
    {
        uint64_t nonce = 0;
        while (bm_pow_trial_value(nonce, initial_hash) > target)
        {
            nonce++;
        }
        return nonce;
    }

    atomic_bool found = false;
    atomic_uint_fast64_t result_nonce = 0;

    pthread_t *threads = malloc(sizeof(*threads) * num_threads);
    struct pow_worker_arg *args = malloc(sizeof(*args) * num_threads);
    for (size_t i = 0; i < num_threads; i++)
    {
        args[i].initial_hash = initial_hash;
        args[i].target = target;
        args[i].start_nonce = (uint64_t)i;
        args[i].stride = (uint64_t)num_threads;
        args[i].found = &found;
        args[i].result_nonce = &result_nonce;
        pthread_create(&threads[i], NULL, pow_worker, &args[i]);
    }
    for (size_t i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }
    free(threads);
    free(args);

    return atomic_load_explicit(&result_nonce, memory_order_relaxed);
}
