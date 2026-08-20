#include "pow_engine.h"

#include <endian.h>
#include <string.h>

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

uint64_t bm_pow_run(const unsigned char *payload, size_t payload_len, uint64_t target)
{
    unsigned char initial_hash[64];
    bm_sha512(payload, payload_len, initial_hash);

    uint64_t nonce = 0;
    while (bm_pow_trial_value(nonce, initial_hash) > target)
    {
        nonce++;
    }
    return nonce;
}
