#ifndef BM_POW_ENGINE_H
#define BM_POW_ENGINE_H

/*
 * Proof of Work計算エンジン。DESIGN.md §4。
 */

#include <stddef.h>
#include <stdint.h>

/* §4.1: target計算式。__uint128_tで中間演算しオーバーフローを避ける */
uint64_t bm_pow_get_target(size_t payload_length, uint64_t ttl,
                            uint64_t nonce_trials_per_byte, uint64_t payload_length_extra_bytes);

/* §4.2: trial value = double_sha512(nonce(8byte BE) || initial_hash)[0:8] (BE解釈) */
uint64_t bm_pow_trial_value(uint64_t nonce, const unsigned char initial_hash[64]);

/*
 * §4.3: payload(nonce抜き)に対しPoWを計算し、見つかったnonceを返す。
 * TODO: 現状は単一スレッド探索(PyBitmessageの_doSafePoW相当)。
 * NumCPU本のワーカースレッドに割り当てる並列化は今後実装する。
 */
uint64_t bm_pow_run(const unsigned char *payload, size_t payload_len, uint64_t target);

#endif /* BM_POW_ENGINE_H */
