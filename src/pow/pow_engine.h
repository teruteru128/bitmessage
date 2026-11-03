#ifndef BM_POW_ENGINE_H
#define BM_POW_ENGINE_H

/*
 * Proof of Work計算エンジン。DESIGN.md §4。
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* §4.1: target計算式。__uint128_tで中間演算しオーバーフローを避ける */
uint64_t bm_pow_get_target(size_t payload_length, uint64_t ttl,
                            uint64_t nonce_trials_per_byte, uint64_t payload_length_extra_bytes);

/* §4.2: trial value = double_sha512(nonce(8byte BE) || initial_hash)[0:8] (BE解釈) */
uint64_t bm_pow_trial_value(uint64_t nonce, const unsigned char initial_hash[64]);

/*
 * §4.3: payload(nonce抜き)に対しPoWを計算し、見つかったnonceを返す。
 * sysconf(_SC_NPROCESSORS_ONLN)本のワーカースレッドに探索空間をstride分割して割り当てる
 * (PyBitmessageの_doSafePoW相当をさらに並列化したもの)。ワーカーiはnonce=i,i+N,i+2N,...を
 * 担当し、いずれかが条件を満たすnonceを見つけたら他のワーカーへ通知して打ち切る。
 * CPUコア数取得に失敗した場合は1スレッド(従来のシングルスレッド探索と同じ経路)にフォールバックする。
 */
uint64_t bm_pow_run(const unsigned char *payload, size_t payload_len, uint64_t target);

/*
 * §11 2026-11-03 項目38: bm_pow_runの打ち切り可能版。cancel(NULL可)が立ったら探索を
 * 打ち切って-1を返す(各ワーカーは既存のfound確認と同じく64回に1回だけcancelを見るので、
 * 立ててから戻るまでの遅れは高々数十マイクロ秒)。見つかれば*out_nonceへ書いて0を返す。
 * pow_queue(pow_queue.h)のshutdownで、走行中のv5 pubkey(期待141秒、DESIGN-PQ.md §8.4)の
 * ようなPoWの完了をjoinが待たされないようにするために足した。
 */
int bm_pow_run_cancellable(const unsigned char *payload, size_t payload_len, uint64_t target,
                           const atomic_bool *cancel, uint64_t *out_nonce);

#endif /* BM_POW_ENGINE_H */
