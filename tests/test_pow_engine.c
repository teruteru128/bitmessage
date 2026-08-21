/*
 * pow/pow_engine.c のテスト。DESIGN.md §4, §11(PoW並列化)。
 * 並列化したbm_pow_runが返すnonceが実際にtargetを満たすことを、複数の乱数payloadで
 * 繰り返し検証する(スレッド間の競合で誤ったnonceを返す/取りこぼす類のバグを拾うため)。
 */

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/hash.h"
#include "../src/pow/pow_engine.h"

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

int main(void)
{
    /* §4.1: 実ネットワーク相当の難易度(1000,1000)だと1回あたり数秒かかるため、テストでは
     * 軽い難易度(50,50)を使う。検証したいのはpow_engine.cのパース/探索ロジックの正しさ
     * であって、ここでは正当性(生成したnonceがtargetを満たすか)が焦点。 */
    for (int trial = 0; trial < 8; trial++)
    {
        size_t payload_len = 32 + (size_t)(trial * 17);
        unsigned char *payload = malloc(payload_len);
        CHECK(RAND_bytes(payload, (int)payload_len) == 1, "RAND_bytes for test payload");

        uint64_t target = bm_pow_get_target(payload_len, 60, 50, 50);
        uint64_t nonce = bm_pow_run(payload, payload_len, target);

        unsigned char initial_hash[64];
        bm_sha512(payload, payload_len, initial_hash);
        uint64_t trial_value = bm_pow_trial_value(nonce, initial_hash);

        CHECK(trial_value <= target, "bm_pow_run should return a nonce satisfying the target");

        free(payload);
    }

    /* target計算式(§4.1)の単純な性質: ttl/extra_bytesが大きいほどtargetは小さくなる
     * (=難易度が上がる)はず */
    uint64_t payload_len = 1000;
    uint64_t target_easy = bm_pow_get_target(payload_len, 60, 1000, 1000);
    uint64_t target_hard = bm_pow_get_target(payload_len, 60 * 60 * 24 * 5, 1000, 1000);
    CHECK(target_hard < target_easy, "longer TTL should produce a smaller (harder) target");

    uint64_t target_more_nonce_trials = bm_pow_get_target(payload_len, 60, 2000, 1000);
    CHECK(target_more_nonce_trials < target_easy,
          "higher nonce_trials_per_byte should produce a smaller (harder) target");

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
