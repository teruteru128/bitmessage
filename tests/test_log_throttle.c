/*
 * §11 2026-09-25 項目46: common/log_throttle.c(同じ理由のログを一定間隔に1回へ間引く)の
 * 単体テスト。時計が数時間ずれたPyBitmessageノードが数秒おきにinbound接続してきて、
 * version timestamp検証による切断のWARNが1時間に約190行journalを埋めたのがきっかけ。
 * 検証観点: 最初の1回は必ず出る/間隔内は黙って回数を数える/間隔が空いたら黙った回数を
 * 添えて出し数をリセットする/時計が巻き戻っても黙り続けない。時刻は引数で渡すので
 * 壁時計待ちは無い。
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/log_throttle.h"

static int failures = 0;

#define CHECK(cond, msg)                                                    \
    do                                                                      \
    {                                                                       \
        if (!(cond))                                                        \
        {                                                                   \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

int main(void)
{
    struct bm_log_throttle t;
    memset(&t, 0, sizeof(t));
    uint64_t suppressed = 12345;

    /* --- 1. ゼロ初期化直後の最初の1回は必ず出る(黙った回数は0) --- */
    CHECK(bm_log_throttle_check(&t, 1000, 600, &suppressed) == 1, "the first call should emit");
    CHECK(suppressed == 0, "nothing should have been suppressed before the first emit");

    /* --- 2. 間隔内の呼び出しは黙る。*out_suppressedは触らない --- */
    suppressed = 999;
    CHECK(bm_log_throttle_check(&t, 1004, 600, &suppressed) == 0, "a call 4s later should be suppressed");
    CHECK(bm_log_throttle_check(&t, 1300, 600, &suppressed) == 0, "a call 300s later should be suppressed");
    CHECK(bm_log_throttle_check(&t, 1599, 600, &suppressed) == 0, "a call 599s later should be suppressed");
    CHECK(suppressed == 999, "a suppressed call should not touch *out_suppressed");

    /* --- 3. ちょうど間隔が空いたら出て、黙った3回を報告し、数をリセットする --- */
    CHECK(bm_log_throttle_check(&t, 1600, 600, &suppressed) == 1, "a call exactly 600s later should emit");
    CHECK(suppressed == 3, "the emit should report the 3 suppressed calls");

    /* --- 4. リセット後は前回の出力時刻から数え直す --- */
    CHECK(bm_log_throttle_check(&t, 1601, 600, &suppressed) == 0, "the next call right after should be suppressed");
    CHECK(bm_log_throttle_check(&t, 2300, 600, &suppressed) == 1, "a call after another interval should emit");
    CHECK(suppressed == 1, "only the calls since the previous emit should be counted");

    /* --- 5. 時計が巻き戻った場合は黙り続けずに出す --- */
    CHECK(bm_log_throttle_check(&t, 100, 600, &suppressed) == 1, "a clock step backwards should emit");
    CHECK(suppressed == 0, "nothing was suppressed between the last emit and the clock step");

    /* --- 6. out_suppressedはNULL可 --- */
    CHECK(bm_log_throttle_check(&t, 101, 600, NULL) == 0, "suppression should work with a NULL out pointer");
    CHECK(bm_log_throttle_check(&t, 800, 600, NULL) == 1, "emitting should work with a NULL out pointer");

    if (failures > 0)
    {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("OK: log_throttle\n");
    return EXIT_SUCCESS;
}
