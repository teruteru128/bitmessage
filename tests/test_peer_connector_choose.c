/*
 * §11 2026-08-23: peer接続選定の確率的な重み付きランダムサンプリング
 * (bm_peer_connector_choose_candidate_index、PyBitmessage本家network/connectionchooser.py
 * chooseConnectionの移植)の回帰テスト。以前は"rating上位N件を毎回そのまま順に使う"設計
 * だったため、rating上位の少数peerだけが毎サイクル選ばれ続け、実測で40候補中9件が
 * 11回以上(最大222回)再接続される一方25件は1回しか試されない「強者総取り」状態に
 * なっていた。ここでは大量に繰り返し呼んだ際の選ばれる頻度分布を検証する:
 * (1) rating下位の候補にも一定の非ゼロな確率で順番が回ること
 * (2) rating上位の候補の方が明確に高い頻度で選ばれること(重み付けが機能している)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/peer_connector.h"

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

#define N_HIGH 5
#define N_LOW 5
#define N_MID 240
#define N_TOTAL (N_HIGH + N_LOW + N_MID)
#define N_TRIALS 20000

int main(void)
{
    struct bm_peer_entry candidates[N_TOTAL];
    memset(candidates, 0, sizeof(candidates));
    int idx = 0;
    for (int i = 0; i < N_HIGH; i++, idx++)
    {
        snprintf(candidates[idx].ip_address, sizeof(candidates[idx].ip_address), "10.0.0.%d", idx);
        candidates[idx].port = 8444;
        candidates[idx].rating = 0.9;
    }
    for (int i = 0; i < N_LOW; i++, idx++)
    {
        snprintf(candidates[idx].ip_address, sizeof(candidates[idx].ip_address), "10.0.0.%d", idx);
        candidates[idx].port = 8444;
        candidates[idx].rating = -0.9;
    }
    for (int i = 0; i < N_MID; i++, idx++)
    {
        snprintf(candidates[idx].ip_address, sizeof(candidates[idx].ip_address), "10.0.0.%d", idx);
        candidates[idx].port = 8444;
        candidates[idx].rating = 0.0;
    }

    long picked_high = 0, picked_low = 0, picked_mid = 0, gave_up = 0;
    for (int t = 0; t < N_TRIALS; t++)
    {
        int chosen = bm_peer_connector_choose_candidate_index(candidates, N_TOTAL, NULL, 50);
        if (chosen < 0)
        {
            gave_up++;
            continue;
        }
        if (chosen < N_HIGH)
        {
            picked_high++;
        }
        else if (chosen < N_HIGH + N_LOW)
        {
            picked_low++;
        }
        else
        {
            picked_mid++;
        }
    }

    fprintf(stderr,
            "[test_peer_connector_choose] picked_high=%ld picked_low=%ld picked_mid=%ld gave_up=%ld "
            "(trials=%d)\n",
            picked_high, picked_low, picked_mid, gave_up, N_TRIALS);

    CHECK(gave_up < N_TRIALS / 10, "giving up (all 50 attempts rejected) should be rare, not the common case");

    /* (1) rating下位(5件)にも非ゼロな確率で順番が回ること。5件でN_TRIALS=20000回のうち
     * 1件でも一切選ばれない、ということが無いようにする(強者総取りの再発防止が主眼) */
    CHECK(picked_low > 0, "low-rating candidates should be selected at least sometimes, not starved entirely");

    /* (2) rating上位(5件)の1件あたりの選ばれやすさが、rating下位(5件)の1件あたりより
     * 明確に高いこと(重み付けが機能していることの確認。0.9のprobは0.5、-0.9のprobは
     * 0.05/1.9≒0.026で、比率にすると約19倍の差がある想定。統計的なテストなので閾値には
     * 余裕を持たせ、"高い方が低い方の3倍以上"程度の緩い基準にする) */
    double per_high = (double)picked_high / N_HIGH;
    double per_low = (double)picked_low / N_LOW;
    CHECK(per_high > per_low * 3.0,
          "high-rating candidates should be picked noticeably more often (per-candidate) than low-rating "
          "ones: the weighting should have a real effect");

    /* mid(rating 0.0)も一定量選ばれていること(候補の大半を占めるため、これが極端に
     * 少ないと「上位に偏りすぎ」という別の問題が疑われる) */
    CHECK(picked_mid > 0, "mid-rating candidates should be selected too");

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
