/*
 * §11 2026-08-24: rating<0の候補に課す再接続クールダウン
 * (BM_PEER_LOW_RATING_COOLDOWN_SECONDS、peer_connector.c)の回帰テスト。
 *
 * 背景: 実daemonの運用ログで、rating=-1.0のまま塩漬けになっている特定peerへ、
 * うちのdaemon自身が13時台〜14時台の1.5時間で少なくとも9回もoutbound接続を
 * 繰り返していたことが判明した。PyBitmessage本家のchooseConnection
 * (network/connectionchooser.py)を調査したところ、prob = 0.05/(1-rating)という
 * 確率式そのものが本家由来であり、rating<0を完全排除しない設計自体は「うちの
 * バグ」ではなく「PyBitmessage本家の仕様」だと確認できた(ユーザーとの議論の結論)。
 *
 * ただし「TCP応答はあるが直後にfatal切断してくるノード」への無駄な再接続実害は
 * 実在するため、rating/last_seenの意味論(PyBitmessage互換)には一切手を付けず、
 * 候補選定(bm_peer_connector_choose_candidate_index)側にのみ、last_attempt基準の
 * クールダウンを追加した。rating>=0の候補には一切影響しない設計。
 *
 * --- シナリオ1: rating<0の候補はクールダウン中(直近の接続試行から
 *     BM_PEER_LOW_RATING_COOLDOWN_SECONDS未満)は選ばれない ---
 * --- シナリオ2: クールダウンが明けれ(経過時間がBM_PEER_LOW_RATING_COOLDOWN_SECONDS
 *     以上)ば、rating<0の候補も再び選ばれうる ---
 * --- シナリオ3: rating>=0の候補は、last_attemptが直近でも一切影響を受けない
 *     (=本家互換の挙動を維持していること) ---
 * --- シナリオ4: bm_peer_manager_record_attempt/list_topのDB往復(last_attempt列が
 *     実際に永続化・再取得できること) ---
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/peer_connector.h"

#define TEST_DB "test_peer_reconnect_cooldown.db"

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

/* BM_PEER_LOW_RATING_COOLDOWN_SECONDSはpeer_connector.c内のfile-local define
 * (テストからは見えない)なので、実装と合わせておく。ズレたらこのテストが
 * 意図通りに落ちる(=実装側の変更に追従が必要だと分かる)よう、あえて再定義する。 */
#define COOLDOWN_SECONDS 1800

int main(void)
{
    /* --- シナリオ1・2: クールダウン中/明けた後の選出可否 --- */
    {
        struct bm_peer_entry candidates[1];
        memset(candidates, 0, sizeof(candidates));
        strncpy(candidates[0].ip_address, "95.49.240.98", sizeof(candidates[0].ip_address) - 1);
        candidates[0].port = 8444;
        candidates[0].rating = -1.0;

        int64_t base_now = 1000000000;
        candidates[0].last_attempt = base_now;

        /* クールダウン中(経過0秒): 選ばれないはず */
        int chosen = bm_peer_connector_choose_candidate_index(candidates, 1, NULL, 50, base_now);
        CHECK(chosen < 0, "a rating<0 candidate within the cooldown window should never be chosen");

        /* クールダウン中(経過COOLDOWN_SECONDS-1秒): まだ選ばれないはず */
        chosen = bm_peer_connector_choose_candidate_index(candidates, 1, NULL, 50,
                                                            base_now + COOLDOWN_SECONDS - 1);
        CHECK(chosen < 0, "a rating<0 candidate just before cooldown expiry should still not be chosen");

        /* クールダウン明け(経過COOLDOWN_SECONDS秒以上): 確率的には選ばれうる。
         * rating=-1.0のprobは0.05/2.0=2.5%なので、十分な回数を試せばほぼ確実に
         * 1回は選ばれるはずだが、statistical flakinessを避けるため
         * max_attemptsを大きく(10000)して確実性を高める。 */
        chosen = bm_peer_connector_choose_candidate_index(candidates, 1, NULL, 10000,
                                                            base_now + COOLDOWN_SECONDS);
        CHECK(chosen == 0, "a rating<0 candidate should become selectable again once the cooldown has elapsed");
    }

    /* --- シナリオ3: rating>=0の候補はクールダウンの影響を受けない --- */
    {
        struct bm_peer_entry candidates[1];
        memset(candidates, 0, sizeof(candidates));
        strncpy(candidates[0].ip_address, "203.0.113.5", sizeof(candidates[0].ip_address) - 1);
        candidates[0].port = 8444;
        candidates[0].rating = 0.5;

        int64_t now = 1000000000;
        candidates[0].last_attempt = now; /* たった今接続を試みたばかり */

        /* rating=0.5、prob=0.05/0.5=10%。max_attempts=10000あれば統計的にほぼ必ず選ばれる */
        int chosen = bm_peer_connector_choose_candidate_index(candidates, 1, NULL, 10000, now);
        CHECK(chosen == 0,
              "a rating>=0 candidate should remain selectable immediately after an attempt "
              "(cooldown must not apply to non-negative ratings, to stay PyBitmessage-compatible)");
    }

    /* --- シナリオ4: DB往復(record_attempt -> list_top) --- */
    {
        unlink(TEST_DB);
        sqlite3 *db = NULL;
        if (sqlite3_open(TEST_DB, &db) != SQLITE_OK || bm_peer_manager_init_schema(db) != 0)
        {
            fprintf(stderr, "FATAL: could not open/init %s\n", TEST_DB);
            return EXIT_FAILURE;
        }

        struct bm_peer_entry entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.ip_address, "198.51.100.9", sizeof(entry.ip_address) - 1);
        entry.port = 8444;
        entry.stream = 1;
        entry.rating = -1.0;
        strncpy(entry.source, "seed", sizeof(entry.source) - 1);
        CHECK(bm_peer_manager_upsert(db, &entry) == 0, "seeding a row should succeed");

        {
            struct bm_peer_entry results[4];
            int count = 0;
            CHECK(bm_peer_manager_list_top(db, 1, results, 4, &count) == 0 && count == 1,
                  "list_top should return the seeded row");
            CHECK(results[0].last_attempt == 0, "a never-attempted row should have last_attempt=0");
        }

        CHECK(bm_peer_manager_record_attempt(db, "198.51.100.9", 8444, 1, 1234567890) == 0,
              "record_attempt should succeed");

        {
            struct bm_peer_entry results[4];
            int count = 0;
            CHECK(bm_peer_manager_list_top(db, 1, results, 4, &count) == 0 && count == 1,
                  "list_top should still return the row");
            CHECK(results[0].last_attempt == 1234567890,
                  "last_attempt should be persisted and readable back via list_top");
            /* record_attemptはrating/last_seenを一切変更しないこと(接続の成否ではなく
             * 「試みた」事実のみを記録する) */
            CHECK(results[0].rating > -1.0 - 1e-9 && results[0].rating < -1.0 + 1e-9,
                  "record_attempt must not change rating");
        }

        sqlite3_close(db);
        unlink(TEST_DB);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
