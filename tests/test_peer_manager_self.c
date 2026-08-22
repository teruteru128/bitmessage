/*
 * §11 2026-08-22: peer_manager.cのis_self機能(PyBitmessageのknownnodes myselfフィールド
 * 相当)のテスト。version messageのnonceによる自己接続検知は、Torではプロセス全体で
 * 同じnonceを使い回すこと自体が匿名性を損なうため採用せず(ユーザーとの議論の結論)、
 * 代わりに自分自身のonionアドレスをhostsテーブルへis_self=1としてマークし、
 * bm_peer_manager_list_top(接続候補選定)から除外する設計にした。
 *
 * - 新規行としてmark_selfした場合、list_topから除外されること
 * - 既にgossip等で学習済みだった行をmark_selfした場合、rating/sourceを保ったまま
 *   is_selfだけ立ち、list_topから除外されるようになること
 * - is_self列が無い"古い"DB(このカラム追加より前のスキーマ)に対しても
 *   bm_peer_manager_init_schemaがマイグレーション(ALTER TABLE)して問題なく動作すること
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"

#define TEST_DB "test_peer_manager_self.db"

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

static int has_ip_port(struct bm_peer_entry *results, int count, const char *ip, int port)
{
    for (int i = 0; i < count; i++)
    {
        if (strcmp(results[i].ip_address, ip) == 0 && results[i].port == port)
        {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    unlink(TEST_DB);
    sqlite3 *db = NULL;
    if (sqlite3_open(TEST_DB, &db) != SQLITE_OK || bm_peer_manager_init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", TEST_DB);
        return EXIT_FAILURE;
    }

    /* --- 1. 新規行としてmark_self: list_topから除外されること --- */
    CHECK(bm_peer_manager_mark_self(db, "abc123.onion", 8444, 1) == 0, "mark_self (new row) should succeed");
    {
        struct bm_peer_entry results[16];
        int count = 0;
        CHECK(bm_peer_manager_list_top(db, 1, results, 16, &count) == 0, "list_top should succeed");
        CHECK(!has_ip_port(results, count, "abc123.onion", 8444),
              "a newly self-marked peer should be excluded from list_top");
    }

    /* --- 2. gossipで既に学習済みだった行をmark_self: rating/sourceは保持され、
     * かつlist_topから除外されるようになること --- */
    CHECK(bm_peer_manager_upsert_learned(db, "def456.onion", 8444, 1, 1, 1000, "onionpeer_obj") == 0,
          "upsert_learned should succeed");
    /* まだmark_self前なのでlist_topに含まれているはず */
    {
        struct bm_peer_entry results[16];
        int count = 0;
        bm_peer_manager_list_top(db, 1, results, 16, &count);
        CHECK(has_ip_port(results, count, "def456.onion", 8444),
              "a learned (not-yet-self) peer should still appear in list_top");
    }
    /* この行のratingを実接続実績で0.5まで積んでおく(mark_self後も保持されるべき値) */
    bm_peer_manager_record_result(db, "def456.onion", 8444, 1, 1);
    bm_peer_manager_record_result(db, "def456.onion", 8444, 1, 1);
    bm_peer_manager_record_result(db, "def456.onion", 8444, 1, 1);
    bm_peer_manager_record_result(db, "def456.onion", 8444, 1, 1);
    bm_peer_manager_record_result(db, "def456.onion", 8444, 1, 1);

    CHECK(bm_peer_manager_mark_self(db, "def456.onion", 8444, 1) == 0,
          "mark_self (existing learned row) should succeed");
    {
        struct bm_peer_entry results[16];
        int count = 0;
        bm_peer_manager_list_top(db, 1, results, 16, &count);
        CHECK(!has_ip_port(results, count, "def456.onion", 8444),
              "after mark_self, a previously-learned peer should be excluded from list_top");
    }
    /* rating履歴が保持されていることを、直接SQLで確認する(list_topはis_self行を
     * そもそも返さないため、is_self=1のまま値を見るには生クエリが必要) */
    {
        sqlite3_stmt *stmt = NULL;
        sqlite3_prepare_v2(db, "SELECT rating, source, is_self FROM hosts WHERE ip_address = ? AND port = ?;",
                            -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, "def456.onion", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, 8444);
        CHECK(sqlite3_step(stmt) == SQLITE_ROW, "the marked row should still exist");
        double rating = sqlite3_column_double(stmt, 0);
        const unsigned char *source = sqlite3_column_text(stmt, 1);
        int is_self = sqlite3_column_int(stmt, 2);
        CHECK(rating > 0.5 - 1e-9 && rating < 0.5 + 1e-9,
              "rating accumulated before mark_self should be preserved (0.5)");
        CHECK(source != NULL && strcmp((const char *)source, "onionpeer_obj") == 0,
              "source accumulated before mark_self should be preserved");
        CHECK(is_self == 1, "is_self should now be 1");
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    unlink(TEST_DB);

    /* --- 3. is_self列を持たない"古い"DBに対するマイグレーション --- */
    unlink(TEST_DB);
    sqlite3 *old_db = NULL;
    sqlite3_open(TEST_DB, &old_db);
    /* is_self列が無い、旧スキーマそのもの(CREATE TABLE IF NOT EXISTSで作られる現行の
     * SCHEMA_SQLとは別に、意図的にis_self列を持たない版を手で作る) */
    sqlite3_exec(old_db,
                 "CREATE TABLE hosts ("
                 "ip_address TEXT NOT NULL, port INTEGER NOT NULL, stream INTEGER NOT NULL DEFAULT 1, "
                 "services INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL, "
                 "rating REAL NOT NULL DEFAULT 0.0, source TEXT NOT NULL DEFAULT 'unknown', "
                 "PRIMARY KEY (ip_address, port, stream));",
                 NULL, NULL, NULL);
    struct bm_peer_entry pre_migration_entry;
    memset(&pre_migration_entry, 0, sizeof(pre_migration_entry));
    strncpy(pre_migration_entry.ip_address, "old.example", sizeof(pre_migration_entry.ip_address) - 1);
    pre_migration_entry.port = 8444;
    pre_migration_entry.stream = 1;
    pre_migration_entry.rating = 0.3;
    strncpy(pre_migration_entry.source, "seed", sizeof(pre_migration_entry.source) - 1);
    CHECK(bm_peer_manager_upsert(old_db, &pre_migration_entry) == 0,
          "seeding a row into the pre-migration (no is_self column) schema should succeed");

    CHECK(bm_peer_manager_init_schema(old_db) == 0,
          "init_schema should succeed (migrate) even against a pre-existing DB without is_self");
    CHECK(bm_peer_manager_mark_self(old_db, "self.example", 8444, 1) == 0,
          "mark_self should work after migration");
    {
        struct bm_peer_entry results[16];
        int count = 0;
        CHECK(bm_peer_manager_list_top(old_db, 1, results, 16, &count) == 0,
              "list_top (with is_self filter) should work after migration");
        CHECK(has_ip_port(results, count, "old.example", 8444),
              "pre-existing row from before migration should survive and still be listed");
        CHECK(!has_ip_port(results, count, "self.example", 8444),
              "the newly self-marked row should be excluded after migration");
    }

    sqlite3_close(old_db);
    unlink(TEST_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
