/*
 * §11 2026-08-23発覚のバグの回帰テスト。bm_peer_connector_connect_initialの候補ループが
 * config->stop_flagを見ずに全候補を試し切ってしまい、実daemonのSIGTERM後の終了処理が
 * (候補数 × 最大25秒)かかっていた問題。config->stop_flagが既に非0なら、候補へは
 * 一切手を付けず(ratingも変更せず)即座に返ることを確認する。
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/peer_connector.h"

#define TEST_PEERS_DB "test_peer_connector_shutdown_peers.db"

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
    unlink(TEST_PEERS_DB);
    sqlite3 *peers_db = NULL;
    CHECK(sqlite3_open(TEST_PEERS_DB, &peers_db) == SQLITE_OK, "open peers.db");
    CHECK(bm_peer_manager_init_schema(peers_db) == 0, "init peers.db schema");

    /* 127.0.0.1の未listenポートへ向ける候補を3件登録する。stop_flagのチェックが正しく
     * 効いていれば、これらへは一切接続を試みない(=ratingが変化しない)はず。もしバグが
     * 残っていれば、実際に接続失敗としてratingが-0.1される */
    const int candidate_ports[3] = {18441, 18442, 18443};
    for (int i = 0; i < 3; i++)
    {
        struct bm_peer_entry entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.ip_address, "127.0.0.1", sizeof(entry.ip_address) - 1);
        entry.port = candidate_ports[i];
        entry.stream = 1;
        entry.services = 1;
        entry.last_seen = (int64_t)time(NULL);
        entry.rating = 0.5;
        strncpy(entry.source, "test", sizeof(entry.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &entry) == 0, "seed candidate row");
    }

    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1 should succeed");

    volatile sig_atomic_t stop_flag = 1; /* 既に停止指示が出ている状態を再現 */

    struct bm_peer_connector_config config;
    memset(&config, 0, sizeof(config));
    config.epfd = epfd;
    config.peers_db = peers_db;
    config.testnet = 0;
    config.max_outbound = 3;
    config.user_agent = "/test:0.0.0/";
    config.registry = NULL;
    config.config_db = NULL;
    config.stop_flag = &stop_flag;

    int connected = bm_peer_connector_connect_initial(&config);
    CHECK(connected == 0, "no connections should be attempted once stop_flag is already set");

    for (int i = 0; i < 3; i++)
    {
        struct bm_peer_entry results[8];
        int out_count = 0;
        CHECK(bm_peer_manager_list_top(peers_db, 1, results, 8, &out_count) == 0, "list_top should succeed");
        int found = 0;
        for (int j = 0; j < out_count; j++)
        {
            if (results[j].port == candidate_ports[i])
            {
                found = 1;
                CHECK(results[j].rating == 0.5,
                      "candidate rating should be untouched when stop_flag was already set before any "
                      "connection attempt");
            }
        }
        CHECK(found, "seeded candidate should still be present in peers.db");
    }

    close(epfd);
    sqlite3_close(peers_db);
    unlink(TEST_PEERS_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
