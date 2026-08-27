/*
 * §11 2026-08-27発覚のバグの回帰テスト。bm_peer_connector_connect_initialが
 * outbound接続数の空き枠判定にbm_peer_registry_count(inbound/outbound合算)を
 * 使っていたため、inbound接続が生きている環境ではoutbound接続数がmax_outbound未満でも
 * 「already_connected(合算) >= max_outbound」が真になり、新規outbound接続を一切
 * 試みなくなっていた(list-connectionsのoutbound数がmax未満で頭打ちになり進まなくなる
 * 不具合として、実daemonのsyslog調査から発覚)。
 *
 * registryにinbound(BM_FD_SERVER_SOCKET)接続を1件だけ登録し、max_outbound=1の状態で
 * connect_initialを呼ぶ。修正前はoutbound数0でもinbound込みの合算(1)がmax_outbound(1)
 * 以上のため候補に一切触れない(rating不変)。修正後はoutbound数0<max_outbound(1)なので
 * 候補への接続を試みる(未listenポートなので失敗するが、rating/last_attemptが更新される
 * ことで「試行された」ことを確認できる)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/peer_connector.h"
#include "../src/infra/peer_registry.h"

#define TEST_PEERS_DB "test_peer_connector_inbound_headroom_peers.db"
#define TEST_CANDIDATE_PORT 18451

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

    /* 127.0.0.1の未listenポートへ向ける候補を1件登録する(接続は必ず失敗する) */
    struct bm_peer_entry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.ip_address, "127.0.0.1", sizeof(entry.ip_address) - 1);
    entry.port = TEST_CANDIDATE_PORT;
    entry.stream = 1;
    entry.services = 1;
    entry.last_seen = (int64_t)time(NULL);
    entry.rating = 0.5;
    strncpy(entry.source, "test", sizeof(entry.source) - 1);
    CHECK(bm_peer_manager_upsert(peers_db, &entry) == 0, "seed candidate row");

    /* registryにinbound接続を1件だけ登録する。fd=-1のダミー(実socketは使わない、
     * has_peer/count_by_typeはtype/logical_peer_ip/peer_addrしか見ないため安全)。 */
    struct bm_peer_registry reg;
    bm_peer_registry_init(&reg);
    struct bm_fd_data inbound_conn;
    memset(&inbound_conn, 0, sizeof(inbound_conn));
    inbound_conn.type = BM_FD_SERVER_SOCKET;
    inbound_conn.fd = -1;
    bm_peer_registry_add(&reg, &inbound_conn);

    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1 should succeed");

    struct bm_peer_connector_config config;
    memset(&config, 0, sizeof(config));
    config.epfd = epfd;
    config.peers_db = peers_db;
    config.testnet = 0;
    config.max_outbound = 1; /* outbound枠は1つ空いているはず(inbound1件はoutbound枠を消費しない) */
    config.user_agent = "/test:0.0.0/";
    config.registry = &reg;
    config.config_db = NULL;
    config.stop_flag = NULL;
    config.observed_nodes_path = "seeds/observed_nodes.txt";

    bm_peer_connector_connect_initial(&config);

    struct bm_peer_entry results[8];
    int out_count = 0;
    CHECK(bm_peer_manager_list_top(peers_db, 1, results, 8, &out_count) == 0, "list_top should succeed");
    int found = 0;
    for (int j = 0; j < out_count; j++)
    {
        if (results[j].port == TEST_CANDIDATE_PORT)
        {
            found = 1;
            /* 接続が試行され失敗したのでratingが減点されているはず。もしバグが残っていれば
             * (inbound1件込みの合算がmax_outbound(1)以上と誤判定され)候補に一切触れず
             * rating==0.5のまま変化しない */
            CHECK(results[j].rating < 0.5,
                  "candidate should have been attempted (rating penalized) even with 1 inbound "
                  "connection already registered, since the outbound slot itself was still free");
        }
    }
    CHECK(found, "seeded candidate should still be present in peers.db");

    bm_peer_registry_remove(&reg, &inbound_conn);
    bm_peer_registry_destroy(&reg);
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
