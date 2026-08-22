/*
 * §11 2026-08-22発覚のバグ修正のテスト。
 *
 * 実際のbootstrap daemonのログで、特定の1peerへの接続が9700行超のログ中3474回にわたって
 * 繰り返されていることが見つかった。原因はpeer_connector.cがconnect()+version送信の成功時点で
 * rating+0.1を記録するが、その直後にECONNRESET等で切断されてもそれをratingへフィードバック
 * する経路が無かったこと。「TCP接続とversion送信はできるが直後に切断される」peerのrating
 * だけが下がらないまま毎回の再接続サイクルで最上位候補に選ばれ続けてしまっていた。
 *
 * bm_network_epoll_threadの実スレッドを起動し、実TCP接続(BM_FD_CLIENT_SOCKET、outbound
 * 接続を模す)がpeer切断(EOF)で終了した際に、peers.dbの該当行のratingが実際に-0.1
 * されることを確認する(tests/test_inbound.cと同じ「実ソケット+実スレッドで決定的に
 * 検証する」方針)。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/network.h"

#define TEST_PEERS_DB "test_peer_rating_peers.db"

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
    if (sqlite3_open(TEST_PEERS_DB, &peers_db) != SQLITE_OK || bm_peer_manager_init_schema(peers_db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", TEST_PEERS_DB);
        return EXIT_FAILURE;
    }

    /* --- 1. "偽peer"役のリスナーを立てる(以後こちらからconnect()し、切断を模す側) --- */
    int fake_peer_listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(fake_peer_listen_fd >= 0, "bm_network_listen should succeed for the fake-peer listener");
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    getsockname(fake_peer_listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len);
    int fake_peer_port = ntohs(listen_addr.sin_port);

    /* --- 2. peers.dbへ、この"偽peer"のratingを0.5として先に登録しておく --- */
    struct bm_peer_entry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.ip_address, "127.0.0.1", sizeof(entry.ip_address) - 1);
    entry.port = fake_peer_port;
    entry.stream = 1;
    entry.rating = 0.5;
    strncpy(entry.source, "test", sizeof(entry.source) - 1);
    CHECK(bm_peer_manager_upsert(peers_db, &entry) == 0, "seeding the peers.db row should succeed");

    /* --- 3. こちらから"偽peer"へoutbound接続する(=peer_connector.cが接続した状況を模す。
     * BM_FD_CLIENT_SOCKETとして登録する) --- */
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client_fd >= 0, "create client socket");
    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = htons((uint16_t)fake_peer_port);
    inet_pton(AF_INET, "127.0.0.1", &connect_addr.sin_addr);
    CHECK(connect(client_fd, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) == 0,
          "outbound connect to the fake peer should succeed");

    int accepted_fd = accept(fake_peer_listen_fd, NULL, NULL);
    CHECK(accepted_fd >= 0, "fake peer should accept the connection");

    struct bm_fd_data *client_conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, client_fd);
    CHECK(client_conn != NULL, "bm_fd_data_new should succeed for the outbound client socket");

    /* --- 4. epollを組み立て、bm_network_epoll_threadを実際に起動する。peers_dbを渡すのが
     * 今回のバグ修正の要(渡さなければrating更新はスキップされる、network.h参照) --- */
    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1 should succeed");
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client_conn;
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) == 0, "epoll_ctl ADD should succeed");

    struct bm_epoll_thread_args *args = malloc(sizeof(*args));
    args->epfd = epfd;
    args->handler = NULL; /* default_dispatchでよい。versionを送らないのでhandlerには到達しない */
    args->user_data = NULL;
    args->registry = NULL;
    args->peers_db = peers_db;

    pthread_t epoll_thread;
    CHECK(pthread_create(&epoll_thread, NULL, bm_network_epoll_thread, args) == 0,
          "pthread_create for bm_network_epoll_thread should succeed");
    /* bm_network_epoll_threadはグレースフルシャットダウン機構を持たない(DESIGN.md既知の
     * 制約)ため、joinはせずプロセス終了時に道連れで終わらせる(main.cの既存方針と同じ) */

    /* --- 5. "偽peer"側が即座に接続を切断する(EOF)。これがbm_network_handle_readableに
     * rc=1("peer closed")を返させ、epollスレッド側のrc!=0分岐(切断処理)を発火させる --- */
    close(accepted_fd);
    close(fake_peer_listen_fd);

    /* epollスレッドが切断を検知しrating更新するまで少し待つ(ポーリング、最大2秒) */
    double final_rating = 0.5;
    int found = 0;
    for (int i = 0; i < 40; i++)
    {
        struct bm_peer_entry results[1];
        int count = 0;
        if (bm_peer_manager_list_top(peers_db, 1, results, 1, &count) == 0 && count == 1)
        {
            found = 1;
            final_rating = results[0].rating;
            if (final_rating < 0.5 - 1e-9)
            {
                break;
            }
        }
        struct timespec ts = {0, 50L * 1000L * 1000L}; /* 50ms */
        nanosleep(&ts, NULL);
    }

    CHECK(found, "the seeded peer row should still exist in peers.db");
    CHECK(final_rating < 0.5 - 1e-9,
          "rating should have decreased below 0.5 after the outbound connection was disconnected");
    CHECK(final_rating > 0.4 - 1e-9 && final_rating < 0.4 + 1e-9,
          "rating should have decreased by exactly 0.1 (0.5 -> 0.4)");

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
