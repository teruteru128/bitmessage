/*
 * §11 2026-08-23: inbound接続のアイドル/ハンドシェイクタイムアウト+keepalive ping送信
 * (PyBitmessage本家network/connectionpool.pyのメインループ移植)のテスト。
 * bm_network_idle_sweepがnowを明示引数に取ることを活かし、実際の壁時計待ちをせず
 * 決定的に検証する(tests/test_object_sync.c等と同じ実socketpair直接呼び出し方針)。
 *
 * - シナリオ1: handshake_complete=0の接続は、BM_HANDSHAKE_TIMEOUT_SECONDSを超えて
 *   無活動なら切断される(registryから消える・fdがcloseされる)。境界未満ではまだ
 *   切断されないことも確認する。
 * - シナリオ2: handshake_complete=1(fully established)の接続は、
 *   BM_IDLE_PING_TIMEOUT_SECONDSを超えて無活動ならpingパケットが送信されるが、
 *   切断はされない。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/infra/network.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"

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

static struct bm_fd_data *make_test_conn(int epfd, int *out_local_fd, int *out_remote_fd)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    {
        return NULL;
    }
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
    if (conn == NULL)
    {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    int flags = fcntl(fds[0], F_GETFL, 0);
    fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = conn;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fds[0], &ev);

    *out_local_fd = fds[0];
    *out_remote_fd = fds[1];
    return conn;
}

int main(void)
{
    /* --- 1. ハンドシェイク未完了の接続は、タイムアウトを超えて無活動なら切断される --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed");

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);

        int local_fd, remote_fd;
        struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
        CHECK(conn != NULL, "make_test_conn should succeed");
        bm_peer_registry_add(&registry, conn);
        CHECK(conn->handshake_complete == 0, "a fresh connection should not be handshake_complete yet");

        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;

        int64_t t0 = (int64_t)1893456000; /* 適当な固定基準時刻(壁時計に依存しないテストのため) */
        conn->last_activity = t0;

        /* 境界未満(タイムアウトぴったりの時点)ではまだ切断されない */
        bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS);
        CHECK(bm_peer_registry_count(&registry) == 1,
              "a not-yet-timed-out handshake-incomplete connection should not be closed");

        /* 境界を超えたら切断される */
        bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + 1);
        CHECK(bm_peer_registry_count(&registry) == 0,
              "a handshake-incomplete connection idle beyond BM_HANDSHAKE_TIMEOUT_SECONDS should be closed");

        /* closeされたfdへの書き込みはEBADF/EPIPEになるはず(fdが実際にcloseされたことの確認) */
        ssize_t n = write(local_fd, "x", 1);
        CHECK(n < 0 && errno == EBADF, "the local fd should have been closed by the idle sweep");

        close(remote_fd);
        bm_peer_registry_destroy(&registry);
        close(epfd);
    }

    /* --- 2. fully establishedな接続は、アイドルタイムアウトを超えてもpingが送られるだけで
     * 切断はされない --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed");

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);

        int local_fd, remote_fd;
        struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
        CHECK(conn != NULL, "make_test_conn should succeed");
        bm_peer_registry_add(&registry, conn);
        conn->handshake_complete = 1;

        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;

        int64_t t0 = (int64_t)1893456000;
        conn->last_activity = t0;

        bm_network_idle_sweep(&args, t0 + BM_IDLE_PING_TIMEOUT_SECONDS + 1);
        CHECK(bm_peer_registry_count(&registry) == 1,
              "a fully-established idle connection should NOT be closed, only pinged");

        unsigned char buf[64];
        ssize_t n = read(remote_fd, buf, sizeof(buf));
        CHECK(n > 0, "a ping packet should have been sent to the peer");
        if (n > 0)
        {
            struct bm_message *msg = NULL;
            size_t consumed = 0;
            CHECK(bm_parse_message(buf, (size_t)n, &msg, &consumed) == BM_PARSE_OK,
                  "the sent packet should parse as a valid message");
            if (msg != NULL)
            {
                CHECK(strncmp(msg->command, "ping", 12) == 0, "the sent packet's command should be 'ping'");
                bm_free_message(msg);
            }
        }

        /* pingを送った直後にlast_activityが更新されているはず(spam防止の確認) */
        CHECK(conn->last_activity > t0, "last_activity should be updated right after sending the ping");

        /* close_connectionを経由していない(切断されていない)ため、bm_fd_data自体は
         * このテストが明示的にfreeする(registryは借用ポインタしか持たない) */
        bm_peer_registry_remove(&registry, conn);
        bm_fd_data_free(conn);
        close(local_fd);
        close(remote_fd);
        bm_peer_registry_destroy(&registry);
        close(epfd);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
