/*
 * §11 2026-08-23: backlog項目2、inbound接続のレート制限(DoS対策)のテスト。
 * Tor hidden service経由のinboundはaccept()で見える接続元IPが常にTorのローカル転送
 * (127.0.0.1:<ephemeral>)になり、生IPベースの制限は機能しないため、IPに依存しない
 * 2種類の制限(同時接続数上限/単位時間あたりaccept数上限)を実装した。
 *
 * - シナリオ1: bm_inbound_rate_limiter_allowの窓カウンタ単体の挙動
 *   (BM_INBOUND_ACCEPT_MAX_PER_WINDOW件までは許可、それを超えると拒否、
 *   BM_INBOUND_ACCEPT_WINDOW_SECONDS経過後に窓がリセットされ再度許可されること)。
 * - シナリオ2: bm_network_handle_acceptが同時接続数上限を実際に守ること。
 *   registryへBM_MAX_INBOUND_CONNECTIONS本ぶんの合成接続(socketpair)を直接
 *   bm_peer_registry_addで事前投入し(実際に66本ものTCP接続をqueueさせるとlisten backlogを
 *   超えてconnect()がSYNリトライでブロックしてしまうため、この方式は避ける)、その状態で
 *   実クライアントを1本だけ接続してbm_network_handle_acceptを呼び、
 *   registryへは追加登録されず即座にcloseされる(クライアント側でEOFが読める)ことを確認する。
 * - シナリオ3: bm_network_handle_acceptが単位時間あたりaccept数の上限を実際に守ること。
 *   registryは使わない(args.registry=NULLで同時接続数チェックを迂回)。
 *   bm_inbound_rate_limiter_allowを直接BM_INBOUND_ACCEPT_MAX_PER_WINDOW回呼んで窓を
 *   使い切った状態を作った上で、実クライアントを1本だけ接続してbm_network_handle_acceptを
 *   呼び、同様に即座にcloseされることを確認する。
 *
 * いずれもtest_idle_sweep.c/test_inbound.cと同じく、epollスレッド自体(無限ループ)は
 * 起動せず直接関数呼び出しで決定的にテストする。
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/infra/network.h"
#include "../src/infra/peer_registry.h"

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

static void close_and_free_conn(struct bm_fd_data *conn, void *user_data)
{
    (void)user_data;
    close(conn->fd);
    bm_fd_data_free(conn);
}

/* listen_fd:listen_portへ実TCP接続し、接続確認できたクライアント側fdを返す */
static int connect_one_client(int listen_port)
{
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)listen_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    CHECK(connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "client connect should succeed");
    return cfd;
}

/* client_fdがサーバー側から即座にcloseされた(EOFが読める)ことを確認する */
static void check_immediately_closed(int client_fd, const char *msg)
{
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
    unsigned char buf[8];
    ssize_t n = read(client_fd, buf, sizeof(buf));
    CHECK(n == 0, msg);
    close(client_fd);
}

int main(void)
{
    /* --- 1. bm_inbound_rate_limiter_allow単体: 窓内の上限とリセット --- */
    {
        struct bm_inbound_rate_limiter rl;
        bm_inbound_rate_limiter_init(&rl);

        int64_t t0 = (int64_t)1893456000;
        int allowed = 0;
        for (int i = 0; i < BM_INBOUND_ACCEPT_MAX_PER_WINDOW; i++)
        {
            if (bm_inbound_rate_limiter_allow(&rl, t0))
            {
                allowed++;
            }
        }
        CHECK(allowed == BM_INBOUND_ACCEPT_MAX_PER_WINDOW,
              "exactly BM_INBOUND_ACCEPT_MAX_PER_WINDOW accepts should be allowed within one window");

        CHECK(bm_inbound_rate_limiter_allow(&rl, t0) == 0,
              "the (max+1)th accept within the same window should be rejected");
        CHECK(bm_inbound_rate_limiter_allow(&rl, t0 + BM_INBOUND_ACCEPT_WINDOW_SECONDS - 1) == 0,
              "still within the same window (one second before the boundary) should still be rejected");

        CHECK(bm_inbound_rate_limiter_allow(&rl, t0 + BM_INBOUND_ACCEPT_WINDOW_SECONDS) == 1,
              "a new window (BM_INBOUND_ACCEPT_WINDOW_SECONDS later) should reset the counter and allow again");
    }

    /* 以降のシナリオで共通して使う、実listenソケット */
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(listen_fd >= 0, "bm_network_listen should succeed on 127.0.0.1:0");
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len);
    int listen_port = ntohs(listen_addr.sin_port);
    struct bm_fd_data *listener = bm_fd_data_new(BM_FD_LISTEN_SOCKET, listen_fd);
    CHECK(listener != NULL, "bm_fd_data_new for the listener should succeed");

    /* --- 2. bm_network_handle_accept: 同時接続数上限を超える分は即座にcloseされる --- */
    {
        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);

        /* registryをBM_MAX_INBOUND_CONNECTIONS本の合成inbound接続(socketpair)で
         * 満たしておく(実際に大量のTCP接続をqueueさせずに「既に上限に達している」状態を
         * 決定的に再現するため) */
        int(*pairs)[2] = malloc(sizeof(int[2]) * (size_t)BM_MAX_INBOUND_CONNECTIONS);
        for (int i = 0; i < BM_MAX_INBOUND_CONNECTIONS; i++)
        {
            socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]);
            struct bm_fd_data *conn = bm_fd_data_new(BM_FD_SERVER_SOCKET, pairs[i][0]);
            bm_peer_registry_add(&registry, conn);
        }
        CHECK(bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET) == (size_t)BM_MAX_INBOUND_CONNECTIONS,
              "setup: registry should be pre-filled to BM_MAX_INBOUND_CONNECTIONS");

        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = -1; /* この経路ではepoll_ctlは呼ばれないので未使用でよい */
        args.registry = &registry;
        args.peers_db = NULL;
        bm_inbound_rate_limiter_init(&args.inbound_rate_limiter);

        int client_fd = connect_one_client(listen_port);
        bm_network_handle_accept(&args, listener, (int64_t)1893456000);

        CHECK(bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET) == (size_t)BM_MAX_INBOUND_CONNECTIONS,
              "an accept beyond BM_MAX_INBOUND_CONNECTIONS should not grow the registry");
        check_immediately_closed(client_fd,
                                  "the over-the-concurrent-limit client should see an immediate EOF (server closed)");

        bm_peer_registry_for_each(&registry, close_and_free_conn, NULL);
        for (int i = 0; i < BM_MAX_INBOUND_CONNECTIONS; i++)
        {
            close(pairs[i][1]);
        }
        free(pairs);
        bm_peer_registry_destroy(&registry);
    }

    /* --- 3. bm_network_handle_accept: 単位時間あたりaccept数の上限を超える分は
     * (同時接続数に余裕があっても)即座にcloseされる --- */
    {
        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = -1;
        args.registry = NULL; /* 同時接続数チェックを迂回し、レート制限だけを検証する */
        args.peers_db = NULL;
        bm_inbound_rate_limiter_init(&args.inbound_rate_limiter);

        int64_t t0 = (int64_t)1893456000;
        for (int i = 0; i < BM_INBOUND_ACCEPT_MAX_PER_WINDOW; i++)
        {
            CHECK(bm_inbound_rate_limiter_allow(&args.inbound_rate_limiter, t0) == 1,
                  "setup: exhausting the accept-rate window should succeed for each of the first N calls");
        }

        int client_fd = connect_one_client(listen_port);
        bm_network_handle_accept(&args, listener, t0);

        check_immediately_closed(client_fd,
                                  "the over-the-accept-rate-limit client should see an immediate EOF (server closed)");
    }

    bm_fd_data_free(listener);
    close(listen_fd);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
