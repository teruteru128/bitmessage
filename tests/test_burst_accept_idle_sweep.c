/*
 * §11 2026-09-05: 本番daemon(daemon A)のjournalctlログ調査(「[peer_registry] failed to
 * send inv to fd=N(write: Broken pipe)」頻発)で見つかったバグの再現テスト。
 *
 * 実際の本番ログを時系列で洗い直したところ、residualなinbound接続8本は「じわじわ」では
 * なく、9/4 22:50:29の1秒の間にまとめて(fd=24,29,30,31,32,33,34,35として)acceptされて
 * いたことが判明した。bm_network_handle_accept(network.c)はEAGAINになるまで一気に
 * 溜まっている接続を全部accept()するループのため、多数のpeerがほぼ同時にTCP接続してくる
 * (Tor hidden service経由でキューされていたstreamが一括で流れ込む等)と、1回の呼び出しで
 * 複数のconnが一括で登録される。この「バーストaccept」状況が、その後のidle_sweepによる
 * ハンドシェイクタイムアウト刈り取りに何らかの悪影響を与えていないかを検証する。
 *
 * - シナリオ1: バーストでaccept()させた直後、クライアント側は一切データを送らず即座に
 *   close()する(「接続だけして即座に消えるpeer」)。ハンドシェイクタイムアウト後、
 *   全数が例外なく刈り取られることを確認する。
 * - シナリオ2: 本番のss調査で見つかった実際の状態(CLOSE-WAIT、Recv-Q=130の未読データ)に
 *   より近い状況。クライアントが少量(130バイト、bitmessageプロトコルとしては不正な
 *   magic/フォーマットの生データ)を送ってから消える。bm_network_handle_readableが
 *   このデータを実際に読み取り処理した後の状態で、なおハンドシェイクタイムアウトが
 *   正しく機能するかを確認する。
 *
 * いずれかのシナリオで1本でも刈り取られずに残れば、それがバグの再現ということになる。
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

/* §11 2026-09-05: 実際に本番で観測したバースト本数(9/4 22:50:29に同時accept()された
 * inbound接続数)に合わせる。bm_network_listenのlisten backlogは16(network.c)なので、
 * これを超える本数を無防備にblocking connect()すると、backlogを超えた分のSYNが
 * カーネル側で溜まり(またはdropされ再送待ちになり)connect()自体が長時間ブロックして
 * テストがハングする(実際に32本で試して120秒タイムアウトになることを確認した)。backlog以下に
 * 抑えることで、この「テスト側のTCPレベルの詰まり」と「調べたいidle_sweepの挙動」を
 * 混同しないようにする。 */
#define BURST_SIZE 8

static void close_and_free_conn(struct bm_fd_data *conn, void *user_data)
{
    (void)user_data;
    close(conn->fd);
    bm_fd_data_free(conn);
}

struct collect_ctx
{
    struct bm_fd_data **out;
    size_t count;
};

static void collect_conn(struct bm_fd_data *conn, void *user_data)
{
    struct collect_ctx *ctx = user_data;
    ctx->out[ctx->count++] = conn;
}

/* listen_fd:listen_port、bm_fd_data*(BM_FD_LISTEN_SOCKET)、epfdへの登録までまとめて行う */
static struct bm_fd_data *setup_listener(int *out_listen_fd, int *out_listen_port, int epfd)
{
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(listen_fd >= 0, "bm_network_listen should succeed on 127.0.0.1:0");
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len);

    struct bm_fd_data *listener = bm_fd_data_new(BM_FD_LISTEN_SOCKET, listen_fd);
    CHECK(listener != NULL, "bm_fd_data_new for the listener should succeed");
    struct epoll_event lev;
    lev.events = EPOLLIN;
    lev.data.ptr = listener;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev);

    *out_listen_fd = listen_fd;
    *out_listen_port = ntohs(listen_addr.sin_port);
    return listener;
}

/* BURST_SIZE本を同時にconnect()する(まだaccept()はしない、listen backlogに溜め込む) */
static void connect_burst(int listen_port, int client_fds[BURST_SIZE])
{
    for (int i = 0; i < BURST_SIZE; i++)
    {
        client_fds[i] = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(client_fds[i] >= 0, "client socket() should succeed");
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)listen_port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        CHECK(connect(client_fds[i], (struct sockaddr *)&addr, sizeof(addr)) == 0,
              "burst client connect() should succeed");
    }
}

int main(void)
{
    /* --- シナリオ1: 接続だけして即座に消えるpeerのバースト --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed (scenario 1)");
        int listen_fd, listen_port;
        struct bm_fd_data *listener = setup_listener(&listen_fd, &listen_port, epfd);

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);
        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;
        bm_inbound_rate_limiter_init(&args.inbound_rate_limiter);

        int client_fds[BURST_SIZE];
        connect_burst(listen_port, client_fds);

        int64_t t0 = (int64_t)1893456000;
        bm_network_handle_accept(&args, listener, t0);
        CHECK(bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET) == BURST_SIZE,
              "scenario 1: all burst connections should have been accepted and registered in one call");

        /* 「接続だけして即座に消えるpeer」を再現: クライアント側を全部close()する
         * (本番で観測した「fullyEstablished=false, 送受信0バイト」の接続と同じ状態)。 */
        for (int i = 0; i < BURST_SIZE; i++)
        {
            close(client_fds[i]);
        }

        /* ハンドシェイクタイムアウトを超えてidle_sweepを複数回呼ぶ(production同様
         * 1回のidle_sweepではMAX_EPOLL_EVENTS等の都合で一部しか処理されない可能性を潰す)。 */
        for (int round = 0; round < 5; round++)
        {
            bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + 1 + round);
        }

        size_t remaining = bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET);
        CHECK(remaining == 0,
              "scenario 1: every burst-accepted, handshake-incomplete (silent) connection should be reaped");
        if (remaining != 0)
        {
            fprintf(stderr, "REPRO(scenario1): %zu of %d burst connections were NOT reaped\n", remaining, BURST_SIZE);
        }

        bm_peer_registry_for_each(&registry, close_and_free_conn, NULL);
        bm_peer_registry_destroy(&registry);
        bm_fd_data_free(listener);
        close(listen_fd);
        close(epfd);
    }

    /* --- シナリオ2: 本番のss調査で見つかった実際の状態(CLOSE-WAIT、Recv-Q=130の未読
     * データ)に近い状況。クライアントがbitmessageプロトコルとしては不正な生データを
     * 130バイト送ってから消える。bm_network_handle_readableでこのデータを実際に
     * 読み取り処理させた後の状態で、なおハンドシェイクタイムアウトが機能するか確認する。 --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed (scenario 2)");
        int listen_fd, listen_port;
        struct bm_fd_data *listener = setup_listener(&listen_fd, &listen_port, epfd);

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);
        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;
        bm_inbound_rate_limiter_init(&args.inbound_rate_limiter);

        int client_fds[BURST_SIZE];
        connect_burst(listen_port, client_fds);

        int64_t t0 = (int64_t)1893456000;
        bm_network_handle_accept(&args, listener, t0);
        CHECK(bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET) == BURST_SIZE,
              "scenario 2: all burst connections should have been accepted and registered in one call");

        /* サーバー側のconnポインタをfdでも引けるように、accept順とclient_fds[]の対応を
         * 仮定せず、registryをスナップショットしてclient_fds[]との対応はfd値の一致で
         * 判定する必要はない(全接続に同じ処理をするだけなので対応関係自体は不要)。 */
        struct bm_fd_data *server_conns[BURST_SIZE];
        struct collect_ctx collect_ctx = {.out = server_conns, .count = 0};
        /* for_each_lockedはロックを持ったままcallbackを呼ぶため、connポインタを
         * そのままローカル配列へ保存しても(ロック区間内の読み取りである限り)安全。 */
        bm_peer_registry_for_each_locked(&registry, collect_conn, &collect_ctx);
        CHECK(collect_ctx.count == BURST_SIZE, "scenario 2: should have collected all server-side conns");

        /* 130バイトの不正データ(bitmessageのmagic bytesと一致しない生データ)を全クライアント
         * から送り、サーバー側にbm_network_handle_readableで実際に読み取り・resync処理させる。 */
        unsigned char garbage[130];
        memset(garbage, 0xAB, sizeof(garbage));
        for (int i = 0; i < BURST_SIZE; i++)
        {
            ssize_t n = write(client_fds[i], garbage, sizeof(garbage));
            CHECK(n == (ssize_t)sizeof(garbage), "scenario 2: writing garbage payload to client fd should succeed");
        }
        for (size_t i = 0; i < collect_ctx.count; i++)
        {
            int rc = bm_network_handle_readable(server_conns[i], NULL, NULL);
            CHECK(rc == 0, "scenario 2: reading garbage (bad magic, resynced away) should not itself close the conn");
            CHECK(server_conns[i]->handshake_complete == 0,
                  "scenario 2: garbage payload alone must not complete the handshake");
        }

        /* 本番で観測した状態を再現: クライアント側を全部close()する(相手が消える) */
        for (int i = 0; i < BURST_SIZE; i++)
        {
            close(client_fds[i]);
        }

        /* garbage読み取り時にlast_activityが更新されているため、そこを起点に
         * ハンドシェイクタイムアウトを超えるところまで進める。 */
        for (int round = 0; round < 5; round++)
        {
            bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + 1 + round);
        }

        size_t remaining = bm_peer_registry_count_by_type(&registry, BM_FD_SERVER_SOCKET);
        CHECK(remaining == 0,
              "scenario 2: every burst-accepted connection that received garbage-then-disappeared should be reaped");
        if (remaining != 0)
        {
            fprintf(stderr, "REPRO(scenario2): %zu of %d burst connections were NOT reaped\n", remaining, BURST_SIZE);
        }

        bm_peer_registry_for_each(&registry, close_and_free_conn, NULL);
        bm_peer_registry_destroy(&registry);
        bm_fd_data_free(listener);
        close(listen_fd);
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
