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
 * - シナリオ3(§11 2026-08-26追加): bm_network_begin_big_invによるbig invの
 *   チャンク分割+ペーシング。一度に大量のinvを無間隔で送りつけると相手のTCP受信
 *   ウィンドウが枯渇し強制切断されることが実測で判明した(DESIGN-LOG.md参照)ため、
 *   BM_BIG_INV_CHUNK_SIZE件ごとに分割しBM_BIG_INV_CHUNK_INTERVAL_SECONDS間隔でのみ
 *   次のチャンクをbm_network_idle_sweep経由で送るようにした。ここではその境界値
 *   (間隔未経過では追加送信されない・経過後は次のchunkが送られる・最後の半端な件数の
 *   chunkも正しく送られてpending状態がクリアされる)を検証する。
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

/*
 * §11 2026-08-26: fdがノンブロッキングであることを前提に、既に届いているデータだけで
 * 1メッセージ分をパースできればそれを返し、データが無ければ(EAGAIN)即座にNULLを返す
 * (tests/test_object_sync.cのread_one_messageと違いブロックして待たない、
 * 「まだ何も送られていないこと」を確認するシナリオ3向け)。
 */
static struct bm_message *try_read_one_message(int fd)
{
    static unsigned char buf[65536];
    size_t total = 0;
    for (;;)
    {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total);
        if (n <= 0)
        {
            return NULL;
        }
        total += (size_t)n;

        struct bm_message *msg = NULL;
        size_t consumed = 0;
        if (bm_parse_message(buf, total, &msg, &consumed) == BM_PARSE_OK)
        {
            return msg;
        }
    }
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

    /* --- 3. §11 2026-08-26: big invのチャンク分割+ペーシング(bm_network_begin_big_inv) --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed (scenario 3)");

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);

        int local_fd, remote_fd;
        struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
        CHECK(conn != NULL, "make_test_conn should succeed (scenario 3)");
        bm_peer_registry_add(&registry, conn);
        conn->handshake_complete = 1;

        /* remote_fdもノンブロッキングにする(まだ送られていないことを確認するため、
         * ブロッキングのままだと来るまで永久に待ってしまう) */
        int rflags = fcntl(remote_fd, F_GETFL, 0);
        fcntl(remote_fd, F_SETFL, rflags | O_NONBLOCK);

        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;

        /* chunk境界をまたぐ半端な件数(1000+1000+500) */
        const size_t total = (size_t)BM_BIG_INV_CHUNK_SIZE * 2 + 500;
        int64_t t0 = (int64_t)1893456000;
        /* §11 2026-08-26発覚(テスト作成時): last_activityをt0近辺に合わせておかないと、
         * bm_fd_data_new時点の実際の現在時刻のまま放置され、t0(壁時計と無関係な未来の
         * 固定値)との差がBM_IDLE_PING_TIMEOUT_SECONDSを超えてidle_sweepがpingパケットを
         * 送ってしまい、「間隔未経過では何も届かない」という検証がpingパケットの混入で
         * 偽陽性(FAIL)になっていた。 */
        conn->last_activity = t0;
        unsigned char(*hashes)[32] = malloc(sizeof(*hashes) * total);
        CHECK(hashes != NULL, "malloc test hashes should succeed");
        for (size_t i = 0; i < total; i++)
        {
            memset(hashes[i], 0, 32);
            hashes[i][0] = (unsigned char)(i & 0xFF);
            hashes[i][1] = (unsigned char)((i >> 8) & 0xFF);
        }

        bm_network_begin_big_inv(conn, hashes, total, t0);

        /* 1回目: 呼び出し直後にBM_BIG_INV_CHUNK_SIZE件だけ即座に送られているはず */
        struct bm_message *msg1 = try_read_one_message(remote_fd);
        CHECK(msg1 != NULL, "the first inv chunk should have been sent immediately");
        if (msg1 != NULL)
        {
            CHECK(strncmp(msg1->command, "inv", 12) == 0, "the first chunk's command should be 'inv'");
            struct bm_inventory_message inv1;
            memset(&inv1, 0, sizeof(inv1));
            CHECK(bm_parse_inventory_message(msg1->payload, msg1->length, &inv1) == 0,
                  "the first chunk's inv payload should parse");
            CHECK(inv1.count == BM_BIG_INV_CHUNK_SIZE,
                  "the first chunk should contain exactly BM_BIG_INV_CHUNK_SIZE items");
            bm_free_inventory_message(&inv1);
            bm_free_message(msg1);
        }
        CHECK(conn->pending_inv_hashes != NULL, "pending inv should remain after the first chunk");
        CHECK(conn->pending_inv_sent == (size_t)BM_BIG_INV_CHUNK_SIZE,
              "pending_inv_sent should equal the first chunk size");

        /* 間隔未経過では追加送信されない */
        bm_network_idle_sweep(&args, t0 + BM_BIG_INV_CHUNK_INTERVAL_SECONDS - 1);
        struct bm_message *msg_none = try_read_one_message(remote_fd);
        CHECK(msg_none == NULL, "no more data should arrive before the pacing interval elapses");

        /* 間隔経過後: 2回目のchunk(またBM_BIG_INV_CHUNK_SIZE件) */
        bm_network_idle_sweep(&args, t0 + BM_BIG_INV_CHUNK_INTERVAL_SECONDS);
        struct bm_message *msg2 = try_read_one_message(remote_fd);
        CHECK(msg2 != NULL, "the second inv chunk should have been sent after the pacing interval");
        if (msg2 != NULL)
        {
            struct bm_inventory_message inv2;
            memset(&inv2, 0, sizeof(inv2));
            CHECK(bm_parse_inventory_message(msg2->payload, msg2->length, &inv2) == 0,
                  "the second chunk's inv payload should parse");
            CHECK(inv2.count == BM_BIG_INV_CHUNK_SIZE, "the second chunk should also contain BM_BIG_INV_CHUNK_SIZE items");
            bm_free_inventory_message(&inv2);
            bm_free_message(msg2);
        }
        CHECK(conn->pending_inv_hashes != NULL, "pending inv should still remain after the second chunk (500 left)");
        CHECK(conn->pending_inv_sent == (size_t)BM_BIG_INV_CHUNK_SIZE * 2,
              "pending_inv_sent should equal 2 chunks");

        /* 3回目: 残り500件(半端な最終chunk)が送られ、pendingがクリアされる */
        bm_network_idle_sweep(&args, t0 + BM_BIG_INV_CHUNK_INTERVAL_SECONDS * 2);
        struct bm_message *msg3 = try_read_one_message(remote_fd);
        CHECK(msg3 != NULL, "the third (final, partial) inv chunk should have been sent");
        if (msg3 != NULL)
        {
            struct bm_inventory_message inv3;
            memset(&inv3, 0, sizeof(inv3));
            CHECK(bm_parse_inventory_message(msg3->payload, msg3->length, &inv3) == 0,
                  "the third chunk's inv payload should parse");
            CHECK(inv3.count == 500, "the final chunk should contain exactly the remaining 500 items");
            bm_free_inventory_message(&inv3);
            bm_free_message(msg3);
        }
        CHECK(conn->pending_inv_hashes == NULL, "pending inv should be cleared once everything has been sent");

        /* 送り終えた後にidle_sweepを呼んでも何も追加送信されない */
        bm_network_idle_sweep(&args, t0 + BM_BIG_INV_CHUNK_INTERVAL_SECONDS * 10);
        struct bm_message *msg_extra = try_read_one_message(remote_fd);
        CHECK(msg_extra == NULL, "nothing more should be sent once the pending inv is exhausted");

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
