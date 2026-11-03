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
 * - シナリオ4(§11 2026-09-09追加): 本番daemon(daemon A)がdouble free or corruption (out)で
 *   SIGABRT死した事故の修正検証。bm_peer_registry_evict_if_current(network_epoll_thread
 *   以外のスレッドから呼ばれる)は、以前はgeneration一致時にその場でclose・
 *   bm_fd_data_freeまで行っていたが、これがnetwork_epoll_thread側の同時処理と競合し
 *   二重free/二重closeを引き起こしていた。修正後はconn->pending_evictionフラグを
 *   立てるだけにし、実際のclose_connectionはnetwork_epoll_thread単一スレッド内
 *   (bm_network_idle_sweep)に一元化した。ここではpending_evictionが立った接続が
 *   idle_sweep呼び出しで確実にclose_connectionされる(registryから消え、fdがcloseされる)
 *   ことを検証する(tests/test_peer_registry_evict.cはフラグが立つことまでを検証、
 *   本テストはそのフラグが実際に消費されることを検証、住み分け)。
 * - シナリオ5(§11 2026-10-15 項目53追加): ゴースト接続の見張り。handshake未完了の接続が
 *   タイムアウトから大きく遅れて(BM_HANDSHAKE_OVERDUE_MARGIN_SECONDS以上)切断されたときだけ、
 *   通常の切断ログとは別に"handshake timeout overdue"のWARNが出ること、余裕の範囲内の
 *   切断・handshake完了済みの接続では出ないこと、WARNに項目23で観測した症状(CLOSE_WAITのまま
 *   未読データが残る)がそのまま記録されることを、stderrを取り込んで確かめる。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

/* §11 2026-10-15 項目53: stderrへ出るログ(bm_log_warn等)を、dup2で一時ファイルへ向けて取り込む。
 * シナリオ5がWARNの有無と中身を確かめるために使う。 */
static int g_saved_stderr = -1;
static FILE *g_capture = NULL;

static void capture_stderr_begin(void)
{
    fflush(stderr);
    g_capture = tmpfile();
    g_saved_stderr = dup(STDERR_FILENO);
    dup2(fileno(g_capture), STDERR_FILENO);
}

/* 取り込んだ内容をbuf(NUL終端)へ入れ、stderrを元に戻す */
static void capture_stderr_end(char *buf, size_t buf_len)
{
    fflush(stderr);
    dup2(g_saved_stderr, STDERR_FILENO);
    close(g_saved_stderr);
    rewind(g_capture);
    size_t n = fread(buf, 1, buf_len - 1, g_capture);
    buf[n] = '\0';
    fclose(g_capture);
    g_capture = NULL;
}

/* 127.0.0.1上の本物のTCP接続を1組作る(server_fdはaccept側、client_fdは接続側)。
 * AF_UNIXのsocketpairではTCP_INFOが取れないため、WARNのtcp_state/unreadの記録は本物のTCPで確かめる。 */
static int make_tcp_pair(int *out_server_fd, int *out_client_fd)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len = sizeof(addr);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 1) != 0
        || getsockname(listener, (struct sockaddr *)&addr, &len) != 0)
    {
        if (listener >= 0)
        {
            close(listener);
        }
        return -1;
    }
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(listener);
        if (client >= 0)
        {
            close(client);
        }
        return -1;
    }
    int server = accept(listener, NULL, NULL);
    close(listener);
    if (server < 0)
    {
        close(client);
        return -1;
    }
    *out_server_fd = server;
    *out_client_fd = client;
    return 0;
}

/* fdのTCP状態がCLOSE_WAIT(8)になるまで最大約1秒待つ。ループバックでは相手のclose直後にほぼ即座に
 * なるが、カーネルの処理順に依存しないよう短くポーリングする(壁時計の待ちはこの1箇所だけ) */
static int wait_for_close_wait(int fd)
{
    for (int i = 0; i < 100; i++)
    {
        struct tcp_info info;
        socklen_t len = sizeof(info);
        memset(&info, 0, sizeof(info));
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0 && info.tcpi_state == 8)
        {
            return 1;
        }
        usleep(10 * 1000);
    }
    return 0;
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

    /* --- 4. §11 2026-09-09: pending_evictionが立った接続は、idle_sweepで確実に
     * close_connectionされる(double free事故の修正検証) --- */
    {
        int epfd = epoll_create1(0);
        CHECK(epfd >= 0, "epoll_create1 should succeed (scenario 4)");

        struct bm_peer_registry registry;
        bm_peer_registry_init(&registry);

        int local_fd, remote_fd;
        struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
        CHECK(conn != NULL, "make_test_conn should succeed (scenario 4)");
        bm_peer_registry_add(&registry, conn);
        conn->handshake_complete = 1; /* fully establishedでもpending_evictionが優先されることを確認 */

        struct bm_epoll_thread_args args;
        memset(&args, 0, sizeof(args));
        args.epfd = epfd;
        args.registry = &registry;
        args.peers_db = NULL;

        int64_t t0 = (int64_t)1893456000;
        conn->last_activity = t0; /* アイドル/ハンドシェイクタイムアウトの対象にはならない直近値 */

        /* bm_peer_registry_evict_if_currentが別スレッドから呼ばれた状況を模す:
         * generation一致でpending_evictionを立てる(この時点ではまだfree/closeされない)。 */
        int rc = bm_peer_registry_evict_if_current(&registry, conn, conn->generation);
        CHECK(rc == 1, "evict_if_current should mark a currently-registered connection");
        CHECK(bm_peer_registry_count(&registry) == 1,
              "evict_if_current alone must not remove the connection from the registry yet");

        /* idle_sweepがpending_evictionを見つけてclose_connectionする。last_activityが
         * 直近(t0)のままでも、アイドルタイムアウト判定より優先して切断されるはず。 */
        bm_network_idle_sweep(&args, t0);
        CHECK(bm_peer_registry_count(&registry) == 0,
              "a connection with pending_eviction set must be closed by the next idle sweep, "
              "even though it is not otherwise idle/handshake-timed-out");

        ssize_t n = write(local_fd, "x", 1);
        CHECK(n < 0 && errno == EBADF, "the local fd should have been closed by the idle sweep");

        close(remote_fd);
        bm_peer_registry_destroy(&registry);
        close(epfd);
    }

    /* --- 5. §11 2026-10-15 項目53: ゴースト接続の見張り。handshake未完了の接続が、タイムアウトから
     * BM_HANDSHAKE_OVERDUE_MARGIN_SECONDS以上遅れて切られたときだけ"handshake timeout overdue"のWARNが出る --- */
    {
        int64_t t0 = (int64_t)1893456000;
        char out[8192];

        /* (a) 余裕の範囲内(しきい値+余裕-1秒)で切断されるのは通常の動作。WARNは出ない */
        {
            int epfd = epoll_create1(0);
            struct bm_peer_registry registry;
            bm_peer_registry_init(&registry);
            int local_fd, remote_fd;
            struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
            CHECK(conn != NULL, "make_test_conn should succeed");
            bm_peer_registry_add(&registry, conn);
            conn->last_activity = t0;
            struct bm_epoll_thread_args args;
            memset(&args, 0, sizeof(args));
            args.epfd = epfd;
            args.registry = &registry;

            capture_stderr_begin();
            bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + BM_HANDSHAKE_OVERDUE_MARGIN_SECONDS - 1);
            capture_stderr_end(out, sizeof(out));
            CHECK(bm_peer_registry_count(&registry) == 0, "(a) the timed-out connection should be closed");
            CHECK(strstr(out, "handshake not completed within") != NULL,
                  "(a) the normal timeout WARN should still be logged");
            CHECK(strstr(out, "handshake timeout overdue") == NULL,
                  "(a) a close within the margin must NOT log the overdue WARN");

            close(remote_fd);
            bm_peer_registry_destroy(&registry);
            close(epfd);
        }

        /* (b) 余裕ちょうど(しきい値+余裕秒)以上遅れた切断では、状態つきのWARNが出る(境界を含む) */
        {
            int epfd = epoll_create1(0);
            struct bm_peer_registry registry;
            bm_peer_registry_init(&registry);
            int local_fd, remote_fd;
            struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
            CHECK(conn != NULL, "make_test_conn should succeed");
            bm_peer_registry_add(&registry, conn);
            conn->last_activity = t0;
            struct bm_epoll_thread_args args;
            memset(&args, 0, sizeof(args));
            args.epfd = epfd;
            args.registry = &registry;

            char fd_text[32];
            snprintf(fd_text, sizeof(fd_text), "fd=%d,", local_fd);
            capture_stderr_begin();
            bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + BM_HANDSHAKE_OVERDUE_MARGIN_SECONDS);
            capture_stderr_end(out, sizeof(out));
            CHECK(bm_peer_registry_count(&registry) == 0, "(b) the overdue connection should still be closed");
            CHECK(strstr(out, "handshake timeout overdue") != NULL,
                  "(b) a close at/after the margin must log the overdue WARN");
            CHECK(strstr(out, fd_text) != NULL, "(b) the overdue WARN should name the fd");
            CHECK(strstr(out, "5s past the 20s threshold") != NULL,
                  "(b) the overdue WARN should say how far past the threshold the idle time was");
            CHECK(strstr(out, "pending_eviction=0") != NULL, "(b) the overdue WARN should include pending_eviction");
            CHECK(strstr(out, "tcp_state=n/a") != NULL,
                  "(b) a non-TCP socket (socketpair) should be reported as tcp_state=n/a, not crash");
            CHECK(strstr(out, "handshake not completed within") != NULL,
                  "(b) the normal timeout WARN should still follow");

            close(remote_fd);
            bm_peer_registry_destroy(&registry);
            close(epfd);
        }

        /* (c) 項目23で観測した症状(相手は切断済みでCLOSE_WAIT、受信バッファに130バイト未読)が、
         * そのままWARNに記録される。本物のTCP接続で確かめる */
        {
            int epfd = epoll_create1(0);
            struct bm_peer_registry registry;
            bm_peer_registry_init(&registry);
            /* §11 2026-11-03: CHECKは失敗しても先へ進むので、make_tcp_pairが失敗すると未初期化の
             * fdでwrite/closeすることになる(RelWithDebInfoビルドの-Wmaybe-uninitializedで発覚、
             * -O0のDebugビルドでは警告が出ない)。-1で初期化し、失敗時は無効なfdとして扱わせる */
            int server_fd = -1;
            int client_fd = -1;
            CHECK(make_tcp_pair(&server_fd, &client_fd) == 0, "(c) a loopback TCP pair should be created");
            struct bm_fd_data *conn = bm_fd_data_new(BM_FD_SERVER_SOCKET, server_fd);
            CHECK(conn != NULL, "(c) bm_fd_data_new should succeed");
            bm_peer_registry_add(&registry, conn);
            conn->last_activity = t0;
            struct bm_epoll_thread_args args;
            memset(&args, 0, sizeof(args));
            args.epfd = epfd;
            args.registry = &registry;

            unsigned char junk[130];
            memset(junk, 0xab, sizeof(junk));
            CHECK(write(client_fd, junk, sizeof(junk)) == (ssize_t)sizeof(junk), "(c) the peer sends 130 bytes");
            close(client_fd);
            CHECK(wait_for_close_wait(server_fd), "(c) the accepted socket should reach CLOSE_WAIT");

            capture_stderr_begin();
            bm_network_idle_sweep(&args, t0 + BM_HANDSHAKE_TIMEOUT_SECONDS + BM_HANDSHAKE_OVERDUE_MARGIN_SECONDS + 10);
            capture_stderr_end(out, sizeof(out));
            CHECK(bm_peer_registry_count(&registry) == 0, "(c) the connection should be closed");
            CHECK(strstr(out, "inbound connection (fd=") != NULL, "(c) the WARN should say inbound");
            CHECK(strstr(out, "unread=130 byte(s) tcp_state=CLOSE_WAIT") != NULL,
                  "(c) the overdue WARN should record the unread bytes and the CLOSE_WAIT state");
            CHECK(strstr(out, "15s past the 20s threshold") != NULL, "(c) the overdue seconds should be reported");

            bm_peer_registry_destroy(&registry);
            close(epfd);
        }

        /* (d) handshake完了済みの接続は、どれだけ無活動でもこのWARNの対象ではない(pingが送られるだけ) */
        {
            int epfd = epoll_create1(0);
            struct bm_peer_registry registry;
            bm_peer_registry_init(&registry);
            int local_fd, remote_fd;
            struct bm_fd_data *conn = make_test_conn(epfd, &local_fd, &remote_fd);
            CHECK(conn != NULL, "make_test_conn should succeed");
            bm_peer_registry_add(&registry, conn);
            conn->handshake_complete = 1;
            conn->last_activity = t0;
            struct bm_epoll_thread_args args;
            memset(&args, 0, sizeof(args));
            args.epfd = epfd;
            args.registry = &registry;

            capture_stderr_begin();
            bm_network_idle_sweep(&args, t0 + 100000);
            capture_stderr_end(out, sizeof(out));
            CHECK(bm_peer_registry_count(&registry) == 1, "(d) a handshake-complete connection is not closed");
            CHECK(strstr(out, "handshake timeout overdue") == NULL,
                  "(d) a handshake-complete connection must NOT log the overdue WARN");

            /* 切断されていないので、bm_fd_data自体はこのテストが片付ける(シナリオ2と同じ) */
            bm_peer_registry_remove(&registry, conn);
            bm_fd_data_free(conn);
            close(local_fd);
            close(remote_fd);
            bm_peer_registry_destroy(&registry);
            close(epfd);
        }
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
