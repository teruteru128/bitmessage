/*
 * §9 Dandelion++ Stage 2(実際のstem/fluff判定ロジック、infra/dandelion.c)のテスト。
 * DESIGN.md §9.2で決めた「単一ホップ分のstem」の実装:
 * - bm_peer_registry_pick_random_dandelion_peer: BM_FD_CLIENT_SOCKET(outbound)かつ
 *   BM_SERVICE_NODE_DANDELIONを立てている接続だけがstem successor候補になること
 * - bm_dandelion_maybe_reshuffle: epoch(600秒)経過前は再抽選しないこと
 * - bm_dandelion_decide: stem successorがtarget_connectionの場合はSTEM、それ以外はSKIP、
 *   タイムアウト経過後は誰に対してもFLUFFになること
 * - bm_dandelion_expire_and_refluff: タイムアウトを過ぎたhashを実際にinvとしてbroadcastし、
 *   それまでSKIPだった接続にも届くようになること
 *
 * 時刻は全て呼び出し側が明示的に渡すため(dandelion.h参照)、実時間を待たずに
 * 決定的にテストできる。
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/infra/dandelion.h"
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

/* 実TCPソケットで、指定した種別・services・logical_peer_ip/portを持つbm_fd_dataを作る
 * (bm_network_resolve_peer_ip_portがどちらの経路を通っても正しく動くよう、実際に
 * accept()されたソケットのpeer_addrも有効にしておく)。呼び出し側でclose(*local_fd)/
 * close(*remote_fd)、bm_fd_data_freeすること。 */
static struct bm_fd_data *make_test_conn(enum bm_fd_type type, uint64_t services, int *out_local_fd,
                                          int *out_remote_fd)
{
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len);
    int port = ntohs(addr.sin_port);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &connect_addr.sin_addr);
    (void)connect(client_fd, (struct sockaddr *)&connect_addr, sizeof(connect_addr));

    int accepted_fd = accept(listen_fd, NULL, NULL);
    close(listen_fd);

    struct bm_fd_data *conn = bm_fd_data_new(type, accepted_fd);
    conn->services = services;
    *out_local_fd = accepted_fd;
    *out_remote_fd = client_fd;
    return conn;
}

int main(void)
{
    bm_dandelion_module_init();

    /* --- 1. pick_random_dandelion_peer: outbound+NODE_DANDELIONだけが候補になること --- */
    {
        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);

        int fds_a[2], fds_b[2], fds_c[2];
        /* a: outbound、Dandelion対応 -> 候補になるべき */
        struct bm_fd_data *conn_a =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_a[0], &fds_a[1]);
        /* b: inbound、Dandelion対応 -> 自分が選んだ相手ではないので候補にならないはず */
        struct bm_fd_data *conn_b =
            make_test_conn(BM_FD_SERVER_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_b[0], &fds_b[1]);
        /* c: outbound、Dandelion非対応(services=0) -> 候補にならないはず */
        struct bm_fd_data *conn_c = make_test_conn(BM_FD_CLIENT_SOCKET, 0, &fds_c[0], &fds_c[1]);

        bm_peer_registry_add(&reg, conn_a);
        bm_peer_registry_add(&reg, conn_b);
        bm_peer_registry_add(&reg, conn_c);

        int found = 0;
        for (int i = 0; i < 20; i++) /* reservoir samplingなので複数回試して安定性を見る */
        {
            char ip[64];
            int port = 0;
            if (bm_peer_registry_pick_random_dandelion_peer(&reg, ip, sizeof(ip), &port))
            {
                found = 1;
                char conn_a_ip[64];
                int conn_a_port = 0;
                bm_network_resolve_peer_ip_port(conn_a, conn_a_ip, sizeof(conn_a_ip), &conn_a_port);
                CHECK(strcmp(ip, conn_a_ip) == 0 && port == conn_a_port,
                      "the only eligible (outbound + NODE_DANDELION) peer should always be picked");
            }
        }
        CHECK(found, "pick_random_dandelion_peer should find the one eligible peer");

        bm_peer_registry_remove(&reg, conn_a);
        bm_peer_registry_remove(&reg, conn_b);
        bm_peer_registry_remove(&reg, conn_c);
        bm_fd_data_free(conn_a);
        bm_fd_data_free(conn_b);
        bm_fd_data_free(conn_c);
        close(fds_a[1]);
        close(fds_b[1]);
        close(fds_c[1]);
        bm_peer_registry_destroy(&reg);
    }

    /* --- 2. no successorならFLUFF、successorありならSTEM/SKIPを正しく振り分け、
     * タイムアウト後は誰に対してもFLUFFになること --- */
    {
        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);

        int fds_stem[2], fds_other[2];
        struct bm_fd_data *stem_conn =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_stem[0], &fds_stem[1]);
        struct bm_fd_data *other_conn =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_other[0], &fds_other[1]);
        bm_peer_registry_add(&reg, stem_conn);
        bm_peer_registry_add(&reg, other_conn);

        int64_t t0 = 1000000000;

        unsigned char hash1[32];
        memset(hash1, 0xAA, sizeof(hash1));

        /* 2a. reshuffle前(stem successor未設定)はFLUFF */
        CHECK(bm_decide_propagation(hash1, stem_conn) == BM_PROPAGATE_FLUFF,
              "before any reshuffle, decide_propagation should return FLUFF (no stem successor yet)");

        /* 新しいhashで検証し直す(2aで既にhash1がfluffed確定してしまっているため) */
        unsigned char hash2[32];
        memset(hash2, 0xBB, sizeof(hash2));

        bm_dandelion_maybe_reshuffle(&reg, t0);
        /* stem_conn/other_connの2択だが、registryに登録した順序に依存しないよう、
         * 実際に選ばれた方を「stem側」、もう一方を「other側」として扱う */
        char stem_ip[64];
        int stem_port = 0;
        bm_network_resolve_peer_ip_port(stem_conn, stem_ip, sizeof(stem_ip), &stem_port);
        char other_ip[64];
        int other_port = 0;
        bm_network_resolve_peer_ip_port(other_conn, other_ip, sizeof(other_ip), &other_port);

        enum bm_propagation_mode mode_stem = bm_dandelion_decide(hash2, stem_conn, t0);
        enum bm_propagation_mode mode_other = bm_dandelion_decide(hash2, other_conn, t0);
        CHECK((mode_stem == BM_PROPAGATE_STEM) != (mode_other == BM_PROPAGATE_STEM),
              "exactly one of the two eligible peers should be the stem successor for this hash");
        CHECK(mode_stem == BM_PROPAGATE_STEM || mode_stem == BM_PROPAGATE_SKIP,
              "non-timed-out decision should be STEM or SKIP, never FLUFF");
        CHECK(mode_other == BM_PROPAGATE_STEM || mode_other == BM_PROPAGATE_SKIP,
              "non-timed-out decision should be STEM or SKIP, never FLUFF");

        /* 2b. 同じhashを、十分先の時刻(タイムアウト後、固定10秒+指数分布平均30秒の
         * 最大現実的な範囲を大きく超える)で問い合わせると、誰に対してもFLUFFになる */
        int64_t far_future = t0 + 10000;
        CHECK(bm_dandelion_decide(hash2, stem_conn, far_future) == BM_PROPAGATE_FLUFF,
              "after the timeout, decision should be FLUFF regardless of target connection (stem side)");
        CHECK(bm_dandelion_decide(hash2, other_conn, far_future) == BM_PROPAGATE_FLUFF,
              "after the timeout, decision should be FLUFF regardless of target connection (other side)");

        bm_peer_registry_remove(&reg, stem_conn);
        bm_peer_registry_remove(&reg, other_conn);
        bm_fd_data_free(stem_conn);
        bm_fd_data_free(other_conn);
        close(fds_stem[1]);
        close(fds_other[1]);
        bm_peer_registry_destroy(&reg);
    }

    /* --- 3. expire_and_refluff: タイムアウト経過後、実際にinvがbroadcastされること --- */
    {
        bm_dandelion_module_init(); /* このシナリオ専用にstateをリセット */

        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);

        int fds_stem[2], fds_other[2];
        struct bm_fd_data *stem_conn =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_stem[0], &fds_stem[1]);
        struct bm_fd_data *other_conn =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_other[0], &fds_other[1]);
        bm_peer_registry_add(&reg, stem_conn);
        bm_peer_registry_add(&reg, other_conn);

        /* infra/object.cのbm_decide_propagation(bm_peer_registry_broadcast_invが内部で
         * 呼ぶ)はtime(NULL)で実時刻を使うため、このシナリオではテスト側も実時刻を基準に
         * 揃える(直接bm_dandelion_decideを呼ぶ他のシナリオのような固定t0は使えない。
         * 固定t0を使うと、broadcast_inv経由で実時刻ベースに確定したエントリのタイムアウトと
         * 噛み合わなくなる) */
        int64_t t0 = (int64_t)time(NULL);
        bm_dandelion_maybe_reshuffle(&reg, t0);

        /* pick_random_dandelion_peerはstem_conn/other_connのどちらを選ぶか保証しない
         * (一様ランダム)ため、変数名で決め打ちせず実際に選ばれた方を都度判定する */
        unsigned char hash3[32];
        memset(hash3, 0xCC, sizeof(hash3));

        /* まずbroadcast_inv経由で新規object扱いにする(1回目はstem/skipに振り分けられ、
         * どちらの接続にも通常のinvは届かないはず)。この呼び出し(内部でtime(NULL)を使う)で
         * hash3のタイムアウトが実時刻基準で確定する */
        bm_peer_registry_broadcast_inv(&reg, &hash3, 1, NULL);

        int real_stem_fd = (bm_dandelion_decide(hash3, stem_conn, t0) == BM_PROPAGATE_STEM) ? fds_stem[1]
                                                                                              : fds_other[1];
        int real_other_fd = (real_stem_fd == fds_stem[1]) ? fds_other[1] : fds_stem[1];

        /* fdをnon-blockingにして「何も届いていない」ことを確認する */
        int flags_stem = fcntl(real_stem_fd, F_GETFL, 0);
        fcntl(real_stem_fd, F_SETFL, flags_stem | O_NONBLOCK);
        int flags_other = fcntl(real_other_fd, F_GETFL, 0);
        fcntl(real_other_fd, F_SETFL, flags_other | O_NONBLOCK);

        unsigned char peek_buf[256];
        ssize_t n_other_before = recv(real_other_fd, peek_buf, sizeof(peek_buf), MSG_PEEK);
        CHECK(n_other_before < 0, "the non-stem peer should not receive anything before the timeout");

        /* タイムアウト後にexpire_and_refluffを呼ぶと、実際にinvがbroadcastされる。
         * 指数分布の平均30秒(+固定10秒)に対し、+10000秒は現実的な乱数の範囲を大きく
         * 超えるため、実時刻基準でも安全にタイムアウト後とみなせる */
        int64_t far_future = t0 + 10000;
        int fluffed = bm_dandelion_expire_and_refluff(&reg, far_future);
        CHECK(fluffed == 1, "expire_and_refluff should report exactly one hash fluffed");

        unsigned char stem_buf[256];
        ssize_t n_stem_after = recv(real_stem_fd, stem_buf, sizeof(stem_buf), MSG_PEEK);
        unsigned char other_buf[256];
        ssize_t n_other_after = recv(real_other_fd, other_buf, sizeof(other_buf), MSG_PEEK);
        CHECK(n_stem_after > 0, "after fluffing, the stem-side peer should receive the inv broadcast");
        CHECK(n_other_after > 0, "after fluffing, the previously-skipped peer should also receive the inv");

        bm_peer_registry_remove(&reg, stem_conn);
        bm_peer_registry_remove(&reg, other_conn);
        bm_fd_data_free(stem_conn);
        bm_fd_data_free(other_conn);
        close(fds_stem[1]);
        close(fds_other[1]);
        bm_peer_registry_destroy(&reg);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
