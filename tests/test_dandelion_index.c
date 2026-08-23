/*
 * §11 2026-08-23発覚の重大な性能バグ修正のテスト。dandelion.cのfind_or_create_entryは
 * 以前g_state.entriesを先頭から線形探索(memcmp)しており、handle_inv(未所持hashごとに
 * 呼ぶ)やsend_big_inv(保有する全hashごとに呼ぶ)がO(n^2)になっていた。今夜
 * object_pool.dbが1万件規模まで育った状態でsend_big_invを1回呼ぶだけで概算5000万回超の
 * memcmpが発生し、g_state.lockを握ったまま単一のnetwork_epoll_thread全体を一瞬止めて
 * いた(新規peerが繋がるたびに発生し、object_pool.dbが増えるほど二次関数的に悪化する)。
 *
 * オープンアドレッシングのハッシュテーブルによる索引をfind_or_create_entryへ追加した
 * (dandelion.c参照)。本テストは以下の2点を確認する:
 * - 正しさ: BM_MAX_INVENTORY_ITEMS(50000)件規模の大量のhashについて、事前に
 *   bm_dandelion_note_sourceで印を付けた分(FLUFF確定になるはず)とそうでない分
 *   (stem successorへSTEMになるはず)を混在させ、bm_dandelion_decideが全件について
 *   正しい判定を返すことを確認する。索引が既存エントリを取り違えたり、既存エントリを
 *   見つけられず重複作成してしまったりするバグがあれば、この判定が食い違って露見する。
 * - 速度: 50000件の処理が数秒以内(O(n)なら余裕で収まるはずの閾値)に完了することを
 *   確認する。旧来のO(n^2)実装ではこの規模だと数秒〜それ以上かかっていたはずで、
 *   将来同じ種類の性能劣化が再発しないことを検知する回帰テストを兼ねる。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/infra/dandelion.h"
#include "../src/infra/network.h"
#include "../src/infra/object.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"

#define TEST_HASH_COUNT 50000

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

/* tests/test_dandelion_stage2.cと同じヘルパー(実socketpair経由、servicesを直接設定できる) */
static struct bm_fd_data *make_test_conn(enum bm_fd_type type, uint64_t services, int *out_local_fd,
                                          int *out_remote_fd)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
    listen(listen_fd, 1);
    socklen_t addr_len = sizeof(listen_addr);
    getsockname(listen_fd, (struct sockaddr *)&listen_addr, &addr_len);
    int port = ntohs(listen_addr.sin_port);

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

    struct bm_peer_registry reg;
    bm_peer_registry_init(&reg);

    int fds_stem[2];
    struct bm_fd_data *stem_conn =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_stem[0], &fds_stem[1]);
    bm_peer_registry_add(&reg, stem_conn);

    int64_t t0 = 1000000000;
    bm_dandelion_maybe_reshuffle(&reg, t0); /* registryに候補が1つだけなので必ずstem_connが選ばれる */

    /* TEST_HASH_COUNT件の相異なるhashを決定的に生成する(乗算定数はKnuthの黄金比ハッシュ、
     * 単なる連番よりバケツへの分布を分散させるため) */
    unsigned char(*hashes)[32] = malloc(sizeof(*hashes) * TEST_HASH_COUNT);
    CHECK(hashes != NULL, "malloc for test hashes");
    for (size_t i = 0; i < TEST_HASH_COUNT; i++)
    {
        memset(hashes[i], 0, sizeof(hashes[i]));
        uint64_t k = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        memcpy(hashes[i], &k, sizeof(k));
    }

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* 偶数indexの分だけ先にnote_sourceでlearned_via_plain_inv=1のエントリを作っておく
     * (FLUFF確定になるはず)。奇数indexの分はbm_dandelion_decideの初回呼び出しで
     * 新規作成され、stem successor(stem_conn)向けにSTEMになるはず */
    for (size_t i = 0; i < TEST_HASH_COUNT; i += 2)
    {
        bm_dandelion_note_source(hashes[i], 0, t0);
    }

    size_t mismatch = 0;
    for (size_t i = 0; i < TEST_HASH_COUNT; i++)
    {
        enum bm_propagation_mode mode = bm_dandelion_decide(hashes[i], stem_conn, t0);
        enum bm_propagation_mode expected = (i % 2 == 0) ? BM_PROPAGATE_FLUFF : BM_PROPAGATE_STEM;
        if (mode != expected)
        {
            mismatch++;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed =
            (double)(ts_end.tv_sec - ts_start.tv_sec) + (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    CHECK(mismatch == 0,
          "every one of the 50000 hashes should get its expected FLUFF/STEM decision (proves the hash index "
          "finds/creates the correct entry at scale, not a duplicate with stale state)");
    printf("dandelion index scale test: %d hashes processed in %.3fs (mismatches: %zu)\n", TEST_HASH_COUNT, elapsed,
            mismatch);
    CHECK(elapsed < 3.0,
          "processing 50000 hashes through the dandelion index should comfortably finish under 3s; the old "
          "O(n^2) linear-scan implementation would take several seconds at this scale");

    free(hashes);
    bm_peer_registry_remove(&reg, stem_conn);
    bm_fd_data_free(stem_conn);
    close(fds_stem[1]);
    bm_peer_registry_destroy(&reg);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
