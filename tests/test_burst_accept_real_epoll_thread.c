/*
 * §11 2026-09-05: tests/test_burst_accept_idle_sweep.cの続き。
 *
 * 直接関数呼び出し(bm_network_handle_accept + bm_network_idle_sweepを合成時刻で
 * 直接呼ぶ)によるバースト再現テストでは、silentな切断・不正データ送信後の切断のいずれも
 * 正しく刈り取られ、バグを再現できなかった。しかしその方式はbm_network_idle_sweepの
 * タイムアウト計算ロジックしか検証しておらず、本番で実際に観測した「CLOSE-WAIT状態で
 * Recv-Q=130バイトの未読データが残ったまま」という事実(=epoll_waitがそのfdに対して
 * 一度もreadableイベントを配送していない可能性を示唆)は検証できていなかった。
 *
 * このテストはbm_network_epoll_threadを実スレッドとして起動し、本物のepoll_wait経由で
 * 同じ「バーストaccept→少量データ送信→peer切断」シナリオを再現できるか確認する。
 * 実時間(壁時計)でBM_HANDSHAKE_TIMEOUT_SECONDS待つ必要があるため、他のテストより
 * 実行時間が長い(数十秒)。
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

/* test_burst_accept_idle_sweep.cと同じ根拠(listen backlog=16以下に抑える) */
#define BURST_SIZE 8

static void sleep_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000L * 1000L};
    nanosleep(&ts, NULL);
}

/* count_by_typeがexpectedになるまで、timeout_msを上限にポーリングする。タイムアウトしても
 * 最後に観測した値を返す(呼び出し元がCHECKで判定する)。 */
static size_t wait_for_count(struct bm_peer_registry *reg, enum bm_fd_type type, size_t expected, long timeout_ms)
{
    long waited = 0;
    size_t count = bm_peer_registry_count_by_type(reg, type);
    while (count != expected && waited < timeout_ms)
    {
        sleep_ms(100);
        waited += 100;
        count = bm_peer_registry_count_by_type(reg, type);
    }
    return count;
}

int main(void)
{
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(listen_fd >= 0, "bm_network_listen should succeed on 127.0.0.1:0");
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len);
    int listen_port = ntohs(listen_addr.sin_port);

    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1 should succeed");

    struct bm_fd_data *listener = bm_fd_data_new(BM_FD_LISTEN_SOCKET, listen_fd);
    CHECK(listener != NULL, "bm_fd_data_new for the listener should succeed");
    struct epoll_event lev;
    lev.events = EPOLLIN;
    lev.data.ptr = listener;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev);

    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);

    /* §11 2026-08-23 backlog項目5準拠: bm_network_epoll_threadはargsをこの関数の外
     * (別スレッド)から参照し続けるため、mallocしてスレッドへ所有権を渡す
     * (test_peer_rating_on_disconnect.cと同じ方針、グレースフルシャットダウン機構が
     * 無いためjoinはせずプロセス終了時に道連れで終わらせる)。 */
    struct bm_epoll_thread_args *args = malloc(sizeof(*args));
    args->epfd = epfd;
    args->handler = NULL;
    args->user_data = NULL;
    args->registry = &registry;
    args->peers_db = NULL;
    bm_inbound_rate_limiter_init(&args->inbound_rate_limiter);

    pthread_t epoll_thread;
    CHECK(pthread_create(&epoll_thread, NULL, bm_network_epoll_thread, args) == 0,
          "pthread_create for bm_network_epoll_thread should succeed");

    /* --- 本番22:50:29の状況を模す: BURST_SIZE本を同時にconnect()する。実スレッドが
     * epoll_wait経由でlistenソケットのreadableを検知し、内部でaccept()ループを
     * 回して一括登録するはず。 --- */
    int client_fds[BURST_SIZE];
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

    /* 実スレッドがbursts全部をaccept()し終えるまで待つ(通常は次のepoll_wait周期で
     * 即座に検知されるはずなので数百ms以内で揃うはず) */
    size_t accepted = wait_for_count(&registry, BM_FD_SERVER_SOCKET, BURST_SIZE, 3000);
    CHECK(accepted == BURST_SIZE, "the real epoll thread should accept all burst connections");

    /* --- 本番のss調査で見つかった実際の状態(CLOSE-WAIT、Recv-Q=130の未読データ)を
     * 再現する: bitmessageプロトコルとしては不正な生データを130バイト送った直後、
     * クライアント側を即座にclose()する(データがまだ相手に読まれていない可能性がある
     * タイミングでの切断)。 --- */
    unsigned char garbage[130];
    memset(garbage, 0xAB, sizeof(garbage));
    for (int i = 0; i < BURST_SIZE; i++)
    {
        write(client_fds[i], garbage, sizeof(garbage));
        close(client_fds[i]);
    }

    /* --- BM_HANDSHAKE_TIMEOUT_SECONDS(実時間)を超えて待ち、実スレッドのidle_sweepが
     * 全数を刈り取るか確認する。1本でも残ればバグの再現。 --- */
    size_t remaining =
        wait_for_count(&registry, BM_FD_SERVER_SOCKET, 0, (long)(BM_HANDSHAKE_TIMEOUT_SECONDS + 10) * 1000L);
    CHECK(remaining == 0,
          "every burst-accepted connection (garbage-then-disconnected) should be reaped by the real epoll thread "
          "within the handshake timeout");
    if (remaining != 0)
    {
        fprintf(stderr, "REPRO: %zu of %d burst connections were NOT reaped by the real epoll thread\n", remaining,
                BURST_SIZE);
    }

    /* bm_network_epoll_threadはグレースフルシャットダウン機構を持たないため、
     * プロセス終了時に道連れで終わらせる(test_peer_rating_on_disconnect.cと同じ方針)。 */

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
