/*
 * §11 2026-08-23 backlog項目5(送受信バイト数)のテスト。接続ごとの累積
 * (struct bm_fd_dataのbytes_sent/bytes_received)と、プロセス起動時からの全体累積
 * (bm_network_get_stats、切断済みの接続ぶんも含む)の両方を検証する。
 *
 * bm_network_get_statsはプロセス内シングルトンでテスト全体を通じて増え続けるだけなので、
 * 各シナリオは絶対値ではなく「シナリオ開始時点からの増分」で検証する。
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/infra/network.h"
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

int main(void)
{
    /* --- 1. 受信側: bm_network_handle_readableが接続ごと・全体累積の両方を
     * 正しく更新すること --- */
    {
        int fds[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair for receive-side scenario");
        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
        CHECK(conn != NULL, "bm_fd_data_new for receive-side scenario");
        CHECK(conn->bytes_received == 0, "a fresh connection should start with bytes_received=0");
        int flags = fcntl(fds[0], F_GETFL, 0);
        fcntl(fds[0], F_SETFL, flags | O_NONBLOCK); /* bm_network_handle_readableはEAGAINまで
                                                       * 読み続けるため必須(test_idle_sweep.c等と同じ) */

        uint64_t sent_before = 0, received_before = 0;
        bm_network_get_stats(&sent_before, &received_before);

        /* verackはpayload無し(ヘッダのみ24byte)。default_dispatch(handler=NULL)は
         * verackを受けてもログを出すだけで返信しないため、送信側の増分と混ざらず
         * 受信側だけを綺麗に検証できる */
        size_t packet_len = 0;
        unsigned char *packet = bm_create_packet("verack", NULL, 0, &packet_len);
        CHECK(packet_len == BM_MESSAGE_HEADER_SIZE, "a header-only packet should be exactly the header size");
        ssize_t written = write(fds[1], packet, packet_len);
        CHECK(written == (ssize_t)packet_len, "writing the verack packet to the peer side should succeed");
        free(packet);

        int rc = bm_network_handle_readable(conn, NULL, NULL);
        CHECK(rc == 0, "bm_network_handle_readable should return 0 (EAGAIN reached, no disconnect)");
        CHECK(conn->bytes_received == packet_len,
              "conn->bytes_received should equal exactly the bytes actually read");

        uint64_t sent_after = 0, received_after = 0;
        bm_network_get_stats(&sent_after, &received_after);
        CHECK(received_after - received_before == packet_len,
              "the global received-bytes total should increase by exactly the bytes read");
        CHECK(sent_after == sent_before,
              "the global sent-bytes total should be unaffected by a receive-only scenario");

        close(fds[0]);
        close(fds[1]);
        bm_fd_data_free(conn);
    }

    /* --- 2. 送信側: bm_reply_verack/bm_reply_pongが接続ごとの送信バイト数を
     * 正しく積むこと(いずれもヘッダのみ、payload無し) --- */
    {
        int fds[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair for send-side scenario");
        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
        CHECK(conn != NULL, "bm_fd_data_new for send-side scenario");
        CHECK(conn->bytes_sent == 0, "a fresh connection should start with bytes_sent=0");

        uint64_t sent_before = 0, received_before = 0;
        bm_network_get_stats(&sent_before, &received_before);

        CHECK(bm_reply_verack(conn) == 0, "bm_reply_verack should succeed");
        CHECK(conn->bytes_sent == BM_MESSAGE_HEADER_SIZE,
              "conn->bytes_sent should equal the header-only verack packet size after one reply");

        CHECK(bm_reply_pong(conn) == 0, "bm_reply_pong should succeed");
        CHECK(conn->bytes_sent == BM_MESSAGE_HEADER_SIZE * 2,
              "conn->bytes_sent should accumulate across multiple replies (verack + pong)");

        uint64_t sent_after = 0, received_after = 0;
        bm_network_get_stats(&sent_after, &received_after);
        CHECK(sent_after - sent_before == BM_MESSAGE_HEADER_SIZE * 2,
              "the global sent-bytes total should increase by exactly the two replies' combined size");
        CHECK(received_after == received_before,
              "the global received-bytes total should be unaffected by a send-only scenario");

        close(fds[0]);
        close(fds[1]);
        bm_fd_data_free(conn);
    }

    /* --- 3. bm_network_write_allを直接fd(conn無し)で呼んだ場合も、全体累積には
     * 正しく計上されること(peer_registry.cのbroadcast_invがdup()したfdへ書く経路の
     * 簡易再現) --- */
    {
        int fds[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair for conn-less write scenario");

        uint64_t sent_before = 0, received_before = 0;
        bm_network_get_stats(&sent_before, &received_before);

        const unsigned char data[] = "hello";
        CHECK(bm_network_write_all(fds[0], data, sizeof(data), BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS, NULL, 0) == 0,
              "bm_network_write_all should succeed");

        uint64_t sent_after = 0, received_after = 0;
        bm_network_get_stats(&sent_after, &received_after);
        CHECK(sent_after - sent_before == sizeof(data),
              "the global sent-bytes total should increase even for a conn-less bm_network_write_all call");

        close(fds[0]);
        close(fds[1]);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
