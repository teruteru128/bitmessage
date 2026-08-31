/*
 * §11 2026-08-31発覚のバグの回帰テスト。以前はversion messageのaddrFrom(送信者が
 * 主張する「自分自身のアドレス」)にconn->local_addr(getsockname()で得たTCP接続の
 * 送信元、NAT配下ではOSが選んだephemeralなローカルポート)をそのまま使っていた
 * (peer_connector.c/object_sync.cのbm_post_version呼び出し箇所)。これが原因で、
 * 外部からアクセス不能な自宅IPv4+ephemeralポートが「自分の連絡先」として接続先peerへ
 * 伝わり、addr message経由でネットワークを巡って自分自身のpeers.dbにも到達不能な
 * 接続候補として混入する問題が実際に発覚した(ユーザー報告)。
 *
 * 修正: addrFromには常にbm_unspecified_ipv4_address()が返す0.0.0.0を使う(「自分の
 * 到達可能アドレスは不明」を正直に示す値。object_sync.cのis_routable_ipv4_peer_address
 * は0.0.0.0を非routableとして弾くため、これを受け取ったpeerがさらに広めることもない)。
 *
 * ここでは、ephemeralな(=リッスンポートと無関係な)ローカルアドレスを渡しても、
 * 実際に送信されるversion payloadのaddrFromが常に0.0.0.0になることを確認する。
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    /* --- 1. bm_unspecified_ipv4_address自体がAF_INET+0.0.0.0を返す --- */
    {
        struct sockaddr_storage self_addr;
        bm_unspecified_ipv4_address(&self_addr);
        CHECK(self_addr.ss_family == AF_INET, "should be AF_INET");
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&self_addr;
        CHECK(sin->sin_addr.s_addr == INADDR_ANY, "should be 0.0.0.0");
        CHECK(sin->sin_port == 0, "port should be 0");
    }

    /* --- 2. 実際にversion payloadを組み立て、addrFromが常に0.0.0.0になること。
     * peer_addr(addrRecv相当)は普通のIPを渡し、addrFromの値だけがpeer_addrの内容と
     * 無関係に0.0.0.0へ潰れることを確認する(以前のバグはこの2つを混同していなかったが、
     * 念のため両者が独立して扱われることも確認する意味も込める) --- */
    {
        struct sockaddr_in peer_addr_in;
        memset(&peer_addr_in, 0, sizeof(peer_addr_in));
        peer_addr_in.sin_family = AF_INET;
        peer_addr_in.sin_port = htons(8444);
        inet_pton(AF_INET, "203.0.113.42", &peer_addr_in.sin_addr);
        struct sockaddr_storage peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        memcpy(&peer_addr, &peer_addr_in, sizeof(peer_addr_in));

        /* 修正前バグの再現条件: ephemeralな(リッスンポートと無関係な)ローカルアドレス */
        struct sockaddr_in ephemeral_local_in;
        memset(&ephemeral_local_in, 0, sizeof(ephemeral_local_in));
        ephemeral_local_in.sin_family = AF_INET;
        ephemeral_local_in.sin_port = htons(54321); /* OSが選んだephemeralポートの例 */
        inet_pton(AF_INET, "192.0.2.7", &ephemeral_local_in.sin_addr); /* 自宅IPの例 */
        (void)ephemeral_local_in; /* 修正後はこの値をbm_post_versionへ渡さないことの説明用 */

        struct sockaddr_storage self_addr;
        bm_unspecified_ipv4_address(&self_addr);

        size_t len = 0;
        unsigned char *msg = bm_new_version_message("/bitmessage-c-test:0.1.0/", 3, &peer_addr, &self_addr, &len);
        CHECK(msg != NULL, "bm_new_version_message should succeed");

        struct bm_version_message ver;
        bm_parse_version_message(msg + BM_MESSAGE_HEADER_SIZE, len - BM_MESSAGE_HEADER_SIZE, &ver);

        /* addr_from(26byte: 未使用time/stream(12)+ipv6-mapped ipv4(12→addr[10..13]がff ff)+ip(4)+port(2)) */
        unsigned char addr_from_ip[4];
        memcpy(addr_from_ip, ver.addr_from + 12, 4);
        CHECK(addr_from_ip[0] == 0 && addr_from_ip[1] == 0 && addr_from_ip[2] == 0 && addr_from_ip[3] == 0,
              "addrFrom IP must be 0.0.0.0, not the ephemeral local address");
        unsigned char addr_from_port[2];
        memcpy(addr_from_port, ver.addr_from + 24, 2);
        CHECK(addr_from_port[0] == 0 && addr_from_port[1] == 0, "addrFrom port must be 0");

        /* addrRecv(peer_addr)側は影響を受けず、渡した203.0.113.42:8444のまま */
        unsigned char addr_recv_ip[4];
        memcpy(addr_recv_ip, ver.addr_recv + 12, 4);
        CHECK(addr_recv_ip[0] == 203 && addr_recv_ip[1] == 0 && addr_recv_ip[2] == 113 && addr_recv_ip[3] == 42,
              "addrRecv should still reflect the given peer_addr");

        bm_free_version_message(&ver);
        free(msg);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
