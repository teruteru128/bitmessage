/*
 * §11 2026-08-22発覚のバグ修正のテスト(rating関連の3回目の修正の兄弟バグ)。
 *
 * bm_peer_registry_has_peer(「既に接続済みの相手には二重接続しない」判定、
 * peer_connector.cのbm_peer_connector_connect_initialが使う)は、以前はreg->conns[i]->
 * peer_addr(getpeername)をそのまま比較していた。SOCKS5(Tor)プロキシ経由の接続では
 * これがプロキシ自身のアドレス(例: 127.0.0.1:9050)になり、渡された本来の候補
 * アドレスとは絶対に一致しないため、SOCKS5有効時は「既に接続済み」判定が常に偽になり
 * 二重接続防止が機能していなかった(rating調査で見つかった一連のバグと同じ根本原因)。
 *
 * bm_network_resolve_peer_ip_port(logical_peer_ip優先)を使うよう修正した結果、
 * (1) SOCKS5経由(logical_peer_ip設定済み)でも本来の接続先で正しく重複検知できること、
 * (2) プロキシ自身のアドレスは重複検知の対象にならないこと、
 * (3) 直接接続(logical_peer_ip未設定、旧来の経路)でも従来通りpeer_addrベースで
 *     重複検知できること、
 * を確認する。fd/実ソケットは使わず、bm_fd_dataを直接組み立てて検証する
 * (bm_peer_registry_has_peer自体はfdに触れない純粋なメモリ上の照合のため)。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void set_addr(struct sockaddr_storage *out, const char *ip, int port)
{
    memset(out, 0, sizeof(*out));
    struct sockaddr_in *sin = (struct sockaddr_in *)out;
    sin->sin_family = AF_INET;
    sin->sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sin->sin_addr);
}

int main(void)
{
    struct bm_peer_registry reg;
    bm_peer_registry_init(&reg);

    /* --- 1. SOCKS5経由を模した接続: peer_addrはプロキシ(127.0.0.1:9060、テスト用ダミー)、
     * logical_peer_ipは本来の接続先(203.0.113.5:8444、TEST-NET-3の予約アドレスなので
     * 実在せずテストとして安全)。peer_connector.cが設定するのと同じ形。 --- */
    struct bm_fd_data proxied_conn;
    memset(&proxied_conn, 0, sizeof(proxied_conn));
    proxied_conn.type = BM_FD_CLIENT_SOCKET;
    proxied_conn.fd = -1;
    set_addr(&proxied_conn.peer_addr, "127.0.0.1", 9060);
    strncpy(proxied_conn.logical_peer_ip, "203.0.113.5", sizeof(proxied_conn.logical_peer_ip) - 1);
    proxied_conn.logical_peer_port = 8444;

    bm_peer_registry_add(&reg, &proxied_conn);

    CHECK(bm_peer_registry_has_peer(&reg, "203.0.113.5", 8444) == 1,
          "proxied connection should be recognized as already-connected via logical_peer_ip");
    CHECK(bm_peer_registry_has_peer(&reg, "127.0.0.1", 9060) == 0,
          "the proxy's own address should NOT be treated as an already-connected peer");
    CHECK(bm_peer_registry_has_peer(&reg, "203.0.113.99", 8444) == 0,
          "an unrelated address should not be falsely recognized as already-connected");

    bm_peer_registry_remove(&reg, &proxied_conn);

    /* --- 2. 直接接続(SOCKS5未使用)を模した接続: logical_peer_ipは未設定のまま、
     * peer_addrが本来の接続先そのもの(直接connect()した場合、getpeername()は正しい値を
     * 返すため)。従来通りpeer_addrベースのフォールバックで重複検知できることを確認する。 --- */
    struct bm_fd_data direct_conn;
    memset(&direct_conn, 0, sizeof(direct_conn));
    direct_conn.type = BM_FD_CLIENT_SOCKET;
    direct_conn.fd = -1;
    set_addr(&direct_conn.peer_addr, "198.51.100.7", 8444); /* TEST-NET-2、テストとして安全 */

    bm_peer_registry_add(&reg, &direct_conn);

    CHECK(bm_peer_registry_has_peer(&reg, "198.51.100.7", 8444) == 1,
          "direct (non-proxied) connection should still be recognized via the peer_addr fallback");

    bm_peer_registry_remove(&reg, &direct_conn);
    CHECK(bm_peer_registry_has_peer(&reg, "198.51.100.7", 8444) == 0,
          "after removal, the peer should no longer be considered already-connected");

    bm_peer_registry_destroy(&reg);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
