#include "peer_connector.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../core/config_store.h"
#include "../core/peer_manager.h"
#include "dandelion.h"
#include "network.h"
#include "peer_registry.h"

#define MAX_CANDIDATES 32
#define CONNECT_TIMEOUT_SEC 5
/* SOCKS5ハンドシェイク(特にCONNECT応答待ち)は、宛先がTor等の場合に回線構築で数秒〜十数秒
 * かかることがあるため、ローカルのプロキシ自体へのTCP接続(CONNECT_TIMEOUT_SEC)より長めに取る */
#define SOCKS5_HANDSHAKE_TIMEOUT_SEC 20

/* 非ブロッキングconnect + selectでタイムアウト付き接続を行う。成功時fd、失敗時-1 */
static int connect_with_timeout(const char *ip, int port, int timeout_sec)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(ip, port_str, &hints, &res) != 0)
    {
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0)
        {
            continue;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(sock, p->ai_addr, p->ai_addrlen);
        if (rc == 0)
        {
            break; /* 即座に完了(loopback等) */
        }
        if (errno != EINPROGRESS)
        {
            close(sock);
            sock = -1;
            continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        rc = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0)
        {
            close(sock);
            sock = -1;
            continue;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0)
        {
            close(sock);
            sock = -1;
            continue;
        }
        break; /* 接続成功。O_NONBLOCKのままepollへ渡す */
    }

    freeaddrinfo(res);
    return sock;
}

/* O_NONBLOCKなsockに対しEAGAIN/EWOULDBLOCKをselect()で待ちながらlenバイト送り切る。成功時0 */
static int socks5_send_all(int sock, const unsigned char *buf, size_t len, int timeout_sec)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n > 0)
        {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0)
            {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return 0;
}

/* 同上の受信版。lenバイト読み切るまでselect()で待つ。相手がcloseしたら失敗として扱う */
static int socks5_recv_all(int sock, unsigned char *buf, size_t len, int timeout_sec)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t n = recv(sock, buf + got, len - got, 0);
        if (n > 0)
        {
            got += (size_t)n;
            continue;
        }
        if (n == 0)
        {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0)
            {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return 0;
}

/* RFC1928のREPコードを人間が読めるメッセージへ変換する(§11 outbound Tor経路の検証:
 * 実際にTorへ繋いだ際の失敗原因切り分けを容易にするため) */
static const char *socks5_rep_to_string(unsigned char rep)
{
    switch (rep)
    {
        case 0x00: return "succeeded";
        case 0x01: return "general SOCKS server failure";
        case 0x02: return "connection not allowed by ruleset";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "command not supported";
        case 0x08: return "address type not supported";
        default: return "unknown REP code";
    }
}

/*
 * SOCKS5(RFC1928)のno-auth CONNECTハンドシェイク。sockは既にproxyへ接続済み(O_NONBLOCK)で
 * あること。宛先は常にドメイン名形式(ATYP=0x03)で送る: dest_hostが数字IPの文字列であっても
 * Tor等のSOCKS5サーバーは正しく扱う(ローカルでDNS解決せずそのままCONNECT先として使うため、
 * 将来onionアドレスに対応する際もこの経路がそのまま使える)。成功時0。失敗時は原因を
 * fprintf(stderr, "[peer_connector] socks5: ...")で診断ログに出す(§11、実際にTorへ繋いだ
 * 際の切り分けを容易にするため)
 */
static int socks5_connect(int sock, const char *dest_host, int dest_port, int timeout_sec)
{
    char addr_buf[64];
    bm_network_format_host_port(dest_host, dest_port, addr_buf, sizeof(addr_buf));

    size_t host_len = strlen(dest_host);
    if (host_len == 0 || host_len > 255)
    {
        fprintf(stderr, "[peer_connector] socks5: destination host name too long (%zu bytes)\n", host_len);
        return -1;
    }

    unsigned char greeting[3] = {0x05, 0x01, 0x00}; /* version=5, 1 method, no-auth */
    if (socks5_send_all(sock, greeting, sizeof(greeting), timeout_sec) != 0)
    {
        fprintf(stderr, "[peer_connector] socks5: failed to send greeting to proxy\n");
        return -1;
    }
    unsigned char method_resp[2];
    if (socks5_recv_all(sock, method_resp, sizeof(method_resp), timeout_sec) != 0)
    {
        fprintf(stderr, "[peer_connector] socks5: no greeting response from proxy (unreachable/not a "
                        "SOCKS5 server?)\n");
        return -1;
    }
    if (method_resp[0] != 0x05 || method_resp[1] != 0x00)
    {
        fprintf(stderr, "[peer_connector] socks5: proxy rejected no-auth (version=0x%02x method=0x%02x)\n",
                method_resp[0], method_resp[1]);
        return -1;
    }

    unsigned char req[4 + 1 + 255 + 2];
    size_t req_len = 0;
    req[req_len++] = 0x05;
    req[req_len++] = 0x01; /* CMD=CONNECT */
    req[req_len++] = 0x00; /* RSV */
    req[req_len++] = 0x03; /* ATYP=domain name */
    req[req_len++] = (unsigned char)host_len;
    memcpy(req + req_len, dest_host, host_len);
    req_len += host_len;
    req[req_len++] = (unsigned char)((dest_port >> 8) & 0xff);
    req[req_len++] = (unsigned char)(dest_port & 0xff);
    if (socks5_send_all(sock, req, req_len, timeout_sec) != 0)
    {
        fprintf(stderr, "[peer_connector] socks5: failed to send CONNECT request to proxy\n");
        return -1;
    }

    unsigned char reply_head[4];
    if (socks5_recv_all(sock, reply_head, sizeof(reply_head), timeout_sec) != 0)
    {
        fprintf(stderr, "[peer_connector] socks5: no CONNECT reply from proxy (target %s unreachable "
                        "via Tor circuit, or proxy timed out)\n",
                addr_buf);
        return -1;
    }
    if (reply_head[0] != 0x05 || reply_head[1] != 0x00)
    {
        fprintf(stderr, "[peer_connector] socks5: CONNECT to %s failed: %s (REP=0x%02x)\n", addr_buf,
                socks5_rep_to_string(reply_head[1]), reply_head[1]);
        return -1;
    }

    size_t bnd_addr_len;
    switch (reply_head[3])
    {
        case 0x01:
            bnd_addr_len = 4;
            break;
        case 0x04:
            bnd_addr_len = 16;
            break;
        case 0x03:
        {
            unsigned char len_byte;
            if (socks5_recv_all(sock, &len_byte, 1, timeout_sec) != 0)
            {
                fprintf(stderr, "[peer_connector] socks5: failed to read BND.ADDR length\n");
                return -1;
            }
            bnd_addr_len = len_byte;
            break;
        }
        default:
            fprintf(stderr, "[peer_connector] socks5: unsupported BND.ADDR type 0x%02x in reply\n",
                    reply_head[3]);
            return -1;
    }
    unsigned char discard[256];
    if (socks5_recv_all(sock, discard, bnd_addr_len + 2, timeout_sec) != 0)
    {
        fprintf(stderr, "[peer_connector] socks5: failed to read BND.ADDR/BND.PORT\n");
        return -1; /* BND.ADDR + BND.PORT。値自体は使わない */
    }
    return 0;
}

/*
 * socks_proxyが有効ならproxy経由でSOCKS5 CONNECTして接続し、そうでなければ従来通り直結する。
 * 戻り値はconnect_with_timeoutと同じ(成功時fd、失敗時-1)。
 */
static int open_peer_connection(const char *ip, int port, int timeout_sec,
                                 const struct bm_socks_proxy_config *socks_proxy)
{
    if (socks_proxy != NULL && socks_proxy->enabled)
    {
        int sock = connect_with_timeout(socks_proxy->host, socks_proxy->port, timeout_sec);
        if (sock < 0)
        {
            char proxy_addr_buf[64];
            bm_network_format_host_port(socks_proxy->host, socks_proxy->port, proxy_addr_buf,
                                         sizeof(proxy_addr_buf));
            fprintf(stderr, "[peer_connector] socks5: failed to reach proxy %s (is Tor/the proxy "
                            "running?)\n",
                    proxy_addr_buf);
            return -1;
        }
        if (socks5_connect(sock, ip, port, SOCKS5_HANDSHAKE_TIMEOUT_SEC) != 0)
        {
            close(sock);
            return -1;
        }
        return sock;
    }
    return connect_with_timeout(ip, port, timeout_sec);
}

int bm_peer_connector_connect_initial(const struct bm_peer_connector_config *config)
{
    /* §11 peers.dbの低rating/古いノードのクリーンアップ。seed_bootstrapより前に呼ぶことで、
     * クリーンアップの結果hostsテーブルが完全に空になった場合でも同じ呼び出し内で
     * 既定シードが再投入される(bm_peer_manager_seed_bootstrapはテーブルが空の時のみ
     * 動作するため) */
    int cleaned = bm_peer_manager_cleanup(config->peers_db, (int64_t)time(NULL));
    if (cleaned > 0)
    {
        fprintf(stderr, "[peer_connector] cleaned up %d stale/low-rating peer(s) from peers.db\n", cleaned);
    }

    bm_peer_manager_seed_bootstrap(config->peers_db, config->testnet);

    /* §11 設定変更の動的リロード: 呼ばれるたびconfig.dbから読み直す(スナップショットを
     * 保持しない)ことで、setSocksProxy APIでの変更がdaemon再起動なしで次回呼び出し
     * (=次の再接続サイクル、既定30秒間隔)から反映されるようにする */
    struct bm_socks_proxy_config socks_proxy;
    memset(&socks_proxy, 0, sizeof(socks_proxy));
    if (config->config_db != NULL)
    {
        bm_config_store_get_socks_proxy(config->config_db, &socks_proxy);
    }

    size_t already_connected = config->registry != NULL ? bm_peer_registry_count(config->registry) : 0;
    if ((int)already_connected >= config->max_outbound)
    {
        return 0;
    }
    int want = config->max_outbound - (int)already_connected;

    struct bm_peer_entry candidates[MAX_CANDIDATES];
    int candidate_count = 0;
    if (bm_peer_manager_list_top(config->peers_db, 1, candidates, MAX_CANDIDATES, &candidate_count) != 0)
    {
        return -1;
    }

    int connected = 0;
    for (int i = 0; i < candidate_count && connected < want; i++)
    {
        if (config->registry != NULL
            && bm_peer_registry_has_peer(config->registry, candidates[i].ip_address, candidates[i].port))
        {
            continue; /* 既に接続済みの相手には二重接続しない */
        }

        char addr_buf[64];
        bm_network_format_host_port(candidates[i].ip_address, candidates[i].port, addr_buf, sizeof(addr_buf));

        fprintf(stderr, "[peer_connector] connecting to %s%s...\n", addr_buf,
                socks_proxy.enabled ? " (via SOCKS5)" : "");
        int sock = open_peer_connection(candidates[i].ip_address, candidates[i].port, CONNECT_TIMEOUT_SEC,
                                         &socks_proxy);
        if (sock < 0)
        {
            fprintf(stderr, "[peer_connector] failed to connect to %s\n", addr_buf);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sock);
        if (conn == NULL)
        {
            fprintf(stderr, "[peer_connector] bm_fd_data_new failed for %s\n", addr_buf);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }
        /* §11 2026-08-22発覚のバグ修正: SOCKS5(Tor)経由の場合、conn->peer_addr(getpeername)は
         * プロキシ自身のアドレスになりpeer_manager.cのrating更新に使えない。ここで選んだ
         * 本来の接続先(candidates[i])を明示的に控えておき、network.c/object_sync.cの
         * rating記録処理がこちらを優先して使うようにする(network.h参照)。 */
        strncpy(conn->logical_peer_ip, candidates[i].ip_address, sizeof(conn->logical_peer_ip) - 1);
        conn->logical_peer_port = candidates[i].port;

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = conn;
        if (epoll_ctl(config->epfd, EPOLL_CTL_ADD, sock, &ev) != 0)
        {
            perror("[peer_connector] epoll_ctl");
            bm_fd_data_free(conn);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        if (bm_post_version(sock, config->user_agent, 3, &conn->peer_addr, &conn->local_addr) != 0)
        {
            fprintf(stderr, "[peer_connector] failed to send version to %s\n", addr_buf);
            epoll_ctl(config->epfd, EPOLL_CTL_DEL, sock, NULL);
            bm_fd_data_free(conn);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        if (config->registry != NULL)
        {
            bm_peer_registry_add(config->registry, conn);
        }
        /* §11 2026-08-22発覚のバグ修正: ここではsuccessを記録しない。以前はTCP接続+自分の
         * version送信が成功しただけでrating+0.1していたが、これは相手が実際に応答したかとは
         * 無関係な「自分側の送信が成功した」という弱い基準で、「繋がるが直後に相手から切断
         * される」peerでも毎サイクル必ず成功扱いになってしまっていた。infra/network.cの
         * bm_network_epoll_threadが切断時にfailure(-0.1)を記録するようになった今、この
         * success(+0.1)が毎サイクル打ち消してしまい、ratingが永久に上限1.0へ張り付いたまま
         * 抜け出せないバグを引き起こしていた(実際に9700行超のログ中3474回、同じ死んだpeerに
         * 接続し続けていたのを確認済み)。successの記録はinfra/object_sync.cのversion/verack
         * 受信時点(=相手が実際に応答した確かな証拠が得られた時点)へ移した。 */

        fprintf(stderr, "[peer_connector] connected to %s, version sent\n", addr_buf);
        connected++;
    }

    return connected;
}

#define RECONNECT_INTERVAL_SECONDS 30
#define STOP_POLL_INTERVAL_SECONDS 1

void *bm_peer_connector_thread(void *arg)
{
    struct bm_peer_connector_thread_args *args = arg;

    while (*args->stop_flag == 0)
    {
        int connected = bm_peer_connector_connect_initial(&args->config);
        if (connected > 0)
        {
            fprintf(stderr, "[peer_connector] %d new outbound connection(s) established\n", connected);
        }

        for (int waited = 0; waited < RECONNECT_INTERVAL_SECONDS && *args->stop_flag == 0; waited++)
        {
            /* §9 Dandelion++ Stage 2: 専用スレッドを新設せず、この既存の1秒間隔ポーリング
             * ループに相乗りさせる(DESIGN.md §9.2で「実装着手時に判断する」としていた点、
             * PyBitmessageのInvThread.expire()相当の頻度に合わせた)。registryが無ければ
             * (テスト等)何もしない。bm_dandelion_maybe_reshuffleは内部で10分間隔かどうかを
             * 判定するため、1秒ごとに呼んでも大半は即returnするだけで軽い。 */
            if (args->config.registry != NULL)
            {
                int64_t now = (int64_t)time(NULL);
                bm_dandelion_maybe_reshuffle(args->config.registry, now);
                bm_dandelion_expire_and_refluff(args->config.registry, now);
            }
            sleep(STOP_POLL_INTERVAL_SECONDS);
        }
    }

    free(args);
    return NULL;
}
