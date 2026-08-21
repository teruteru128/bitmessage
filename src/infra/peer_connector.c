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
#include <unistd.h>

#include "../core/config_store.h"
#include "network.h"
#include "peer_manager.h"
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

/*
 * SOCKS5(RFC1928)のno-auth CONNECTハンドシェイク。sockは既にproxyへ接続済み(O_NONBLOCK)で
 * あること。宛先は常にドメイン名形式(ATYP=0x03)で送る: dest_hostが数字IPの文字列であっても
 * Tor等のSOCKS5サーバーは正しく扱う(ローカルでDNS解決せずそのままCONNECT先として使うため、
 * 将来onionアドレスに対応する際もこの経路がそのまま使える)。成功時0
 */
static int socks5_connect(int sock, const char *dest_host, int dest_port, int timeout_sec)
{
    size_t host_len = strlen(dest_host);
    if (host_len == 0 || host_len > 255)
    {
        return -1;
    }

    unsigned char greeting[3] = {0x05, 0x01, 0x00}; /* version=5, 1 method, no-auth */
    if (socks5_send_all(sock, greeting, sizeof(greeting), timeout_sec) != 0)
    {
        return -1;
    }
    unsigned char method_resp[2];
    if (socks5_recv_all(sock, method_resp, sizeof(method_resp), timeout_sec) != 0)
    {
        return -1;
    }
    if (method_resp[0] != 0x05 || method_resp[1] != 0x00)
    {
        return -1; /* no-auth非対応、または想定外バージョン */
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
        return -1;
    }

    unsigned char reply_head[4];
    if (socks5_recv_all(sock, reply_head, sizeof(reply_head), timeout_sec) != 0)
    {
        return -1;
    }
    if (reply_head[0] != 0x05 || reply_head[1] != 0x00)
    {
        return -1; /* REPが成功(0x00)以外 */
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
                return -1;
            }
            bnd_addr_len = len_byte;
            break;
        }
        default:
            return -1;
    }
    unsigned char discard[256];
    if (socks5_recv_all(sock, discard, bnd_addr_len + 2, timeout_sec) != 0)
    {
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
    bm_peer_manager_seed_bootstrap(config->peers_db, config->testnet);

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

        fprintf(stderr, "[peer_connector] connecting to %s:%d%s...\n",
                candidates[i].ip_address, candidates[i].port,
                (config->socks_proxy != NULL && config->socks_proxy->enabled) ? " (via SOCKS5)" : "");
        int sock = open_peer_connection(candidates[i].ip_address, candidates[i].port, CONNECT_TIMEOUT_SEC,
                                         config->socks_proxy);
        if (sock < 0)
        {
            fprintf(stderr, "[peer_connector] failed to connect to %s:%d\n",
                    candidates[i].ip_address, candidates[i].port);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sock);
        if (conn == NULL)
        {
            fprintf(stderr, "[peer_connector] bm_fd_data_new failed for %s:%d\n",
                    candidates[i].ip_address, candidates[i].port);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

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
            fprintf(stderr, "[peer_connector] failed to send version to %s:%d\n",
                    candidates[i].ip_address, candidates[i].port);
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
        bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 1);

        fprintf(stderr, "[peer_connector] connected to %s:%d, version sent\n",
                candidates[i].ip_address, candidates[i].port);
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
            sleep(STOP_POLL_INTERVAL_SECONDS);
        }
    }

    free(args);
    return NULL;
}
