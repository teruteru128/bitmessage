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

#include "network.h"
#include "peer_manager.h"
#include "peer_registry.h"

#define MAX_CANDIDATES 32
#define CONNECT_TIMEOUT_SEC 5

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

        fprintf(stderr, "[peer_connector] connecting to %s:%d...\n",
                candidates[i].ip_address, candidates[i].port);
        int sock = connect_with_timeout(candidates[i].ip_address, candidates[i].port, CONNECT_TIMEOUT_SEC);
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
