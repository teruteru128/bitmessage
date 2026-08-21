#include "network.h"

#include "peer_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define INIT_RECV_BUFFER_SIZE 131072
#define MAX_EPOLL_EVENTS 64

/* §11 DoS上限の見直し。受信バッファのdoubling自体にも上限を設ける(bm_parse_messageの
 * BM_MAX_MESSAGE_LENGTHチェックと二重の防御。複数メッセージがバッファ内に連続で溜まる
 * ケースも考慮し、単一メッセージの上限より少し余裕を持たせる)。 */
#define MAX_RECV_BUFFER_SIZE (2u * (BM_MESSAGE_HEADER_SIZE + BM_MAX_MESSAGE_LENGTH))

struct bm_fd_data *bm_fd_data_new(enum bm_fd_type type, int fd)
{
    struct bm_fd_data *data = calloc(1, sizeof(struct bm_fd_data));
    if (data == NULL)
    {
        return NULL;
    }
    data->type = type;
    data->fd = fd;
    data->size = INIT_RECV_BUFFER_SIZE;
    data->length = 0;

    data->local_len = sizeof(data->local_addr);
    if (getsockname(fd, (struct sockaddr *)&data->local_addr, &data->local_len) == -1)
    {
        perror("getsockname");
        free(data);
        return NULL;
    }
    /* §11 listenソケット自体には相手(peer)が存在しないためgetpeername()は常に失敗する
     * (ENOTCONN)。BM_FD_LISTEN_SOCKETの場合はpeer_addrを空のまま(未使用)にしてスキップする */
    if (type != BM_FD_LISTEN_SOCKET)
    {
        data->peer_len = sizeof(data->peer_addr);
        if (getpeername(fd, (struct sockaddr *)&data->peer_addr, &data->peer_len) == -1)
        {
            perror("getpeername");
            free(data);
            return NULL;
        }
    }

    data->recv_buffer = malloc(INIT_RECV_BUFFER_SIZE);
    if (data->recv_buffer == NULL)
    {
        free(data);
        return NULL;
    }
    return data;
}

void bm_fd_data_free(struct bm_fd_data *data)
{
    if (data == NULL)
    {
        return;
    }
    free(data->recv_buffer);
    free(data);
}

int bm_network_listen(const char *bind_address, int port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(bind_address, port_str, &hints, &res) != 0)
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
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (bind(sock, p->ai_addr, p->ai_addrlen) == 0 && listen(sock, 16) == 0)
        {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0)
    {
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    return sock;
}

int bm_network_write_all(int fd, const unsigned char *data, size_t len, int timeout_sec)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = write(fd, data + sent, len - sent);
        if (n > 0)
        {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0)
            {
                return -1; /* タイムアウトまたはselect()自体のエラー */
            }
            continue;
        }
        return -1; /* 相手が切断した(n==0)、またはその他のエラー */
    }
    return 0;
}

static int send_header_only(int fd, const char *command)
{
    size_t len = 0;
    unsigned char *packet = bm_create_packet(command, NULL, 0, &len);
    int rc = bm_network_write_all(fd, packet, len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS);
    free(packet);
    return rc;
}

int bm_reply_verack(struct bm_fd_data *conn)
{
    return send_header_only(conn->fd, "verack");
}

int bm_reply_pong(struct bm_fd_data *conn)
{
    return send_header_only(conn->fd, "pong");
}

int bm_post_version(int sock, const char *user_agent_str, int version,
                     const struct sockaddr_storage *peer_addr,
                     const struct sockaddr_storage *local_addr)
{
    size_t len = 0;
    unsigned char *msg = bm_new_version_message(user_agent_str, version, peer_addr, local_addr, &len);
    int rc = bm_network_write_all(sock, msg, len, BM_NETWORK_WRITE_TIMEOUT_LONG_SECONDS);
    free(msg);
    return rc;
}

/* 既定のコマンドディスパッチ。DESIGN.md §1.1 command_worker_thread の初版実装。
 * object/getdataはTODO(§5, §9): infra/object.c 実装後にキュー経由へ差し替える。 */
static void default_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data)
{
    (void)user_data;
    char command[13] = {0};
    memcpy(command, msg->command, 12);

    if (strncmp(msg->command, "version", 12) == 0)
    {
        struct bm_version_message ver;
        bm_parse_version_message(msg->payload, msg->length, &ver);
        fprintf(stderr, "[network] version: v=%u services=%" PRIu64 " ua=%s\n",
                ver.version, ver.services, ver.user_agent);
        bm_free_version_message(&ver);
        if (bm_reply_verack(conn) != 0)
        {
            fprintf(stderr, "[network] failed to reply verack\n");
        }
    }
    else if (strncmp(msg->command, "verack", 12) == 0)
    {
        fprintf(stderr, "[network] verack received\n");
    }
    else if (strncmp(msg->command, "ping", 12) == 0)
    {
        if (bm_reply_pong(conn) != 0)
        {
            fprintf(stderr, "[network] failed to reply pong\n");
        }
    }
    else if (strncmp(msg->command, "addr", 12) == 0)
    {
        struct bm_addr_message addr_msg;
        if (bm_parse_addr_message(msg->payload, msg->length, &addr_msg) == 0)
        {
            fprintf(stderr, "[network] addr: %" PRIu64 " entries (TODO: peer_manager未実装)\n", addr_msg.count);
            bm_free_addr_message(&addr_msg);
        }
    }
    else if (strncmp(msg->command, "inv", 12) == 0)
    {
        struct bm_inventory_message inv_msg;
        if (bm_parse_inventory_message(msg->payload, msg->length, &inv_msg) == 0)
        {
            fprintf(stderr, "[network] inv: %" PRIu64 " items (TODO: object_store未実装、getdata未送信)\n", inv_msg.count);
            bm_free_inventory_message(&inv_msg);
        }
    }
    else if (strncmp(msg->command, "object", 12) == 0)
    {
        fprintf(stderr, "[network] object received, %u bytes (TODO: object_store/decrypt_worker未実装)\n", msg->length);
    }
    else
    {
        fprintf(stderr, "[network] unhandled command: %s\n", command);
    }
}

int bm_network_handle_readable(struct bm_fd_data *conn, bm_command_handler_fn handler, void *user_data)
{
    if (handler == NULL)
    {
        handler = default_dispatch;
    }

    unsigned char buf[INIT_RECV_BUFFER_SIZE];
    for (;;)
    {
        ssize_t n = read(conn->fd, buf, sizeof(buf));
        if (n == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            perror("read");
            return -1;
        }
        if (n == 0)
        {
            return 1; /* peer closed */
        }
        if (conn->length + (size_t)n > conn->size)
        {
            size_t new_size = conn->size;
            while (conn->length + (size_t)n > new_size)
            {
                new_size *= 2;
            }
            if (new_size > MAX_RECV_BUFFER_SIZE)
            {
                /* §11 単一メッセージの上限(BM_MAX_MESSAGE_LENGTH)は通常bm_parse_messageの
                 * BM_PARSE_MESSAGE_TOO_LARGEで先に検知されるが、それより前にここへ到達する
                 * ケース(単一read()で大量データが一度に届く等)に備えた二重の防御 */
                fprintf(stderr, "[network] recv buffer would exceed %u bytes, dropping connection\n",
                        MAX_RECV_BUFFER_SIZE);
                return -1;
            }
            unsigned char *grown = realloc(conn->recv_buffer, new_size);
            if (grown == NULL)
            {
                return -1;
            }
            conn->recv_buffer = grown;
            conn->size = new_size;
        }
        memcpy(conn->recv_buffer + conn->length, buf, (size_t)n);
        conn->length += (size_t)n;
    }

    for (;;)
    {
        struct bm_message *msg = NULL;
        size_t consumed = 0;
        enum bm_parse_result result = bm_parse_message(conn->recv_buffer, conn->length, &msg, &consumed);

        if (result == BM_PARSE_INCOMPLETE)
        {
            break;
        }
        if (result == BM_PARSE_BAD_CHECKSUM)
        {
            fprintf(stderr, "[network] checksum mismatch, dropping %zu bytes\n", consumed);
            memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
            conn->length -= consumed;
            continue;
        }
        if (result == BM_PARSE_BAD_MAGIC)
        {
            /* mainnet/testnet取り違え等。1byteずつresyncを試みる(ログは出さない、
             * ノイズの多いストリームだと大量に出て邪魔になるため) */
            memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
            conn->length -= consumed;
            continue;
        }
        if (result == BM_PARSE_MESSAGE_TOO_LARGE)
        {
            /* §11 巨大なlengthを申告された。resyncを試みるコスト自体もDoSになりうるため、
             * 即座に接続を切断する(呼び出し元でclose・registry除去される) */
            fprintf(stderr, "[network] declared message length exceeds %u bytes, dropping connection\n",
                    BM_MAX_MESSAGE_LENGTH);
            return -1;
        }

        /* BM_PARSE_OK */
        memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
        conn->length -= consumed;
        handler(conn, msg, user_data);
        bm_free_message(msg);
    }

    return 0;
}

/*
 * §11 inbound接続(Tor hidden service)対応。listenソケットがreadable(=accept可能)に
 * なった際に呼ぶ。EAGAINになるまで(=溜まっている分を全部)accept()し、各接続を
 * BM_FD_SERVER_SOCKETとしてepoll登録・registry登録する。inbound接続はこの時点では
 * まだ相手のversionを受け取っていないため、自分からは何も送らずに待つ(相手からの
 * versionを受けてobject_sync.cが自分のversionを送り返す、object_sync_dispatch参照)。
 */
static void handle_accept(struct bm_epoll_thread_args *args, struct bm_fd_data *listener)
{
    for (;;)
    {
        int client_fd = accept(listener->fd, NULL, NULL);
        if (client_fd < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
                perror("[network] accept");
            }
            break;
        }

        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK); /* accept()されたfdはlistenソケットの
                                                          * O_NONBLOCKを継承しないため明示的に設定 */

        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_SERVER_SOCKET, client_fd);
        if (conn == NULL)
        {
            close(client_fd);
            continue;
        }

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = conn;
        if (epoll_ctl(args->epfd, EPOLL_CTL_ADD, client_fd, &ev) != 0)
        {
            perror("[network] epoll_ctl (inbound accept)");
            bm_fd_data_free(conn);
            close(client_fd);
            continue;
        }
        if (args->registry != NULL)
        {
            bm_peer_registry_add(args->registry, conn);
        }
        fprintf(stderr, "[network] accepted inbound connection (fd=%d)\n", client_fd);
    }
}

void *bm_network_epoll_thread(void *arg)
{
    struct bm_epoll_thread_args *args = arg;
    struct epoll_event events[MAX_EPOLL_EVENTS];

    for (;;)
    {
        int nfds = epoll_wait(args->epfd, events, MAX_EPOLL_EVENTS, -1);
        if (nfds == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < nfds; i++)
        {
            struct bm_fd_data *conn = events[i].data.ptr;
            if (conn->type == BM_FD_LISTEN_SOCKET)
            {
                handle_accept(args, conn);
                continue;
            }
            int rc = bm_network_handle_readable(conn, args->handler, args->user_data);
            if (rc != 0)
            {
                if (args->registry != NULL)
                {
                    bm_peer_registry_remove(args->registry, conn);
                }
                epoll_ctl(args->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
                close(conn->fd);
                bm_fd_data_free(conn);
            }
        }
    }
    free(args);
    return NULL;
}
