#include "network.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#define INIT_RECV_BUFFER_SIZE 131072
#define MAX_EPOLL_EVENTS 64

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
    data->peer_len = sizeof(data->peer_addr);
    if (getpeername(fd, (struct sockaddr *)&data->peer_addr, &data->peer_len) == -1)
    {
        perror("getpeername");
        free(data);
        return NULL;
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

static int send_header_only(int fd, const char *command)
{
    size_t len = 0;
    unsigned char *packet = bm_create_packet(command, NULL, 0, &len);
    ssize_t w = write(fd, packet, len);
    free(packet);
    return (w == (ssize_t)len) ? 0 : -1;
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
    ssize_t w = write(sock, msg, len);
    free(msg);
    return (w == (ssize_t)len) ? 0 : -1;
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

        /* BM_PARSE_OK */
        memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
        conn->length -= consumed;
        handler(conn, msg, user_data);
        bm_free_message(msg);
    }

    return 0;
}

struct bm_epoll_thread_args
{
    int epfd;
    bm_command_handler_fn handler;
    void *user_data;
};

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
            int rc = bm_network_handle_readable(conn, args->handler, args->user_data);
            if (rc != 0)
            {
                epoll_ctl(args->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
                close(conn->fd);
                bm_fd_data_free(conn);
            }
        }
    }
    free(args);
    return NULL;
}
