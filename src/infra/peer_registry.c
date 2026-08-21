#include "peer_registry.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"

/* peer_addr(sockaddr_storage)を"ip:port"文字列にする。DNS引きはせず数値表記のみ */
static void format_peer_addr(const struct sockaddr_storage *addr, char *out, size_t out_len)
{
    char ip[INET6_ADDRSTRLEN] = {0};
    int port = 0;
    if (addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        port = ntohs(sin->sin_port);
    }
    else if (addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        port = ntohs(sin6->sin6_port);
    }
    snprintf(out, out_len, "%s:%d", ip, port);
}

void bm_peer_registry_init(struct bm_peer_registry *reg)
{
    pthread_mutex_init(&reg->lock, NULL);
    reg->conns = NULL;
    reg->count = 0;
    reg->capacity = 0;
}

void bm_peer_registry_destroy(struct bm_peer_registry *reg)
{
    pthread_mutex_destroy(&reg->lock);
    free(reg->conns);
    reg->conns = NULL;
    reg->count = 0;
    reg->capacity = 0;
}

void bm_peer_registry_add(struct bm_peer_registry *reg, struct bm_fd_data *conn)
{
    pthread_mutex_lock(&reg->lock);
    if (reg->count >= reg->capacity)
    {
        size_t new_cap = reg->capacity == 0 ? 8 : reg->capacity * 2;
        struct bm_fd_data **grown = realloc(reg->conns, sizeof(*grown) * new_cap);
        if (grown == NULL)
        {
            pthread_mutex_unlock(&reg->lock);
            return;
        }
        reg->conns = grown;
        reg->capacity = new_cap;
    }
    reg->conns[reg->count++] = conn;
    pthread_mutex_unlock(&reg->lock);
}

void bm_peer_registry_remove(struct bm_peer_registry *reg, struct bm_fd_data *conn)
{
    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        if (reg->conns[i] == conn)
        {
            reg->conns[i] = reg->conns[reg->count - 1];
            reg->count--;
            break;
        }
    }
    pthread_mutex_unlock(&reg->lock);
}

size_t bm_peer_registry_count(struct bm_peer_registry *reg)
{
    pthread_mutex_lock(&reg->lock);
    size_t count = reg->count;
    pthread_mutex_unlock(&reg->lock);
    return count;
}

int bm_peer_registry_has_peer(struct bm_peer_registry *reg, const char *ip, int port)
{
    char target[INET6_ADDRSTRLEN + 8];
    snprintf(target, sizeof(target), "%s:%d", ip, port);

    pthread_mutex_lock(&reg->lock);
    int found = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        char current[INET6_ADDRSTRLEN + 8];
        format_peer_addr(&reg->conns[i]->peer_addr, current, sizeof(current));
        if (strcmp(current, target) == 0)
        {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&reg->lock);
    return found;
}

void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except)
{
    if (count == 0)
    {
        return;
    }

    size_t packet_len = 0;
    unsigned char *packet = bm_create_inventory_message("inv", hashes, count, &packet_len);
    if (packet == NULL)
    {
        return;
    }

    /* §11 部分書き込み対策: bm_network_write_all は書き込み可能になるまで(最大
     * BM_NETWORK_WRITE_TIMEOUT_SECONDS)select()で待つことがあるため、reg->lock を
     * 持ったまま呼ぶと1本の詰まったpeerが他スレッドのregistry操作を長時間ブロック
     * しかねない。かといってfd番号だけコピーしてロックを解放すると、書き込み前に
     * 元の接続がepoll thread側でclose()されfd番号が別の用途に再利用された場合に
     * 誤った相手へ書き込んでしまう恐れがある。dup()した複製fdはclose(conn->fd)されても
     * 無効化されず同じsocketを指し続けるため、ロックを持っている間にdup()するだけで
     * この競合を避けつつロックを早期に解放できる */
    int *fds = reg->count > 0 ? malloc(sizeof(int) * reg->count) : NULL;
    size_t fd_count = 0;

    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn == except)
        {
            continue;
        }
        int dup_fd = dup(conn->fd);
        if (dup_fd >= 0)
        {
            fds[fd_count++] = dup_fd;
        }
    }
    pthread_mutex_unlock(&reg->lock);

    for (size_t i = 0; i < fd_count; i++)
    {
        if (bm_network_write_all(fds[i], packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) != 0)
        {
            fprintf(stderr, "[peer_registry] failed to send inv to fd=%d\n", fds[i]);
        }
        close(fds[i]);
    }
    free(fds);

    free(packet);
}
