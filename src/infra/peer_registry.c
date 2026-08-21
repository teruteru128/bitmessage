#include "peer_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "protocol.h"

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

    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn == except)
        {
            continue;
        }
        if (write(conn->fd, packet, packet_len) != (ssize_t)packet_len)
        {
            fprintf(stderr, "[peer_registry] failed to send inv to fd=%d\n", conn->fd);
        }
    }
    pthread_mutex_unlock(&reg->lock);

    free(packet);
}
