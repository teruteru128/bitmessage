#include "peer_registry.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "object.h"
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

size_t bm_peer_registry_count(struct bm_peer_registry *reg)
{
    pthread_mutex_lock(&reg->lock);
    size_t count = reg->count;
    pthread_mutex_unlock(&reg->lock);
    return count;
}

int bm_peer_registry_has_peer(struct bm_peer_registry *reg, const char *ip, int port)
{
    pthread_mutex_lock(&reg->lock);
    int found = 0;
    for (size_t i = 0; i < reg->count; i++)
    {
        /* §11 2026-08-22発覚のバグ修正: 以前はreg->conns[i]->peer_addr(getpeername)を
         * そのまま比較していたが、SOCKS5(Tor)プロキシ経由の接続ではこれがプロキシ自身の
         * アドレス(例: 127.0.0.1:9050)になり、ipで渡される本来の候補アドレスとは
         * 絶対に一致しない。結果としてSOCKS5有効時は「既に接続済み」判定が常に偽になり、
         * peer_connector.cの二重接続防止(bm_peer_connector_connect_initial)が機能して
         * いなかった(rating調査で見つかった一連のバグと同じ根本原因)。
         * bm_network_resolve_peer_ip_port(logical_peer_ip優先、network.h参照)で解決した
         * ip:portと比較するよう修正した。 */
        char current_ip[INET6_ADDRSTRLEN];
        int current_port = 0;
        bm_network_resolve_peer_ip_port(reg->conns[i], current_ip, sizeof(current_ip), &current_port);
        if (current_port == port && strcmp(current_ip, ip) == 0)
        {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&reg->lock);
    return found;
}

/* §9 Dandelion++ Stage 1: dup()した接続1本ぶんの送信予定(bm_decide_propagationで
 * FLUFF判定されたhashだけに絞り込んだもの)。ロック解放後にまとめて書き込むための
 * 一時データ(既存のfd dup()方式と同じ理由、下記参照)。 */
struct pending_inv_send
{
    int fd;
    unsigned char (*hashes)[32];
    size_t count;
};

void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except)
{
    if (count == 0)
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
    struct pending_inv_send *pending = reg->count > 0 ? malloc(sizeof(*pending) * reg->count) : NULL;
    size_t pending_count = 0;

    pthread_mutex_lock(&reg->lock);
    for (size_t i = 0; i < reg->count; i++)
    {
        struct bm_fd_data *conn = reg->conns[i];
        if (conn == except)
        {
            continue;
        }

        /* §9 Dandelion++差し込み点(DESIGN.md §9.2「inv送信判断は必ずこの関数を経由させる」):
         * 接続ごと・hashごとにfluff/stem/skipを判断する。v1は常にFLUFFを返すダミーのため
         * 全hashが素通りし挙動は変わらない。stemはv1では発生しない(bm_decide_propagationの
         * stub参照)ため、このfluff broadcast(=全接続peerへの通常inv配信)にはFLUFFのhashだけ
         * を含める設計にしている。将来STEMを実際に返すようになったら、stem対象のhashは
         * このbroadcast関数とは別の、単一の子ピアだけへdinvを送る専用の送信経路で扱う想定。 */
        unsigned char (*filtered)[32] = malloc(sizeof(*filtered) * count);
        size_t filtered_count = 0;
        for (size_t h = 0; h < count; h++)
        {
            if (bm_decide_propagation(hashes[h], conn) == BM_PROPAGATE_FLUFF)
            {
                memcpy(filtered[filtered_count], hashes[h], 32);
                filtered_count++;
            }
        }

        if (filtered_count == 0)
        {
            free(filtered);
            continue;
        }

        int dup_fd = dup(conn->fd);
        if (dup_fd >= 0)
        {
            pending[pending_count].fd = dup_fd;
            pending[pending_count].hashes = filtered;
            pending[pending_count].count = filtered_count;
            pending_count++;
        }
        else
        {
            free(filtered);
        }
    }
    pthread_mutex_unlock(&reg->lock);

    for (size_t i = 0; i < pending_count; i++)
    {
        size_t packet_len = 0;
        unsigned char *packet =
            bm_create_inventory_message("inv", pending[i].hashes, pending[i].count, &packet_len);
        if (packet != NULL)
        {
            if (bm_network_write_all(pending[i].fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS)
                != 0)
            {
                fprintf(stderr, "[peer_registry] failed to send inv to fd=%d\n", pending[i].fd);
            }
            free(packet);
        }
        close(pending[i].fd);
        free(pending[i].hashes);
    }
    free(pending);
}
