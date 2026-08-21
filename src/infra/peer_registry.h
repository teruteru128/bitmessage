#ifndef BM_INFRA_PEER_REGISTRY_H
#define BM_INFRA_PEER_REGISTRY_H

/*
 * 現在epollに登録されている接続(bm_fd_data*)の一覧。object_sync_threadが「新しく手に入れた
 * objectを他の接続中peerへinvで知らせる」ために使う(DESIGN.md §11「他peerへのinv broadcast」)。
 * 接続の追加(infra/peer_connector.c)・削除(infra/network.cのepoll_waitループ)は将来的に
 * 別スレッドから行われる可能性がある(peer_connector_threadの常駐化、TODO)ためmutexで保護する。
 */

#include <pthread.h>
#include <stddef.h>

#include "network.h"

struct bm_peer_registry
{
    pthread_mutex_t lock;
    struct bm_fd_data **conns; /* malloc済み配列、各要素は借用ポインタ(所有権は持たない) */
    size_t count;
    size_t capacity;
};

void bm_peer_registry_init(struct bm_peer_registry *reg);
void bm_peer_registry_destroy(struct bm_peer_registry *reg);

void bm_peer_registry_add(struct bm_peer_registry *reg, struct bm_fd_data *conn);
/* connが登録されていなくても何もしない(既に削除済み等) */
void bm_peer_registry_remove(struct bm_peer_registry *reg, struct bm_fd_data *conn);

/* 現在の登録数(peer_connectorが接続数維持の判断に使う) */
size_t bm_peer_registry_count(struct bm_peer_registry *reg);

/* ip:portが既に登録済みの接続の中にあるか(peer_connectorが同じ相手への二重接続を避けるため) */
int bm_peer_registry_has_peer(struct bm_peer_registry *reg, const char *ip, int port);

/*
 * 現在接続中の全peer(exceptが非NULLならそれを除く)へ、hashesをinvとして送る。
 * 個々のwrite失敗は無視する(接続の生死判定はnetwork_epoll_thread側のepoll_wait/readに任せ、
 * ここでは能動的に切断しない)。
 */
void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except);

#endif /* BM_INFRA_PEER_REGISTRY_H */
