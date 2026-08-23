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
 * §11 2026-08-23: 登録済みの全接続についてcallbackを呼ぶ汎用イテレータ(network.cの
 * アイドル/ハンドシェイクタイムアウト走査で使う)。ロックを持っている間にconnポインタの
 * スナップショットだけ取り、callback自体はロック解放後に呼ぶ(callbackが
 * bm_peer_registry_removeを呼んでも同じmutexの再帰ロックにならない)。
 */
void bm_peer_registry_for_each(struct bm_peer_registry *reg, void (*callback)(struct bm_fd_data *conn, void *user_data),
                                void *user_data);

/*
 * 現在接続中の全peer(exceptが非NULLならそれを除く)へ、hashesを送る。接続ごと・hashごとに
 * infra/object.hのbm_decide_propagation(§9 Dandelion++の差し込み点)を呼び、FLUFF判定
 * されたhashは通常のinv、STEM判定されたhashはdinvとして送る(SKIP判定のhashはその接続へは
 * 送らない)。v1 Stage 1時点はbm_decide_propagationが常にFLUFFを返すダミーのため、
 * 送信内容・宛先は「全peerへinv」のまま変わらない。個々のwrite失敗は無視する
 * (接続の生死判定はnetwork_epoll_thread側のepoll_wait/readに任せ、ここでは能動的に
 * 切断しない)。
 */
void bm_peer_registry_broadcast_inv(struct bm_peer_registry *reg, const unsigned char (*hashes)[32],
                                     size_t count, const struct bm_fd_data *except);

/*
 * §9 Dandelion++ Stage 2: registryに登録済みの接続のうち、outbound(BM_FD_CLIENT_SOCKET)
 * かつBM_SERVICE_NODE_DANDELION(services、object_sync.cのversion受信時に記録)を
 * 立てているものから一様ランダムに1つ選び、そのip:portをout_ip/out_portへ書き込む
 * (dandelion.cのstem successor選定に使う)。該当する接続が1つも無ければ0を返す
 * (out_ip/out_portは変更しない)。見つかれば1。
 */
int bm_peer_registry_pick_random_dandelion_peer(struct bm_peer_registry *reg, char *out_ip, size_t out_ip_len,
                                                 int *out_port);

#endif /* BM_INFRA_PEER_REGISTRY_H */
