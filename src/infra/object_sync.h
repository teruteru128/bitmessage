#ifndef BM_INFRA_OBJECT_SYNC_H
#define BM_INFRA_OBJECT_SYNC_H

/*
 * DESIGN.md §1.1 object_sync_thread(実質的にはcommand_worker_threadの本体も兼ねる)。
 * network_epoll_threadのbm_command_handler_fnとして使う。version/verack/addr/pingは
 * infra/network.cのdefault_dispatchと同等の最小応答、inv/getdata/objectを実際に処理する:
 *   - inv受信: 未所持hashについてgetdataを送り返す
 *   - getdata受信: object_pool.dbにあれば同じ接続へobjectを返す
 *   - object受信: 重複排除してobject_pool.dbへ保存し、
 *       - type=msgならtrial_decrypt(core/trial_decrypt.c)を試み、成功したらinboxへ、
 *         埋め込みack_payloadがあれば検証してobject_pool.dbへ登録する(§5.5)
 *       - type=pubkey(version 2/3)ならpubkey_cache(core/pubkey_cache.c)へ登録を試みる
 *         (version 4は「誰宛の候補か」が必要なため、getpubkey自動化と合わせて別途TODO)
 *       - どのtypeでもsent.ack_dataとの突合せ(§5.5のack検知)を試みる
 *   期限切れobjectのGCも間引きながら実行する(bm_object_sync_gcで直接呼ぶことも可能)。
 *
 * v1スコープ外(既知のTODO、DESIGN.md §11参照):
 *   - 受信objectを他の接続中peerへ能動的にinv broadcastする処理(接続レジストリが必要)
 *   - addrのpeer_manager永続化
 *   - getpubkey受信時に自分のpubkeyで応答する処理
 *   - broadcast(type=3)の購読・復号
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "../core/keyring.h"
#include "network.h"

struct bm_object_sync_ctx
{
    sqlite3 *object_pool_db;
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    bm_keyring_t *keyring;
    time_t last_gc; /* GC間引き用。network_epoll_threadという単一スレッドからのみ呼ばれる
                      * 前提で排他制御はしない */
};

void bm_object_sync_ctx_init(struct bm_object_sync_ctx *ctx, sqlite3 *object_pool_db,
                              sqlite3 *identity_db, sqlite3 *messages_db, bm_keyring_t *keyring);

/* bm_command_handler_fn互換。user_dataにstruct bm_object_sync_ctx*を渡すこと */
void bm_object_sync_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data);

/* 期限切れobjectを削除する(object_store.cのdelete_expiredを呼ぶだけ)。削除件数を返す。
 * dispatch内部でも間引きながら呼ばれるが、テストや明示的なメンテナンス用に直接呼べる */
int bm_object_sync_gc(struct bm_object_sync_ctx *ctx, int64_t now);

#endif /* BM_INFRA_OBJECT_SYNC_H */
