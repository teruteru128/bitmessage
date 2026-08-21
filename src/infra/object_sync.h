#ifndef BM_INFRA_OBJECT_SYNC_H
#define BM_INFRA_OBJECT_SYNC_H

/*
 * DESIGN.md §1.1 object_sync_thread(実質的にはcommand_worker_threadの本体も兼ねる)。
 * network_epoll_threadのbm_command_handler_fnとして使う。version/pingはinfra/network.cの
 * default_dispatchと同等の最小応答、addr/inv/getdata/objectを実際に処理する:
 *   - addr受信: 教えられたホストをpeers.db(peer_manager.c)へ登録する(§11)。既存行は
 *     services/last_seenのみ更新しratingは変更しない(接続実績で積み上げたratingを、
 *     単なる伝聞情報で上書きしないため)。DoS対策としてinv同様1メッセージ50000件を上限とする
 *   - inv受信: 未所持hashについてgetdataを送り返す
 *   - getdata受信: object_pool.dbにあれば同じ接続へobjectを返す
 *   - object受信: 期限切れ・ネットワーク既定の最低難易度(1000,1000)未満のPoWを即座に
 *     拒否した上で、重複排除してobject_pool.dbへ保存し、
 *       - type=msgならtrial_decrypt(core/trial_decrypt.c)を試み、成功したらinboxへ、
 *         埋め込みack_payloadがあれば検証してobject_pool.dbへ登録する(§5.5)
 *       - type=pubkey(version 2/3)ならpubkey_cache(core/pubkey_cache.c)へ登録を試みる。
 *         version 4は「誰宛の候補か」が必要なため、自分がgetpubkeyを発行してpending登録して
 *         いる宛先(identity.dbのpubkey_requestsテーブル)を候補として順に試す(§11)
 *       - type=getpubkeyなら、要求されているripe/tagがkeyringでunlock済みの自分のアドレス
 *         宛かどうか判定し、該当すれば自分のpubkeyオブジェクトを組み立てて応答する(§11、
 *         unlockされていないアドレスへの要求には応答できない)
 *       - type=broadcastなら、messages.dbのsubscriptions(購読先、§5.4)に登録されている
 *         アドレスを候補として順に復号を試み、成功したらinboxへ保存する
 *         (core/broadcast_decrypt.c、成功した時点で打ち切る)
 *       - どのtypeでもsent.ack_dataとの突合せ(§5.5のack検知)を試みる
 *       - 新規に取り込んだobject(受信msgそのもの、埋め込みackの両方)はpeer_registry経由で
 *         受信元コネクション以外の接続中peerへinv broadcastする。自分が新たに作った
 *         object(getpubkeyへの自応答)は除外無しで全peerへbroadcastする
 *   期限切れobjectのGCも間引きながら実行する(bm_object_sync_gcで直接呼ぶことも可能)。
 *   再送(resend)チェックも間引きながら実行する(§11、bm_object_sync_check_resendsで直接
 *   呼ぶことも可能): messages.dbのsentテーブルでack未着かつnext_resend_time経過・
 *   resend_count上限未満の行をbm_send_pipeline_send_message(core/send_pipeline.c)で
 *   再送する(reuse_msg_idに既存msg_idを渡すことで同じsent行を更新、ack_dataは新しく
 *   生成し直される)。生成されたobjectはobject_pool.dbへ挿入しpeer_registryで全peerへ
 *   broadcastする(自分が新たに作ったobjectなのでgetpubkey自応答等と同じ扱い)。
 *
 * また、core/api_server.cのsendMessageが生成したobject(自分が送信したmsg)、およびpubkey_cache
 * 未登録の宛先へ送ろうとした際に自動発行するgetpubkey要求は、bm_object_sync_broadcast_thread
 * (下記)が別途broadcast_queueから受け取ってobject_pool.dbへ挿入・broadcastする(core層は
 * infra層のpeer_registryを直接呼べないため、common層のbm_broadcast_item経由でqueue越しに
 * 受け渡す設計、DESIGN.md §1.2参照)。
 *
 * v1スコープ外(既知のTODO、DESIGN.md §11参照):
 *   - getpubkey応答のスパム対策(同じ宛先への短時間の連続要求に対する応答側スロットリング。
 *     PoW検証自体はあるので無償のspamは防げるが、正規のPoWを払われた場合の対策は無い)
 *   - addrで教えられたホストのフィルタリング(private/loopbackアドレス除外等)は未実装。
 *     不正確な情報が紛れ込んでもconnect失敗時にratingが下がるだけなので実害は小さい
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "../common/broadcast_item.h"
#include "../common/queue.h"
#include "../core/keyring.h"
#include "network.h"
#include "peer_registry.h"

struct bm_object_sync_ctx
{
    sqlite3 *object_pool_db;
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    sqlite3 *peers_db; /* NULL可(未使用ならaddr永続化をスキップ) */
    bm_keyring_t *keyring;
    struct bm_peer_registry *registry; /* NULL可(未使用ならinv broadcastをスキップ) */
    time_t last_gc; /* GC間引き用。network_epoll_threadという単一スレッドからのみ呼ばれる
                      * 前提で排他制御はしない */
    time_t last_resend_check; /* §11再送チェックの間引き用。last_gcと同じ理由で排他制御はしない */
};

void bm_object_sync_ctx_init(struct bm_object_sync_ctx *ctx, sqlite3 *object_pool_db,
                              sqlite3 *identity_db, sqlite3 *messages_db, sqlite3 *peers_db,
                              bm_keyring_t *keyring, struct bm_peer_registry *registry);

/* bm_command_handler_fn互換。user_dataにstruct bm_object_sync_ctx*を渡すこと */
void bm_object_sync_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data);

/* 期限切れobjectを削除する(object_store.cのdelete_expiredを呼ぶだけ)。削除件数を返す。
 * dispatch内部でも間引きながら呼ばれるが、テストや明示的なメンテナンス用に直接呼べる */
int bm_object_sync_gc(struct bm_object_sync_ctx *ctx, int64_t now);

/*
 * §11再送ロジック: ack未着のままnext_resend_timeを過ぎ、resend_count上限未満のsent行を
 * bm_send_pipeline_send_message(既存msg_idを再利用)で再送し、object_pool.dbへ挿入・
 * peer_registryでbroadcastする。dispatch内部でも間引きながら呼ばれるが、テストや
 * 明示的なメンテナンス用に直接呼べる。処理した(再送を試みた)件数を返す。
 */
int bm_object_sync_check_resends(struct bm_object_sync_ctx *ctx, int64_t now);

/*
 * broadcast_queueの消費ループ(pthread_createのarg用にmallocして渡す想定、main.c参照)。
 * core/api_server.cのsendMessageがpushしたbm_broadcast_item(§1.2)をpopし、object_pool.dbへ
 * 挿入した上でpeer_registry経由で全接続peer(除外無し)へinv broadcastする。既知object(重複)
 * ならbroadcastしない。itemとitem->objectの所有権を受け取り、処理後に解放する。
 * queueがbm_queue_shutdownされたら関数を抜ける(argも道連れで解放する)。
 */
struct bm_broadcast_thread_args
{
    struct bm_object_sync_ctx *ctx;
    bm_queue_t *queue;
};
void *bm_object_sync_broadcast_thread(void *arg);

#endif /* BM_INFRA_OBJECT_SYNC_H */
