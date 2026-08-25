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
    /* §11 inbound接続(Tor hidden service)対応。inbound(BM_FD_SERVER_SOCKET)接続からversionを
     * 受信した際、自分自身のversionを送り返すのに使う(outboundは接続直後にpeer_connector.cが
     * 既に送信済みのため送り返さない、object_sync.cのversion処理参照)。NULL可(その場合は
     * inbound接続でも自分のversionを送り返さない。テスト等outbound専用の用途向け)。 */
    const char *user_agent;
    time_t last_gc; /* GC間引き用。network_epoll_threadという単一スレッドからのみ呼ばれる
                      * 前提で排他制御はしない */
    time_t last_resend_check; /* §11再送チェックの間引き用。last_gcと同じ理由で排他制御はしない */
    /* §11 2026-08-24: onionpeer自己announceの定期再送間引き用。peer_connector_threadという
     * 単一スレッドからのみ呼ばれる前提で排他制御はしない(last_gc/last_resend_checkと同じ理由。
     * ただしそれらとは別のスレッドから触られるフィールドである点に注意)。 */
    time_t last_onion_announce;
};

void bm_object_sync_ctx_init(struct bm_object_sync_ctx *ctx, sqlite3 *object_pool_db,
                              sqlite3 *identity_db, sqlite3 *messages_db, sqlite3 *peers_db,
                              bm_keyring_t *keyring, struct bm_peer_registry *registry,
                              const char *user_agent);

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

/*
 * §11 outbound Tor経路の強化(送信側): 自分自身のonion hidden service情報をonionpeer object
 * (BM_OBJECT_ONIONPEER)として組み立て・PoWし、object_pool.dbへ登録した上でpeer_registry経由で
 * 全peer(除外無し、自分が新たに作った物なので他の自己生成object同様except=NULL)へbroadcast
 * する。main.cがTor ControlPort連携(Stage 2)でhidden serviceを作成した直後に1回呼ぶ想定。
 * onion_addressは"xxxx.onion"(v3、56文字+".onion")形式であること。stream=1(既定のmother
 * stream)で告知する。成功時0、onion_addressの形式が不正な場合のみ-1(PoW自体は必ず成功する)。
 *
 * §11 2026-08-24発覚のバグ修正: 以前はexpires_time計算に関数内部でtime(NULL)を直接呼んで
 * いたため、bm_object_sync_maybe_reannounce_onion_peer経由で同じ実時刻の1秒以内に2回呼ばれる
 * (テストのように短時間に連続して呼ぶ場合や、極端に短い間隔設定の場合)とexpires_timeを含む
 * payloadが完全に同一になり、PoWも決定的(nonceのブルートフォース探索、乱数ではない)なので
 * objectのhashまで一致してしまう。結果、2回目はbm_object_store_hasによる重複排除に引っかかり
 * announceされない(=定期再送が実際には効かない秒がある)、という意図しない挙動になっていた
 * (実際にtests/test_object_sync.cのシナリオ16で秒境界をまたぐかどうかに依存するflaky failure
 * として発覚)。CLAUDE.mdの「時刻は明示引数で受け取り、関数内部でtime(NULL)を直接呼ばない」
 * 方針に従い、nowを呼び出し元から受け取るよう変更した。
 */
int bm_object_sync_announce_onion_peer(struct bm_object_sync_ctx *ctx, const char *onion_address, int port,
                                        int64_t now);

/*
 * §11 2026-08-24 backlog項目6: onionpeer自己announceの定期再送(PyBitmessage本家
 * class_singleCleaner.pyの約2時間おきの周期処理に相当)。以前は起動時に1回
 * bm_object_sync_announce_onion_peerを呼ぶだけで、TTL(BM_ONIONPEER_ANNOUNCE_TTL_SECONDS、
 * 2日)経過後は再起動しない限り誰からも発見されなくなっていた。ctx->last_onion_announceを
 * 基準に、BM_ONIONPEER_REANNOUNCE_INTERVAL_SECONDS未満の間隔での呼び出しは即returnする
 * (呼び出し元は間引き無しで毎回呼んでよい、peer_connector.cの1秒間隔ポーリングループ
 * からの利用を想定)。onion_addressがNULLまたは空文字列なら何もしない(Tor未使用の
 * 構成向け)。main.cが起動時に直接announce_onion_peerを呼んだ直後は、呼び出し側が
 * ctx->last_onion_announceを現在時刻にセットしておくことで、この関数の初回呼び出しでの
 * 二重announceを避ける想定(main.c参照)。
 */
void bm_object_sync_maybe_reannounce_onion_peer(struct bm_object_sync_ctx *ctx, const char *onion_address, int port,
                                                 int64_t now);

/*
 * §11 2026-08-25 join-chan後にchan宛の過去メッセージが読めない問題の対応。
 * 通常の受信フロー(bm_object_sync_dispatch)はobjectを新規受信した瞬間に一度しか
 * trial_decryptを試みないため、その宛先の鍵をunlockする「前」に既にobject_pool.dbへ
 * 保存されていたBM_OBJECT_MSGオブジェクト(chan参加前に他メンバーが投稿した分、あるいは
 * 単に後からunlockした通常identity宛の過去メッセージ)は、鍵をunlockしても自動では
 * inboxに現れない(ユーザー指摘)。
 * kr(呼び出し時点でunlockされている全identity)でobject_pool_db中の全MSGオブジェクトを
 * 再走査し、復号できたものをmessages_db inboxへ挿入する(bm_trial_decrypt_and_store委譲、
 * msg_idユニーク制約によりinbox側は複数回呼んでも重複挿入されない)。
 * core/api_server.cのunlockAddress成功直後から、生きたpeer接続やregistryを持たない文脈で
 * 呼ばれることを想定するため、埋め込みack_payloadの検証・再送(§5.5)はここでは行わない
 * (受信直後の通常経路とは異なり、送信元へのack配送が遅れる/届かない可能性があるが、
 * v1では「chan参加前の過去ログが読めるようになる」ことを優先し許容する)。
 * 新規にinboxへ挿入できた件数を返す。object_pool_dbの列挙に失敗した場合のみ-1。
 */
int bm_object_sync_backfill_trial_decrypt(sqlite3 *object_pool_db, sqlite3 *messages_db, bm_keyring_t *kr);

#endif /* BM_INFRA_OBJECT_SYNC_H */
