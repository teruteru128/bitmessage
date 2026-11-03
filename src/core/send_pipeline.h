#ifndef BM_CORE_SEND_PIPELINE_H
#define BM_CORE_SEND_PIPELINE_H

/*
 * send_pipeline_thread(§1.1)。message_builder.c(組み立て)とpow_engine.c(PoW計算)を
 * 繋いで、送信要求から完成object(nonce込み)を作る。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "keyring.h"

/*
 * from_address(keyring内でunlocked済みであること)からto_addressへメッセージを送る。
 *
 * 宛先の公開暗号鍵は常にidentity_dbのpubkey_cache(§2.3)をto_addressのripeで検索して使う
 * (見つからなければ失敗する。呼び出し側=api_server.cが見つからない場合にgetpubkey要求を
 * 自動発行する、§11)。ただしto_address==from_address(自分自身宛、chan投稿)の場合は
 * cache不要でfrom_id自身のpub_encryptionを使う。ack_stealth_levelは§5.5/§8-6(既定値は1)。
 *
 * §11 2026-08-30 呼び出し側が公開鍵を直接渡せるto_pub_encryption引数を廃止した。渡された
 * hexがto_addressと対応する保証が無く、①toAddressと無関係の鍵で暗号化してしまう、
 * ②検証されない鍵がそのままpubkey_cacheへ自動upsertされ以後の送信も汚染する、という2つの
 * 実害があったため(ユーザー指摘)。相手の鍵を事前に知っている場合は呼び出し側が
 * bm_pubkey_cache_upsertで明示的に登録してから呼ぶこと。
 *
 * reuse_msg_idはNULL可。NULLなら新規送信としてsent.msg_idをランダム生成する。非NULLなら
 * その32byte IDでsentテーブルの既存行をUPDATEする(§11再送ロジック、object_sync.cの
 * 再送チェックが既存msg_idを渡して呼ぶ。ack_dataは毎回新しく生成し直され、resend_countは
 * DB側で自動的に+1される)。next_resend_timeは呼び出し側が§11の間隔倍々ルールに従って
 * 計算した値を渡すこと(新規送信ならsent_time+BM_RESEND_INITIAL_INTERVAL_SECONDS)。
 *
 * 成功時0。*out_objectに完成object(nonce込み、malloc)、*out_object_lenにその長さを設定する
 * (呼び出し側でfreeすること)。副作用としてmessages.dbのsentテーブルへ1行記録/更新する。
 * ネットワークへの実際のブロードキャストは呼び出し側の責務(broadcast_queue経由、§1.2)。
 *
 * 失敗する場合: from_addressがunlockedでない、to_addressのデコード失敗、pubkey_cacheに
 * 宛先の鍵が無い、message_builder/pow_engineでのエラー、DB書き込み失敗。
 */
int bm_send_pipeline_send_message(bm_keyring_t *kr, sqlite3 *identity_db, sqlite3 *messages_db,
                                   const char *from_address, const char *to_address,
                                   const char *subject, const char *body,
                                   uint64_t ttl_seconds, int ack_stealth_level,
                                   const unsigned char reuse_msg_id[32], int64_t next_resend_time,
                                   unsigned char **out_object, size_t *out_object_len);

/*
 * §5.4/§11: from_address(keyring内でunlocked済みであること)からbroadcastを送る。
 * broadcastには単一の宛先もack機構も無いため、send_messageと異なりsentテーブルへの
 * 記録・再送の対象にはしない(v1の単純化。送りっぱなし)。
 * 成功時0。*out_objectに完成object(nonce込み、malloc)、*out_object_lenにその長さを設定する
 * (呼び出し側でfreeすること)。ネットワークへの実際のブロードキャストは呼び出し側の責務
 * (broadcast_queue経由、§1.2)。失敗する場合: from_addressがunlockedでない、
 * message_builder/pow_engineでのエラー。
 */
int bm_send_pipeline_send_broadcast(bm_keyring_t *kr, const char *from_address,
                                     const char *subject, const char *body, uint64_t ttl_seconds,
                                     unsigned char **out_object, size_t *out_object_len);

/*
 * §11 2026-11-03 項目38 Tier 2: 上の2つの非同期版。PoWをpow_queue(src/pow/pow_queue.h)の
 * ワーカーで行い、呼び出し元スレッドを止めない。上の同期版は、これをpow_queue==NULLで呼んで
 * その場で結果を受け取る薄いラッパーになった(テスト・単体動作用。挙動は以前と同じ)。
 *
 * 鍵・宛先の解決など、失敗の大半はこの関数の中(呼び出し元スレッド)で同期的に判定する。
 *
 * 戻り値:
 *   0  受け付けた。doneはちょうど1回呼ばれる(pow_queue==NULLなら、この関数が戻る前に)。
 *      PoW以降の失敗(sentへの記録の失敗・shutdownでの打ち切り等)はdoneのrc=-1で知らせる
 *   -1 準備段での失敗、またはpow_queueの上限超過・shutdown後。doneは呼ばれない
 *   1  (send_messageのみ)同じmsg_id(=reuse_msg_idを渡した再送)のPoWが既に走っている。
 *      doneは呼ばれない
 *
 * doneはワーカースレッド上で呼ばれうる。rc==0ならobject(nonce込みの完成object)の所有権は
 * doneへ移る(doneがfreeする)。nowはPoW完了時点の時刻。sent行の記録(send_message)は
 * doneより前に済んでいる。ネットワークへ流すのは従来通りdone(呼び出し側)の責務。
 * nowは準備段の時刻で、expires_timeはnow+ttl_secondsになる(CLAUDE.mdの方針で、
 * 関数内部でtime(NULL)を呼ばない)。
 */
struct bm_pow_queue;
typedef void (*bm_send_done_fn)(void *user_data, int rc, unsigned char *object, size_t object_len, int64_t now);

int bm_send_pipeline_send_message_async(struct bm_pow_queue *pow_queue, bm_keyring_t *kr, sqlite3 *identity_db,
                                        sqlite3 *messages_db, const char *from_address, const char *to_address,
                                        const char *subject, const char *body, uint64_t ttl_seconds,
                                        int ack_stealth_level, const unsigned char reuse_msg_id[32],
                                        int64_t next_resend_time, int64_t now, bm_send_done_fn done,
                                        void *user_data);

int bm_send_pipeline_send_broadcast_async(struct bm_pow_queue *pow_queue, bm_keyring_t *kr,
                                          const char *from_address, const char *subject, const char *body,
                                          uint64_t ttl_seconds, int64_t now, bm_send_done_fn done, void *user_data);

void *bm_send_pipeline_thread(void *arg);

#endif /* BM_CORE_SEND_PIPELINE_H */
