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
 * to_pub_encryptionはNULL可。NULLの場合、identity_dbのpubkey_cache(§2.3)をto_addressの
 * ripeで検索し、見つかればそれを使う(見つからなければ失敗する。呼び出し側=api_server.cが
 * 見つからない場合にgetpubkey要求を自動発行する、§11)。呼び出し側が既に相手の公開鍵を
 * 知っている場合は直接渡すこともできる(cache参照をbypass)。ack_stealth_levelは§5.5/§8-6
 * (既定値は1)。
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
 * 失敗する場合: from_addressがunlockedでない、to_addressのデコード失敗、
 * to_pub_encryptionがNULLでpubkey_cacheにも無い、message_builder/pow_engineでのエラー、
 * DB書き込み失敗。
 */
int bm_send_pipeline_send_message(bm_keyring_t *kr, sqlite3 *identity_db, sqlite3 *messages_db,
                                   const char *from_address, const char *to_address,
                                   const unsigned char to_pub_encryption[65],
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

void *bm_send_pipeline_thread(void *arg);

#endif /* BM_CORE_SEND_PIPELINE_H */
