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
 * to_pub_encryptionは呼び出し側が指定する(pubkey_cache参照・getpubkey要求による自動取得は
 * 未実装、TODO — v1では呼び出し側が既知の相手の公開鍵を渡す前提)。
 * ack_stealth_levelは§5.5/§8-6(既定値は1)。
 *
 * 成功時0。*out_objectに完成object(nonce込み、malloc)、*out_object_lenにその長さを設定する
 * (呼び出し側でfreeすること)。副作用としてmessages.dbのsentテーブルへ1行記録する。
 * ネットワークへの実際のブロードキャストはinfra層の責務(TODO、object_store/network実装後)。
 *
 * 失敗する場合: from_addressがunlockedでない、to_addressのデコード失敗、
 * message_builder/pow_engineでのエラー、DB書き込み失敗。
 */
int bm_send_pipeline_send_message(bm_keyring_t *kr, sqlite3 *messages_db,
                                   const char *from_address, const char *to_address,
                                   const unsigned char to_pub_encryption[65],
                                   const char *subject, const char *body,
                                   uint64_t ttl_seconds, int ack_stealth_level,
                                   unsigned char **out_object, size_t *out_object_len);

void *bm_send_pipeline_thread(void *arg);

#endif /* BM_CORE_SEND_PIPELINE_H */
