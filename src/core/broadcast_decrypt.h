#ifndef BM_CORE_BROADCAST_DECRYPT_H
#define BM_CORE_BROADCAST_DECRYPT_H

/*
 * §5.4 broadcast(type=3)の受信側処理。message_builder.cのbm_build_broadcastの逆方向。
 * 「アドレスを知っていれば誰でも読める」暗号鍵(pubkey v4/getpubkey v4と同じ
 * bm_address_derive_secret_and_tag方式)のため、購読(subscription)している候補アドレスを
 * 1件ずつ試す設計(呼び出し側=infra/object_sync.cがmessages.dbのsubscriptionsを列挙して
 * ループする)。objectVersion==5(fromAddressVersion>=4)はtagで安価に候補を絞れるが、
 * objectVersion==4(fromAddressVersion<=3)はtagが無いため毎回ECIES復号を試みるしかない
 * (DESIGN.md §5.4「total-scan」)。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

struct bm_decoded_broadcast
{
    uint64_t from_address_version;
    uint64_t from_stream;
    char from_address[40];
    char *subject; /* malloc、bm_decoded_broadcast_freeで解放 */
    char *body;    /* malloc */
};

/*
 * type=broadcastの完全なobject(nonce込み)を、candidate(購読先候補)のアドレス情報で
 * 復号を試みる。成功時0でoutを埋める(bm_decoded_broadcast_freeで解放すること)。
 * 以下は全て失敗(非0)として扱う: objectTypeがbroadcastでない/candidateとtagが合わない
 * (objectVersion==5の場合)/ECIES復号失敗/署名検証失敗。
 */
int bm_trial_decrypt_broadcast(const unsigned char *object, size_t object_len,
                                uint64_t candidate_version, uint64_t candidate_stream,
                                const unsigned char candidate_ripe[20],
                                struct bm_decoded_broadcast *out);
void bm_decoded_broadcast_free(struct bm_decoded_broadcast *msg);

/*
 * bm_trial_decrypt_broadcastを呼び、成功したらinboxへ保存する(msg_id=objectのinventory hash、
 * to_address=from_address。broadcastには単一の宛先が無いためPyBitmessageに倣いfromと同じ値を
 * 入れて「これはbroadcastである」ことが分かるようにする、§5.4)。成功時0。
 */
int bm_trial_decrypt_broadcast_and_store(sqlite3 *messages_db, const unsigned char *object, size_t object_len,
                                          uint64_t candidate_version, uint64_t candidate_stream,
                                          const unsigned char candidate_ripe[20]);

#endif /* BM_CORE_BROADCAST_DECRYPT_H */
