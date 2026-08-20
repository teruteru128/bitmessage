#ifndef BM_CORE_MESSAGES_STORE_H
#define BM_CORE_MESSAGES_STORE_H

/* messages.db(§2.4)の操作。 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

int bm_messages_store_init_schema(sqlite3 *db);

/*
 * inboxへ1件挿入する(trial_decrypt.cから呼ばれる)。msg_idはobjectのinventory hash(32byte)。
 * 既に同じmsg_idがあれば何もしない(重複配送への耐性)。成功時0。
 */
int bm_messages_store_insert_inbox(sqlite3 *db, const unsigned char msg_id[32],
                                    const char *to_address, const char *from_address,
                                    const char *subject, const char *body,
                                    int64_t received_time);

/*
 * sentへ1件挿入する(send_pipeline.cから呼ばれる)。ack_dataはbm_build_ack_objectで
 * 作ったackobjectの生バイト列(§5.5)。成功時0。
 */
int bm_messages_store_insert_sent(sqlite3 *db, const unsigned char *ack_data, size_t ack_data_len,
                                   const char *to_address, const char *from_address,
                                   const char *subject, const char *body,
                                   const char *status, int64_t sent_time, int64_t ttl);

#endif /* BM_CORE_MESSAGES_STORE_H */
