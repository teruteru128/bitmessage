#ifndef BM_CORE_MESSAGES_STORE_H
#define BM_CORE_MESSAGES_STORE_H

/* messages.db(§2.4)の操作。sent側のCRUDはsend_pipeline.c実装時にTODO。 */

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

#endif /* BM_CORE_MESSAGES_STORE_H */
