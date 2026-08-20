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

#define BM_MESSAGES_ADDRESS_MAX 40
#define BM_MESSAGES_FOLDER_MAX 16

struct bm_inbox_message
{
    unsigned char msg_id[32];
    char to_address[BM_MESSAGES_ADDRESS_MAX];
    char from_address[BM_MESSAGES_ADDRESS_MAX];
    char *subject; /* malloc */
    char *body;    /* malloc */
    int64_t received_time;
    int read;
    char folder[BM_MESSAGES_FOLDER_MAX];
};

/*
 * inboxを一覧する(受信時刻降順)。folder_filterがNULLなら全件(inbox/trash問わず)、
 * 非NULLならその値のfolderのみ。成功時0、*out_listはmalloc済み配列(bm_inbox_message_list_freeで解放)。
 */
int bm_messages_store_list_inbox(sqlite3 *db, const char *folder_filter,
                                  struct bm_inbox_message **out_list, size_t *out_count);
void bm_inbox_message_list_free(struct bm_inbox_message *list, size_t count);

#endif /* BM_CORE_MESSAGES_STORE_H */
