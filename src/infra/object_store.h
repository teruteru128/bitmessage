#ifndef BM_INFRA_OBJECT_STORE_H
#define BM_INFRA_OBJECT_STORE_H

/*
 * object_pool.db(§2.2)の操作。移植元: study/libstudy の bm_storage.h(中身が空だったため新規実装)。
 * トライアル復号への引き渡し(decrypt_request_queueへの投入)は core 層実装後にTODO。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

int bm_object_store_init_schema(sqlite3 *db);

/* 既に同じhashがあれば何もしない(重複排除)。成功時0 */
int bm_object_store_insert(sqlite3 *db, const unsigned char hash[32], int object_type, int stream,
                            const unsigned char *payload, size_t payload_len, int64_t expires_time,
                            int64_t received_time);

int bm_object_store_has(sqlite3 *db, const unsigned char hash[32]);

/* 期限切れ(expires_time < now)のobjectを削除する。削除件数を返す(エラー時-1) */
int bm_object_store_delete_expired(sqlite3 *db, int64_t now);

#endif /* BM_INFRA_OBJECT_STORE_H */
