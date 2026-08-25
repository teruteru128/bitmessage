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

/* hashからpayload(nonce込みの完全なobjectバイト列)を取得する。見つかれば0で*out_payloadをmalloc
 * (呼び出し側でfree)、見つからない/エラー時は非0 */
int bm_object_store_get(sqlite3 *db, const unsigned char hash[32],
                         unsigned char **out_payload, size_t *out_len);

/* 期限切れ(expires_time < now)のobjectを削除する。削除件数を返す(エラー時-1) */
int bm_object_store_delete_expired(sqlite3 *db, int64_t now);

/*
 * §11 2026-08-23 backlog: PyBitmessage本家のsendBigInv相当(handshake完了時に自分の
 * 保有object全件を新規peerへ知らせる)で使う。指定streamの未期限切れ(expires_time > now)
 * object hashを全件取得する。成功時0で*out_hashesをmalloc(呼び出し側でfree、0件でも
 * NULLにはせずmalloc(0)相当を返す)、*out_countへ件数を設定。エラー時-1。
 */
int bm_object_store_list_hashes_by_stream(sqlite3 *db, int stream, int64_t now,
                                           unsigned char (**out_hashes)[32], size_t *out_count);

/*
 * §11 2026-08-25 unlockAddress時のtrial_decryptバックフィル(object_sync.cの
 * bm_object_sync_backfill_trial_decrypt)で使う。指定object_type(通常はBM_OBJECT_MSG)の
 * objectのhashを、期限切れかどうかに関わらず全件取得する(受信済みだが復号できずに
 * 残っているobjectを後から拾うための処理のため、expires_timeでは絞り込まない)。
 * 成功時0で*out_hashesをmalloc(呼び出し側でfree、0件でも同様)、*out_countへ件数を設定。
 * エラー時-1。
 */
int bm_object_store_list_hashes_by_type(sqlite3 *db, int object_type,
                                         unsigned char (**out_hashes)[32], size_t *out_count);

#endif /* BM_INFRA_OBJECT_STORE_H */
