#ifndef BM_COMMON_DB_COMMON_H
#define BM_COMMON_DB_COMMON_H

/*
 * SQLite接続の共通処理。DESIGN.md §1.3: スレッドごとに個別コネクションを開き、
 * WALモード + SQLITE_OPEN_FULLMUTEX を用いる(1コネクションを複数スレッドで共有しない)。
 */

#include <sqlite3.h>

/* filenameへの接続を開き、WALモードを有効化する。失敗時はNULLを返す(標準エラー出力にログ) */
sqlite3 *bm_db_open(const char *filename);

/* schema_sql(CREATE TABLE IF NOT EXISTS ...を想定)を実行する。成功時0、失敗時非0 */
int bm_db_init_schema(sqlite3 *db, const char *schema_sql);

#endif /* BM_COMMON_DB_COMMON_H */
