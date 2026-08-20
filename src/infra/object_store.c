#include "object_store.h"

#include <stddef.h>

#include "../common/db_common.h"

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS objects ("
    "hash BLOB PRIMARY KEY, "
    "object_type INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "payload BLOB NOT NULL, "
    "expires_time INTEGER NOT NULL, "
    "received_time INTEGER NOT NULL, "
    "processed INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_expires ON objects(expires_time);"
    "CREATE INDEX IF NOT EXISTS idx_stream_type ON objects(stream, object_type);"
    "CREATE INDEX IF NOT EXISTS idx_unprocessed ON objects(processed) WHERE processed = 0;";

int bm_object_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_object_store_insert(sqlite3 *db, const unsigned char hash[32], int object_type, int stream,
                            const unsigned char *payload, size_t payload_len, int64_t expires_time,
                            int64_t received_time)
{
    static const char *SQL =
        "INSERT OR IGNORE INTO objects (hash, object_type, stream, payload, expires_time, received_time) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, object_type);
    sqlite3_bind_int(stmt, 3, stream);
    sqlite3_bind_blob(stmt, 4, payload, (int)payload_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, expires_time);
    sqlite3_bind_int64(stmt, 6, received_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_object_store_has(sqlite3 *db, const unsigned char hash[32])
{
    static const char *SQL = "SELECT 1 FROM objects WHERE hash = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return 0;
    }
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

int bm_object_store_delete_expired(sqlite3 *db, int64_t now)
{
    static const char *SQL = "DELETE FROM objects WHERE expires_time < ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
    {
        return -1;
    }
    return sqlite3_changes(db);
}
