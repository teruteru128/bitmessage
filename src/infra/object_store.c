#include "object_store.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

int bm_object_store_get(sqlite3 *db, const unsigned char hash[32],
                         unsigned char **out_payload, size_t *out_len)
{
    static const char *SQL = "SELECT payload FROM objects WHERE hash = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return -1;
    }
    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    unsigned char *out = malloc((size_t)blob_len);
    memcpy(out, blob, (size_t)blob_len);
    sqlite3_finalize(stmt);

    *out_payload = out;
    *out_len = (size_t)blob_len;
    return 0;
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

int bm_object_store_list_hashes_by_stream(sqlite3 *db, int stream, int64_t now,
                                           unsigned char (**out_hashes)[32], size_t *out_count)
{
    static const char *COUNT_SQL = "SELECT COUNT(*) FROM objects WHERE stream = ?1 AND expires_time > ?2;";
    sqlite3_stmt *count_stmt = NULL;
    if (sqlite3_prepare_v2(db, COUNT_SQL, -1, &count_stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(count_stmt, 1, stream);
    sqlite3_bind_int64(count_stmt, 2, now);
    if (sqlite3_step(count_stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(count_stmt);
        return -1;
    }
    size_t count = (size_t)sqlite3_column_int64(count_stmt, 0);
    sqlite3_finalize(count_stmt);

    unsigned char(*hashes)[32] = count > 0 ? malloc(sizeof(*hashes) * count) : malloc(1);
    if (hashes == NULL)
    {
        return -1;
    }

    static const char *SQL = "SELECT hash FROM objects WHERE stream = ?1 AND expires_time > ?2;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        free(hashes);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, stream);
    sqlite3_bind_int64(stmt, 2, now);

    size_t n = 0;
    while (n < count && sqlite3_step(stmt) == SQLITE_ROW)
    {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (blob != NULL && blob_len == 32)
        {
            memcpy(hashes[n], blob, 32);
            n++;
        }
    }
    sqlite3_finalize(stmt);

    *out_hashes = hashes;
    *out_count = n;
    return 0;
}

int bm_object_store_list_hashes_by_type(sqlite3 *db, int object_type,
                                         unsigned char (**out_hashes)[32], size_t *out_count)
{
    static const char *COUNT_SQL = "SELECT COUNT(*) FROM objects WHERE object_type = ?1;";
    sqlite3_stmt *count_stmt = NULL;
    if (sqlite3_prepare_v2(db, COUNT_SQL, -1, &count_stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(count_stmt, 1, object_type);
    if (sqlite3_step(count_stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(count_stmt);
        return -1;
    }
    size_t count = (size_t)sqlite3_column_int64(count_stmt, 0);
    sqlite3_finalize(count_stmt);

    unsigned char(*hashes)[32] = count > 0 ? malloc(sizeof(*hashes) * count) : malloc(1);
    if (hashes == NULL)
    {
        return -1;
    }

    static const char *SQL = "SELECT hash FROM objects WHERE object_type = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        free(hashes);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, object_type);

    size_t n = 0;
    while (n < count && sqlite3_step(stmt) == SQLITE_ROW)
    {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (blob != NULL && blob_len == 32)
        {
            memcpy(hashes[n], blob, 32);
            n++;
        }
    }
    sqlite3_finalize(stmt);

    *out_hashes = hashes;
    *out_count = n;
    return 0;
}
