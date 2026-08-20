#include "peer_manager.h"

#include <string.h>

#include "../common/db_common.h"

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS hosts ("
    "ip_address TEXT NOT NULL, "
    "port INTEGER NOT NULL, "
    "stream INTEGER NOT NULL DEFAULT 1, "
    "services INTEGER NOT NULL DEFAULT 1, "
    "last_seen INTEGER NOT NULL, "
    "rating REAL NOT NULL DEFAULT 0.0, "
    "source TEXT NOT NULL DEFAULT 'unknown', "
    "PRIMARY KEY (ip_address, port, stream)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_hosts_stream_rating ON hosts(stream, rating DESC);";

int bm_peer_manager_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_peer_manager_upsert(sqlite3 *db, const struct bm_peer_entry *entry)
{
    static const char *SQL =
        "INSERT INTO hosts (ip_address, port, stream, services, last_seen, rating, source) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
        "ON CONFLICT(ip_address, port, stream) DO UPDATE SET "
        "services=excluded.services, last_seen=excluded.last_seen, "
        "rating=excluded.rating, source=excluded.source;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, entry->ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, entry->port);
    sqlite3_bind_int(stmt, 3, entry->stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)entry->services);
    sqlite3_bind_int64(stmt, 5, entry->last_seen);
    sqlite3_bind_double(stmt, 6, entry->rating);
    sqlite3_bind_text(stmt, 7, entry->source, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_list_top(sqlite3 *db, int stream, struct bm_peer_entry *results,
                              int max_results, int *out_count)
{
    static const char *SQL =
        "SELECT ip_address, port, stream, services, last_seen, rating, source "
        "FROM hosts WHERE stream = ?1 ORDER BY rating DESC LIMIT ?2;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, stream);
    sqlite3_bind_int(stmt, 2, max_results);

    int count = 0;
    while (count < max_results && sqlite3_step(stmt) == SQLITE_ROW)
    {
        struct bm_peer_entry *e = &results[count];
        memset(e, 0, sizeof(*e));
        const unsigned char *ip = sqlite3_column_text(stmt, 0);
        strncpy(e->ip_address, (const char *)ip, sizeof(e->ip_address) - 1);
        e->port = sqlite3_column_int(stmt, 1);
        e->stream = sqlite3_column_int(stmt, 2);
        e->services = (uint64_t)sqlite3_column_int64(stmt, 3);
        e->last_seen = sqlite3_column_int64(stmt, 4);
        e->rating = sqlite3_column_double(stmt, 5);
        const unsigned char *source = sqlite3_column_text(stmt, 6);
        if (source != NULL)
        {
            strncpy(e->source, (const char *)source, sizeof(e->source) - 1);
        }
        count++;
    }
    sqlite3_finalize(stmt);

    if (out_count)
    {
        *out_count = count;
    }
    return 0;
}
