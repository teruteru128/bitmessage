#include "peer_manager.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../common/db_common.h"

struct bootstrap_node
{
    const char *ip;
    int port;
};

/* PyBitmessage src/network/knownnodes.py の DEFAULT_NODES(2026-08-21確認) */
static const struct bootstrap_node MAINNET_SEEDS[] = {
    {"5.45.99.75", 8444},
    {"75.167.159.54", 8444},
    {"95.165.168.168", 8444},
    {"85.180.139.241", 8444},
    {"158.222.217.190", 8080},
    {"178.62.12.187", 8448},
    {"24.188.198.204", 8111},
    {"109.147.204.113", 1195},
    {"178.11.46.221", 8444},
};

/* 同ファイルの TESTNET_NODES */
static const struct bootstrap_node TESTNET_SEEDS[] = {
    {"46.62.252.34", 8444},
    {"5.78.198.100", 8444},
};

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

int bm_peer_manager_seed_bootstrap(sqlite3 *db, int testnet)
{
    sqlite3_stmt *count_stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM hosts;", -1, &count_stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    int existing = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW)
    {
        existing = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);
    if (existing > 0)
    {
        return 0; /* 既に何かある場合は上書きしない */
    }

    const struct bootstrap_node *seeds = testnet ? TESTNET_SEEDS : MAINNET_SEEDS;
    size_t seed_count = testnet
        ? sizeof(TESTNET_SEEDS) / sizeof(TESTNET_SEEDS[0])
        : sizeof(MAINNET_SEEDS) / sizeof(MAINNET_SEEDS[0]);

    int64_t now = (int64_t)time(NULL);
    for (size_t i = 0; i < seed_count; i++)
    {
        struct bm_peer_entry entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.ip_address, seeds[i].ip, sizeof(entry.ip_address) - 1);
        entry.port = seeds[i].port;
        entry.stream = 1;
        entry.services = 1;
        entry.last_seen = now;
        entry.rating = 0.0;
        strncpy(entry.source, "seed", sizeof(entry.source) - 1);
        if (bm_peer_manager_upsert(db, &entry) != 0)
        {
            return -1;
        }
    }
    fprintf(stderr, "[peer_manager] seeded %zu bootstrap nodes (%s)\n", seed_count,
            testnet ? "testnet" : "mainnet");
    return 0;
}

int bm_peer_manager_upsert_learned(sqlite3 *db, const char *ip_address, int port, int stream,
                                    uint64_t services, int64_t last_seen, const char *source)
{
    static const char *SQL =
        "INSERT INTO hosts (ip_address, port, stream, services, last_seen, rating, source) "
        "VALUES (?1, ?2, ?3, ?4, ?5, 0.0, ?6) "
        "ON CONFLICT(ip_address, port, stream) DO UPDATE SET "
        "services=excluded.services, last_seen=excluded.last_seen;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)services);
    sqlite3_bind_int64(stmt, 5, last_seen);
    sqlite3_bind_text(stmt, 6, source, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_record_result(sqlite3 *db, const char *ip_address, int port, int stream, int success)
{
    const char *sql = success
        ? "UPDATE hosts SET rating = MIN(1.0, rating + 0.1), last_seen = ?4 "
          "WHERE ip_address = ?1 AND port = ?2 AND stream = ?3;"
        : "UPDATE hosts SET rating = MAX(-1.0, rating - 0.1) "
          "WHERE ip_address = ?1 AND port = ?2 AND stream = ?3;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    if (success)
    {
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
    }

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
