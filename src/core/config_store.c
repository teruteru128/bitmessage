#include "config_store.h"

#include <string.h>

#include "../common/db_common.h"

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS socks_proxy ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "enabled INTEGER NOT NULL DEFAULT 0, "
    "host TEXT NOT NULL DEFAULT '127.0.0.1', "
    "port INTEGER NOT NULL DEFAULT 9050"
    ");"
    "CREATE TABLE IF NOT EXISTS tor_onion ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "private_key TEXT"
    ");";

int bm_config_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_config_store_get_socks_proxy(sqlite3 *db, struct bm_socks_proxy_config *out)
{
    memset(out, 0, sizeof(*out));
    out->enabled = 0;
    strncpy(out->host, "127.0.0.1", sizeof(out->host) - 1);
    out->port = 9050;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT enabled, host, port FROM socks_proxy WHERE id = 1;", -1, &stmt, NULL)
        != SQLITE_OK)
    {
        return -1;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        out->enabled = sqlite3_column_int(stmt, 0);
        const unsigned char *host = sqlite3_column_text(stmt, 1);
        if (host != NULL)
        {
            strncpy(out->host, (const char *)host, sizeof(out->host) - 1);
        }
        out->port = sqlite3_column_int(stmt, 2);
    }
    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? 0 : -1;
}

int bm_config_store_set_socks_proxy(sqlite3 *db, const struct bm_socks_proxy_config *cfg)
{
    static const char *SQL =
        "INSERT INTO socks_proxy (id, enabled, host, port) VALUES (1, ?1, ?2, ?3) "
        "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, host=excluded.host, port=excluded.port;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, cfg->enabled);
    sqlite3_bind_text(stmt, 2, cfg->host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, cfg->port);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_config_store_get_tor_onion_key(sqlite3 *db, char *out, size_t out_size)
{
    out[0] = '\0';

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT private_key FROM tor_onion WHERE id = 1;", -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    int rc = sqlite3_step(stmt);
    int found = 0;
    if (rc == SQLITE_ROW)
    {
        const unsigned char *key = sqlite3_column_text(stmt, 0);
        if (key != NULL)
        {
            strncpy(out, (const char *)key, out_size - 1);
            out[out_size - 1] = '\0';
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
    {
        return -1;
    }
    return found;
}

int bm_config_store_set_tor_onion_key(sqlite3 *db, const char *private_key)
{
    static const char *SQL =
        "INSERT INTO tor_onion (id, private_key) VALUES (1, ?1) "
        "ON CONFLICT(id) DO UPDATE SET private_key=excluded.private_key;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, private_key, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
