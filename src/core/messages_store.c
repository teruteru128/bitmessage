#include "messages_store.h"

#include <string.h>

#include "../common/db_common.h"

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS inbox ("
    "msg_id BLOB PRIMARY KEY, "
    "to_address TEXT NOT NULL, "
    "from_address TEXT NOT NULL, "
    "subject BLOB NOT NULL, "
    "body BLOB NOT NULL, "
    "received_time INTEGER NOT NULL, "
    "read INTEGER NOT NULL DEFAULT 0, "
    "folder TEXT NOT NULL DEFAULT 'inbox'"
    ");"
    "CREATE TABLE IF NOT EXISTS sent ("
    "ack_data BLOB PRIMARY KEY, "
    "to_address TEXT NOT NULL, "
    "from_address TEXT NOT NULL, "
    "subject BLOB NOT NULL, "
    "body BLOB NOT NULL, "
    "status TEXT NOT NULL, "
    "sent_time INTEGER NOT NULL, "
    "ttl INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS address_book ("
    "address TEXT PRIMARY KEY, "
    "label TEXT NOT NULL"
    ");";

int bm_messages_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_messages_store_insert_inbox(sqlite3 *db, const unsigned char msg_id[32],
                                    const char *to_address, const char *from_address,
                                    const char *subject, const char *body,
                                    int64_t received_time)
{
    static const char *SQL =
        "INSERT OR IGNORE INTO inbox (msg_id, to_address, from_address, subject, body, received_time) "
        "VALUES (?1,?2,?3,?4,?5,?6);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, msg_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, subject, (int)strlen(subject), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, body, (int)strlen(body), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, received_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_messages_store_insert_sent(sqlite3 *db, const unsigned char *ack_data, size_t ack_data_len,
                                   const char *to_address, const char *from_address,
                                   const char *subject, const char *body,
                                   const char *status, int64_t sent_time, int64_t ttl)
{
    static const char *SQL =
        "INSERT INTO sent (ack_data, to_address, from_address, subject, body, status, sent_time, ttl) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ack_data, (int)ack_data_len, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, subject, (int)strlen(subject), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, body, (int)strlen(body), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, sent_time);
    sqlite3_bind_int64(stmt, 8, ttl);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
