#include "messages_store.h"

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
