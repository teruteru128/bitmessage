#include "messages_store.h"

#include <stdlib.h>
#include <string.h>

#include "../common/db_common.h"
#include "../common/hash.h"

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

int bm_messages_store_list_inbox(sqlite3 *db, const char *folder_filter,
                                  struct bm_inbox_message **out_list, size_t *out_count)
{
    static const char *SQL_ALL =
        "SELECT msg_id, to_address, from_address, subject, body, received_time, read, folder "
        "FROM inbox ORDER BY received_time DESC;";
    static const char *SQL_FILTERED =
        "SELECT msg_id, to_address, from_address, subject, body, received_time, read, folder "
        "FROM inbox WHERE folder = ?1 ORDER BY received_time DESC;";

    sqlite3_stmt *stmt = NULL;
    const char *sql = folder_filter != NULL ? SQL_FILTERED : SQL_ALL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    if (folder_filter != NULL)
    {
        sqlite3_bind_text(stmt, 1, folder_filter, -1, SQLITE_TRANSIENT);
    }

    size_t cap = 8;
    size_t count = 0;
    struct bm_inbox_message *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        struct bm_inbox_message *m = &list[count];
        memset(m, 0, sizeof(*m));

        const void *msg_id = sqlite3_column_blob(stmt, 0);
        int msg_id_len = sqlite3_column_bytes(stmt, 0);
        if (msg_id_len == 32)
        {
            memcpy(m->msg_id, msg_id, 32);
        }

        const unsigned char *to_address = sqlite3_column_text(stmt, 1);
        strncpy(m->to_address, (const char *)to_address, BM_MESSAGES_ADDRESS_MAX - 1);
        const unsigned char *from_address = sqlite3_column_text(stmt, 2);
        strncpy(m->from_address, (const char *)from_address, BM_MESSAGES_ADDRESS_MAX - 1);

        const void *subject = sqlite3_column_blob(stmt, 3);
        int subject_len = sqlite3_column_bytes(stmt, 3);
        m->subject = malloc((size_t)subject_len + 1);
        memcpy(m->subject, subject, (size_t)subject_len);
        m->subject[subject_len] = '\0';

        const void *body = sqlite3_column_blob(stmt, 4);
        int body_len = sqlite3_column_bytes(stmt, 4);
        m->body = malloc((size_t)body_len + 1);
        memcpy(m->body, body, (size_t)body_len);
        m->body[body_len] = '\0';

        m->received_time = sqlite3_column_int64(stmt, 5);
        m->read = sqlite3_column_int(stmt, 6);
        const unsigned char *folder = sqlite3_column_text(stmt, 7);
        strncpy(m->folder, (const char *)folder, BM_MESSAGES_FOLDER_MAX - 1);

        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_inbox_message_list_free(struct bm_inbox_message *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        free(list[i].subject);
        free(list[i].body);
    }
    free(list);
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

int bm_messages_store_try_mark_ack_received(sqlite3 *db, const unsigned char received_hash[32])
{
    static const char *SELECT_SQL = "SELECT ack_data FROM sent WHERE status != 'ackreceived';";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SELECT_SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    int found = 0;
    while (!found && sqlite3_step(stmt) == SQLITE_ROW)
    {
        const void *ack_data = sqlite3_column_blob(stmt, 0);
        int ack_data_len = sqlite3_column_bytes(stmt, 0);
        if (ack_data_len <= 0)
        {
            continue;
        }
        unsigned char computed[32];
        bm_inventory_hash((const unsigned char *)ack_data, (size_t)ack_data_len, computed);
        if (memcmp(computed, received_hash, 32) == 0)
        {
            static const char *UPDATE_SQL = "UPDATE sent SET status = 'ackreceived' WHERE ack_data = ?1;";
            sqlite3_stmt *upd = NULL;
            if (sqlite3_prepare_v2(db, UPDATE_SQL, -1, &upd, NULL) == SQLITE_OK)
            {
                sqlite3_bind_blob(upd, 1, ack_data, ack_data_len, SQLITE_TRANSIENT);
                sqlite3_step(upd);
                sqlite3_finalize(upd);
                found = 1;
            }
        }
    }
    sqlite3_finalize(stmt);
    return found ? 0 : -1;
}
