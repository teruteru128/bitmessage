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
    "msg_id BLOB PRIMARY KEY, " /* 送信試行を安定して指す32byteランダムID(再送でも不変) */
    "ack_data BLOB NOT NULL, "  /* 再送のたびに新しいobjectと共に上書きされる */
    "to_address TEXT NOT NULL, "
    "from_address TEXT NOT NULL, "
    "subject BLOB NOT NULL, "
    "body BLOB NOT NULL, "
    "status TEXT NOT NULL, "
    "ack_stealth_level INTEGER NOT NULL DEFAULT 1, "
    "sent_time INTEGER NOT NULL, "
    "ttl INTEGER NOT NULL, "
    "resend_count INTEGER NOT NULL DEFAULT 0, "
    "next_resend_time INTEGER NOT NULL DEFAULT 0, "
    "folder TEXT NOT NULL DEFAULT 'sent'" /* 'sent' | 'trash'(§11 2026-08-30 trashMessage用) */
    ");"
    "CREATE TABLE IF NOT EXISTS address_book ("
    "address TEXT PRIMARY KEY, "
    "label TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS subscriptions ("
    "address TEXT PRIMARY KEY, "
    "label TEXT NOT NULL DEFAULT '', "
    "enabled INTEGER NOT NULL DEFAULT 1"
    ");";

int bm_messages_store_init_schema(sqlite3 *db)
{
    if (bm_db_init_schema(db, SCHEMA_SQL) != 0)
    {
        return -1;
    }
    /* §11 2026-08-30: folder列は追加時点で既に稼働中のmessages.dbのsentテーブルには存在しない。
     * peer_manager.cのis_self追加時と同じ理由でALTER TABLEにより後付けする(既存DBとの重複エラーは
     * 無視する)。trashMessage APIでsent側もfolder='trash'にできるようにするため追加。 */
    sqlite3_exec(db, "ALTER TABLE sent ADD COLUMN folder TEXT NOT NULL DEFAULT 'sent';", NULL, NULL, NULL);
    return 0;
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

int bm_messages_store_insert_sent(sqlite3 *db, const unsigned char msg_id[32],
                                   const unsigned char *ack_data, size_t ack_data_len,
                                   const char *to_address, const char *from_address,
                                   const char *subject, const char *body,
                                   const char *status, int ack_stealth_level,
                                   int64_t sent_time, int64_t ttl, int64_t next_resend_time)
{
    static const char *SQL =
        "INSERT INTO sent (msg_id, ack_data, to_address, from_address, subject, body, status, "
        "ack_stealth_level, sent_time, ttl, resend_count, next_resend_time) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11) "
        "ON CONFLICT(msg_id) DO UPDATE SET "
        "ack_data=excluded.ack_data, status=excluded.status, sent_time=excluded.sent_time, "
        "ttl=excluded.ttl, resend_count=sent.resend_count + 1, "
        "next_resend_time=excluded.next_resend_time;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, msg_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, ack_data, (int)ack_data_len, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, to_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, from_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, subject, (int)strlen(subject), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 6, body, (int)strlen(body), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, ack_stealth_level);
    sqlite3_bind_int64(stmt, 9, sent_time);
    sqlite3_bind_int64(stmt, 10, ttl);
    sqlite3_bind_int64(stmt, 11, next_resend_time);

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

int bm_messages_store_list_resend_candidates(sqlite3 *db, int64_t now, int max_attempts,
                                              struct bm_sent_resend_candidate **out_list, size_t *out_count)
{
    static const char *SQL =
        "SELECT msg_id, to_address, from_address, subject, body, ack_stealth_level, ttl, resend_count "
        "FROM sent WHERE status != 'ackreceived' AND next_resend_time <= ?1 AND resend_count < ?2;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_int(stmt, 2, max_attempts);

    size_t cap = 4;
    size_t count = 0;
    struct bm_sent_resend_candidate *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (sqlite3_column_bytes(stmt, 0) != 32)
        {
            continue;
        }
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        struct bm_sent_resend_candidate *c = &list[count];
        memset(c, 0, sizeof(*c));
        memcpy(c->msg_id, sqlite3_column_blob(stmt, 0), 32);

        const unsigned char *to_address = sqlite3_column_text(stmt, 1);
        strncpy(c->to_address, (const char *)to_address, sizeof(c->to_address) - 1);
        const unsigned char *from_address = sqlite3_column_text(stmt, 2);
        strncpy(c->from_address, (const char *)from_address, sizeof(c->from_address) - 1);

        int subject_len = sqlite3_column_bytes(stmt, 3);
        c->subject = malloc((size_t)subject_len + 1);
        memcpy(c->subject, sqlite3_column_blob(stmt, 3), (size_t)subject_len);
        c->subject[subject_len] = '\0';

        int body_len = sqlite3_column_bytes(stmt, 4);
        c->body = malloc((size_t)body_len + 1);
        memcpy(c->body, sqlite3_column_blob(stmt, 4), (size_t)body_len);
        c->body[body_len] = '\0';

        c->ack_stealth_level = sqlite3_column_int(stmt, 5);
        c->ttl = sqlite3_column_int64(stmt, 6);
        c->resend_count = sqlite3_column_int(stmt, 7);

        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_sent_resend_candidate_list_free(struct bm_sent_resend_candidate *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        free(list[i].subject);
        free(list[i].body);
    }
    free(list);
}

int bm_messages_store_add_subscription(sqlite3 *db, const char *address, const char *label)
{
    static const char *SQL =
        "INSERT INTO subscriptions (address, label, enabled) VALUES (?1,?2,1) "
        "ON CONFLICT(address) DO UPDATE SET label=excluded.label, enabled=1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, label, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_messages_store_remove_subscription(sqlite3 *db, const char *address)
{
    static const char *SQL = "DELETE FROM subscriptions WHERE address = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_messages_store_list_subscriptions(sqlite3 *db, struct bm_subscription **out_list, size_t *out_count)
{
    static const char *SQL = "SELECT address, label FROM subscriptions WHERE enabled = 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    size_t cap = 4;
    size_t count = 0;
    struct bm_subscription *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        struct bm_subscription *s = &list[count];
        memset(s, 0, sizeof(*s));
        const unsigned char *address = sqlite3_column_text(stmt, 0);
        strncpy(s->address, (const char *)address, sizeof(s->address) - 1);
        const unsigned char *label = sqlite3_column_text(stmt, 1);
        if (label != NULL)
        {
            strncpy(s->label, (const char *)label, sizeof(s->label) - 1);
        }
        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_subscription_list_free(struct bm_subscription *list)
{
    free(list);
}

int bm_messages_store_add_address_book_entry(sqlite3 *db, const char *address, const char *label)
{
    static const char *SQL = "INSERT INTO address_book (address, label) VALUES (?1,?2);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, label, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1; /* 既に同じaddressがあればUNIQUE制約違反で非0 */
}

int bm_messages_store_remove_address_book_entry(sqlite3 *db, const char *address)
{
    static const char *SQL = "DELETE FROM address_book WHERE address = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_messages_store_list_address_book(sqlite3 *db, struct bm_address_book_entry **out_list, size_t *out_count)
{
    static const char *SQL = "SELECT address, label FROM address_book;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    size_t cap = 4;
    size_t count = 0;
    struct bm_address_book_entry *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        struct bm_address_book_entry *e = &list[count];
        memset(e, 0, sizeof(*e));
        const unsigned char *address = sqlite3_column_text(stmt, 0);
        strncpy(e->address, (const char *)address, sizeof(e->address) - 1);
        const unsigned char *label = sqlite3_column_text(stmt, 1);
        if (label != NULL)
        {
            strncpy(e->label, (const char *)label, sizeof(e->label) - 1);
        }
        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_address_book_list_free(struct bm_address_book_entry *list)
{
    free(list);
}

int bm_messages_store_list_sent(sqlite3 *db, struct bm_sent_message **out_list, size_t *out_count)
{
    /* §11 2026-08-30: trashMessageでfolder='trash'にした行はPyBitmessage本家のlistSentMessages
     * (WHERE folder='sent')同様、一覧から除外する。除外しないとtrashMessageが実質何も
     * 隠さないことになってしまうため。 */
    static const char *SQL =
        "SELECT msg_id, to_address, from_address, subject, body, status, sent_time, ttl, resend_count "
        "FROM sent WHERE folder = 'sent' ORDER BY sent_time DESC;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    size_t cap = 8;
    size_t count = 0;
    struct bm_sent_message *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        struct bm_sent_message *m = &list[count];
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

        const unsigned char *status = sqlite3_column_text(stmt, 5);
        strncpy(m->status, (const char *)status, sizeof(m->status) - 1);

        m->sent_time = sqlite3_column_int64(stmt, 6);
        m->ttl = sqlite3_column_int64(stmt, 7);
        m->resend_count = sqlite3_column_int(stmt, 8);

        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_sent_message_list_free(struct bm_sent_message *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        free(list[i].subject);
        free(list[i].body);
    }
    free(list);
}

/* §11 2026-08-30: trashMessage API用。PyBitmessage本家api.pyのHandleTrashMessageは
 * helper_inbox.trash(msgid)とUPDATE sent SET folder='trash' WHERE msgid=?を両方無条件に実行し、
 * 該当が無くてもエラーにしない(「存在したと仮定して削除した」という応答仕様)。こちらも同じ
 * 構成にする(該当行数を見ずに常に0を返す)。 */
int bm_messages_store_trash_inbox_message(sqlite3 *db, const unsigned char msg_id[32])
{
    static const char *SQL = "UPDATE inbox SET folder = 'trash' WHERE msg_id = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, msg_id, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_messages_store_trash_sent_message(sqlite3 *db, const unsigned char msg_id[32])
{
    static const char *SQL = "UPDATE sent SET folder = 'trash' WHERE msg_id = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, msg_id, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
