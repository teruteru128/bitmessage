#include "db_common.h"

#include <stdio.h>

sqlite3 *bm_db_open(const char *filename)
{
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int rc = sqlite3_open_v2(filename, &db, flags, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "sqlite3_open_v2(%s): %s\n", filename, sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    char *err_msg = NULL;
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "PRAGMA journal_mode=WAL (%s): %s\n", filename, err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

int bm_db_init_schema(sqlite3 *db, const char *schema_sql)
{
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "sqlite3_exec(schema): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}
