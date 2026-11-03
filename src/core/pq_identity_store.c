#include "pq_identity_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/db_common.h"

/* §11 2026-11-04 項目55の段3。列の意味はpq_identity_store.hのstruct bm_pq_identity_rowと同じ */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS pq_identities ("
    "address TEXT PRIMARY KEY, "
    "label TEXT NOT NULL DEFAULT '', "
    "enabled INTEGER NOT NULL DEFAULT 1, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "id BLOB NOT NULL, "
    "sig_pk BLOB NOT NULL, "
    "kem_pk BLOB NOT NULL, "
    "kdf_algo TEXT NOT NULL DEFAULT 'scrypt', "
    "kdf_salt BLOB NOT NULL, "
    "kdf_params TEXT NOT NULL, "
    "wrapped_seeds BLOB NOT NULL, "
    "nonce_trials_per_byte INTEGER NOT NULL DEFAULT 1000, "
    "payload_length_extra_bytes INTEGER NOT NULL DEFAULT 1000, "
    "created_time INTEGER NOT NULL"
    ");";

int bm_pq_identity_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_pq_identity_store_insert(sqlite3 *db, const struct bm_pq_identity_row *row)
{
    static const char *SQL =
        "INSERT INTO pq_identities (address, label, enabled, address_version, stream, id, sig_pk, kem_pk, "
        "kdf_algo, kdf_salt, kdf_params, wrapped_seeds, nonce_trials_per_byte, payload_length_extra_bytes, "
        "created_time) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, row->address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, row->enabled);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)row->address_version);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)row->stream);
    sqlite3_bind_blob(stmt, 6, row->id, BM_PQV5_ID_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 7, row->sig_pk, BM_PQV5_SIG_PK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 8, row->kem_pk, BM_PQV5_KEM_PK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, row->kdf_algo, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 10, row->kdf_salt, BM_IDENTITY_KDF_SALT_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, row->kdf_params, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 12, row->wrapped_seeds, BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 13, (sqlite3_int64)row->nonce_trials_per_byte);
    sqlite3_bind_int64(stmt, 14, (sqlite3_int64)row->payload_length_extra_bytes);
    sqlite3_bind_int64(stmt, 15, row->created_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* BLOB列を固定長のバッファへ写す。長さが期待と違えば非0(壊れた行を黙って読まない) */
static int copy_blob(sqlite3_stmt *stmt, int col, unsigned char *out, size_t expected_len)
{
    const void *blob = sqlite3_column_blob(stmt, col);
    if (blob == NULL || (size_t)sqlite3_column_bytes(stmt, col) != expected_len)
    {
        return -1;
    }
    memcpy(out, blob, expected_len);
    return 0;
}

static void copy_text(sqlite3_stmt *stmt, int col, char *out, size_t out_size)
{
    const unsigned char *text = sqlite3_column_text(stmt, col);
    snprintf(out, out_size, "%s", text != NULL ? (const char *)text : "");
}

int bm_pq_identity_store_load(sqlite3 *db, const char *address, struct bm_pq_identity_row *out)
{
    static const char *SQL =
        "SELECT address, label, enabled, address_version, stream, id, sig_pk, kem_pk, kdf_algo, kdf_salt, "
        "kdf_params, wrapped_seeds, nonce_trials_per_byte, payload_length_extra_bytes, created_time "
        "FROM pq_identities WHERE address = ?1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        memset(out, 0, sizeof(*out));
        copy_text(stmt, 0, out->address, sizeof(out->address));
        copy_text(stmt, 1, out->label, sizeof(out->label));
        out->enabled = sqlite3_column_int(stmt, 2);
        out->address_version = (uint64_t)sqlite3_column_int64(stmt, 3);
        out->stream = (uint64_t)sqlite3_column_int64(stmt, 4);
        copy_text(stmt, 8, out->kdf_algo, sizeof(out->kdf_algo));
        copy_text(stmt, 10, out->kdf_params, sizeof(out->kdf_params));
        out->nonce_trials_per_byte = (uint64_t)sqlite3_column_int64(stmt, 12);
        out->payload_length_extra_bytes = (uint64_t)sqlite3_column_int64(stmt, 13);
        out->created_time = sqlite3_column_int64(stmt, 14);
        if (copy_blob(stmt, 5, out->id, BM_PQV5_ID_LEN) == 0
            && copy_blob(stmt, 6, out->sig_pk, BM_PQV5_SIG_PK_LEN) == 0
            && copy_blob(stmt, 7, out->kem_pk, BM_PQV5_KEM_PK_LEN) == 0
            && copy_blob(stmt, 9, out->kdf_salt, BM_IDENTITY_KDF_SALT_LEN) == 0
            && copy_blob(stmt, 11, out->wrapped_seeds, BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN) == 0)
        {
            rc = 0;
        }
    }
    sqlite3_finalize(stmt);
    return rc;
}

int bm_pq_identity_store_delete(sqlite3 *db, const char *address)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM pq_identities WHERE address = ?1;", -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pq_identity_store_list(sqlite3 *db, struct bm_identity_summary **out_list, size_t *out_count)
{
    *out_list = NULL;
    *out_count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT address, label, enabled FROM pq_identities ORDER BY created_time, address;",
                           -1, &stmt, NULL)
        != SQLITE_OK)
    {
        return -1;
    }
    size_t cap = 0;
    struct bm_identity_summary *list = NULL;
    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        if (*out_count == cap)
        {
            size_t new_cap = cap == 0 ? 8 : cap * 2;
            struct bm_identity_summary *grown = realloc(list, new_cap * sizeof(*grown));
            if (grown == NULL)
            {
                free(list);
                sqlite3_finalize(stmt);
                return -1;
            }
            list = grown;
            cap = new_cap;
        }
        struct bm_identity_summary *s = &list[*out_count];
        memset(s, 0, sizeof(*s));
        copy_text(stmt, 0, s->address, sizeof(s->address));
        copy_text(stmt, 1, s->label, sizeof(s->label));
        s->enabled = sqlite3_column_int(stmt, 2);
        s->is_chan = 0;
        (*out_count)++;
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE)
    {
        free(list);
        *out_count = 0;
        return -1;
    }
    *out_list = list;
    return 0;
}
