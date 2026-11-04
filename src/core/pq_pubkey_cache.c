#include "pq_pubkey_cache.h"

#include <string.h>

#include "../common/db_common.h"

/* §11 2026-11-04 項目55の段5(pq_pubkey_cache.h参照) */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS pq_pubkey_cache ("
    "tag BLOB PRIMARY KEY, "
    "id BLOB NOT NULL, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "behavior_bitfield INTEGER NOT NULL, "
    "sig_pk BLOB NOT NULL, "
    "kem_pk BLOB NOT NULL, "
    "nonce_trials_per_byte INTEGER NOT NULL, "
    "payload_length_extra_bytes INTEGER NOT NULL, "
    "received_time INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS pq_pubkey_requests ("
    "tag BLOB PRIMARY KEY, "
    "id BLOB NOT NULL, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "requested_time INTEGER NOT NULL"
    ");";

int bm_pq_pubkey_cache_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_pq_pubkey_cache_record_request(sqlite3 *db, uint64_t address_version, uint64_t stream,
                                      const unsigned char id[BM_PQV5_ID_LEN], int64_t requested_time)
{
    static const char *SQL =
        "INSERT INTO pq_pubkey_requests (tag, id, address_version, stream, requested_time) "
        "VALUES (?1,?2,?3,?4,?5) "
        "ON CONFLICT(tag) DO UPDATE SET requested_time=excluded.requested_time;";

    unsigned char tag[32];
    bm_pqv5_derive_secret_and_tag(address_version, stream, id, NULL, tag);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, sizeof(tag), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, id, BM_PQV5_ID_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)address_version);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)stream);
    sqlite3_bind_int64(stmt, 5, requested_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pq_pubkey_cache_find_request(sqlite3 *db, const unsigned char tag[32], struct bm_pq_pubkey_request *out)
{
    static const char *SQL = "SELECT id, address_version, stream FROM pq_pubkey_requests WHERE tag = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, 32, SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_bytes(stmt, 0) == BM_PQV5_ID_LEN)
    {
        memcpy(out->id, sqlite3_column_blob(stmt, 0), BM_PQV5_ID_LEN);
        out->address_version = (uint64_t)sqlite3_column_int64(stmt, 1);
        out->stream = (uint64_t)sqlite3_column_int64(stmt, 2);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int bm_pq_pubkey_cache_clear_request(sqlite3 *db, const unsigned char tag[32])
{
    static const char *SQL = "DELETE FROM pq_pubkey_requests WHERE tag = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pq_pubkey_cache_upsert(sqlite3 *db, const unsigned char id[BM_PQV5_ID_LEN],
                              const struct bm_pq_pubkey_parsed *pubkey, int64_t received_time)
{
    static const char *SQL =
        "INSERT OR REPLACE INTO pq_pubkey_cache (tag, id, address_version, stream, behavior_bitfield, sig_pk, kem_pk, "
        "nonce_trials_per_byte, payload_length_extra_bytes, received_time) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);";

    unsigned char tag[32];
    bm_pqv5_derive_secret_and_tag(pubkey->address_version, pubkey->stream, id, NULL, tag);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, sizeof(tag), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, id, BM_PQV5_ID_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)pubkey->address_version);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)pubkey->stream);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)pubkey->bitfield);
    sqlite3_bind_blob(stmt, 6, pubkey->sig_pk, BM_PQV5_SIG_PK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 7, pubkey->kem_pk, BM_PQV5_KEM_PK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)pubkey->nonce_trials_per_byte);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)pubkey->payload_length_extra_bytes);
    sqlite3_bind_int64(stmt, 10, received_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pq_pubkey_cache_lookup(sqlite3 *db, uint64_t address_version, uint64_t stream,
                              const unsigned char id[BM_PQV5_ID_LEN], struct bm_pq_pubkey_parsed *out)
{
    static const char *SQL =
        "SELECT behavior_bitfield, sig_pk, kem_pk, nonce_trials_per_byte, payload_length_extra_bytes "
        "FROM pq_pubkey_cache WHERE tag = ?1;";

    unsigned char tag[32];
    bm_pqv5_derive_secret_and_tag(address_version, stream, id, NULL, tag);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, sizeof(tag), SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_bytes(stmt, 1) == BM_PQV5_SIG_PK_LEN
        && sqlite3_column_bytes(stmt, 2) == BM_PQV5_KEM_PK_LEN)
    {
        memset(out, 0, sizeof(*out));
        out->address_version = address_version;
        out->stream = stream;
        out->bitfield = (uint32_t)sqlite3_column_int64(stmt, 0);
        memcpy(out->sig_pk, sqlite3_column_blob(stmt, 1), BM_PQV5_SIG_PK_LEN);
        memcpy(out->kem_pk, sqlite3_column_blob(stmt, 2), BM_PQV5_KEM_PK_LEN);
        out->nonce_trials_per_byte = (uint64_t)sqlite3_column_int64(stmt, 3);
        out->payload_length_extra_bytes = (uint64_t)sqlite3_column_int64(stmt, 4);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    return rc;
}
