#include "identity_store.h"

#include <stdlib.h>
#include <string.h>

#include "../common/db_common.h"

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS identities ("
    "address TEXT PRIMARY KEY, "
    "label TEXT NOT NULL DEFAULT '', "
    "enabled INTEGER NOT NULL DEFAULT 1, "
    "is_chan INTEGER NOT NULL DEFAULT 0, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "signing_pubkey BLOB NOT NULL, "
    "encryption_pubkey BLOB NOT NULL, "
    "kdf_algo TEXT NOT NULL DEFAULT 'scrypt', "
    "kdf_salt BLOB NOT NULL, "
    "kdf_params TEXT NOT NULL, "
    "wrapped_priv_signing_key BLOB NOT NULL, "
    "wrapped_priv_encryption_key BLOB NOT NULL, "
    "nonce_trials_per_byte INTEGER NOT NULL DEFAULT 1000, "
    "payload_length_extra_bytes INTEGER NOT NULL DEFAULT 1000, "
    "created_time INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS pubkey_cache ("
    "ripe BLOB PRIMARY KEY, "
    "tag BLOB, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "behavior_bitfield INTEGER NOT NULL, "
    "signing_pubkey BLOB NOT NULL, "
    "encryption_pubkey BLOB NOT NULL, "
    "nonce_trials_per_byte INTEGER, "
    "payload_length_extra_bytes INTEGER, "
    "used_personally INTEGER NOT NULL DEFAULT 0, "
    "received_time INTEGER NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_pubkey_cache_tag ON pubkey_cache(tag);"
    "CREATE TABLE IF NOT EXISTS pubkey_requests ("
    "ripe BLOB PRIMARY KEY, "
    "address_version INTEGER NOT NULL, "
    "stream INTEGER NOT NULL, "
    "requested_time INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS self_pubkey_response_cache ("
    "ripe BLOB PRIMARY KEY, "
    "object_hash BLOB NOT NULL, "
    "expires_time INTEGER NOT NULL"
    ");";

int bm_identity_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}

int bm_identity_store_insert(sqlite3 *db, const struct bm_identity_row *row)
{
    static const char *SQL =
        "INSERT INTO identities (address, label, enabled, is_chan, address_version, stream, "
        "signing_pubkey, encryption_pubkey, kdf_algo, kdf_salt, kdf_params, "
        "wrapped_priv_signing_key, wrapped_priv_encryption_key, "
        "nonce_trials_per_byte, payload_length_extra_bytes, created_time) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, row->address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, row->enabled);
    sqlite3_bind_int(stmt, 4, row->is_chan);
    sqlite3_bind_int(stmt, 5, row->address_version);
    sqlite3_bind_int(stmt, 6, row->stream);
    sqlite3_bind_blob(stmt, 7, row->signing_pubkey, 65, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 8, row->encryption_pubkey, 65, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, row->kdf_algo, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 10, row->kdf_salt, BM_IDENTITY_KDF_SALT_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, row->kdf_params, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 12, row->wrapped_priv_signing_key, BM_IDENTITY_WRAPPED_KEY_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 13, row->wrapped_priv_encryption_key, BM_IDENTITY_WRAPPED_KEY_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 14, (sqlite3_int64)row->nonce_trials_per_byte);
    sqlite3_bind_int64(stmt, 15, (sqlite3_int64)row->payload_length_extra_bytes);
    sqlite3_bind_int64(stmt, 16, row->created_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_identity_store_load(sqlite3 *db, const char *address, struct bm_identity_row *out)
{
    static const char *SQL =
        "SELECT address, label, enabled, is_chan, address_version, stream, "
        "signing_pubkey, encryption_pubkey, kdf_algo, kdf_salt, kdf_params, "
        "wrapped_priv_signing_key, wrapped_priv_encryption_key, "
        "nonce_trials_per_byte, payload_length_extra_bytes, created_time "
        "FROM identities WHERE address = ?1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, address, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    strncpy(out->address, (const char *)sqlite3_column_text(stmt, 0), BM_IDENTITY_ADDRESS_MAX - 1);
    const unsigned char *label = sqlite3_column_text(stmt, 1);
    if (label != NULL)
    {
        strncpy(out->label, (const char *)label, BM_IDENTITY_LABEL_MAX - 1);
    }
    out->enabled = sqlite3_column_int(stmt, 2);
    out->is_chan = sqlite3_column_int(stmt, 3);
    out->address_version = sqlite3_column_int(stmt, 4);
    out->stream = sqlite3_column_int(stmt, 5);

    const void *sign_pub = sqlite3_column_blob(stmt, 6);
    int sign_pub_len = sqlite3_column_bytes(stmt, 6);
    const void *enc_pub = sqlite3_column_blob(stmt, 7);
    int enc_pub_len = sqlite3_column_bytes(stmt, 7);
    if (sign_pub_len != 65 || enc_pub_len != 65)
    {
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(out->signing_pubkey, sign_pub, 65);
    memcpy(out->encryption_pubkey, enc_pub, 65);

    const unsigned char *kdf_algo = sqlite3_column_text(stmt, 8);
    if (kdf_algo != NULL)
    {
        strncpy(out->kdf_algo, (const char *)kdf_algo, BM_IDENTITY_KDF_ALGO_MAX - 1);
    }
    const void *salt = sqlite3_column_blob(stmt, 9);
    int salt_len = sqlite3_column_bytes(stmt, 9);
    if (salt_len != BM_IDENTITY_KDF_SALT_LEN)
    {
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(out->kdf_salt, salt, BM_IDENTITY_KDF_SALT_LEN);

    const unsigned char *kdf_params = sqlite3_column_text(stmt, 10);
    if (kdf_params != NULL)
    {
        strncpy(out->kdf_params, (const char *)kdf_params, BM_IDENTITY_KDF_PARAMS_MAX - 1);
    }

    const void *wrapped_sign = sqlite3_column_blob(stmt, 11);
    int wrapped_sign_len = sqlite3_column_bytes(stmt, 11);
    const void *wrapped_enc = sqlite3_column_blob(stmt, 12);
    int wrapped_enc_len = sqlite3_column_bytes(stmt, 12);
    if (wrapped_sign_len != BM_IDENTITY_WRAPPED_KEY_LEN || wrapped_enc_len != BM_IDENTITY_WRAPPED_KEY_LEN)
    {
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(out->wrapped_priv_signing_key, wrapped_sign, BM_IDENTITY_WRAPPED_KEY_LEN);
    memcpy(out->wrapped_priv_encryption_key, wrapped_enc, BM_IDENTITY_WRAPPED_KEY_LEN);

    out->nonce_trials_per_byte = (uint64_t)sqlite3_column_int64(stmt, 13);
    out->payload_length_extra_bytes = (uint64_t)sqlite3_column_int64(stmt, 14);
    out->created_time = sqlite3_column_int64(stmt, 15);

    sqlite3_finalize(stmt);
    return 0;
}

int bm_identity_store_delete(sqlite3 *db, const char *address)
{
    static const char *SQL = "DELETE FROM identities WHERE address = ?1;";
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

int bm_identity_store_set_is_chan(sqlite3 *db, const char *address, int is_chan)
{
    static const char *SQL = "UPDATE identities SET is_chan = ?1 WHERE address = ?2;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, is_chan);
    sqlite3_bind_text(stmt, 2, address, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_identity_store_list(sqlite3 *db, struct bm_identity_summary **out_list, size_t *out_count)
{
    static const char *SQL = "SELECT address, label, enabled, is_chan FROM identities ORDER BY created_time;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    size_t cap = 8;
    size_t count = 0;
    struct bm_identity_summary *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        memset(&list[count], 0, sizeof(list[count]));
        const unsigned char *address = sqlite3_column_text(stmt, 0);
        strncpy(list[count].address, (const char *)address, BM_IDENTITY_ADDRESS_MAX - 1);
        const unsigned char *label = sqlite3_column_text(stmt, 1);
        if (label != NULL)
        {
            strncpy(list[count].label, (const char *)label, BM_IDENTITY_LABEL_MAX - 1);
        }
        list[count].enabled = sqlite3_column_int(stmt, 2);
        list[count].is_chan = sqlite3_column_int(stmt, 3);
        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}
