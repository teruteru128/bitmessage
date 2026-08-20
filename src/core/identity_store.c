#include "identity_store.h"

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
    "CREATE INDEX IF NOT EXISTS idx_pubkey_cache_tag ON pubkey_cache(tag);";

int bm_identity_store_init_schema(sqlite3 *db)
{
    return bm_db_init_schema(db, SCHEMA_SQL);
}
