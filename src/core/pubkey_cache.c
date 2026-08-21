#include "pubkey_cache.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#include "../common/varint.h"
#include "../infra/object.h"
#include "address.h"
#include "crypto.h"

static uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* --- DB操作 --- */

int bm_pubkey_cache_upsert(sqlite3 *db, const struct bm_cached_pubkey *entry, int64_t received_time)
{
    static const char *SQL =
        "INSERT INTO pubkey_cache (ripe, tag, address_version, stream, behavior_bitfield, "
        "signing_pubkey, encryption_pubkey, nonce_trials_per_byte, payload_length_extra_bytes, received_time) "
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) "
        "ON CONFLICT(ripe) DO UPDATE SET tag=excluded.tag, address_version=excluded.address_version, "
        "stream=excluded.stream, behavior_bitfield=excluded.behavior_bitfield, "
        "signing_pubkey=excluded.signing_pubkey, encryption_pubkey=excluded.encryption_pubkey, "
        "nonce_trials_per_byte=excluded.nonce_trials_per_byte, "
        "payload_length_extra_bytes=excluded.payload_length_extra_bytes, "
        "received_time=excluded.received_time;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, entry->ripe, 20, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, entry->tag, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)entry->address_version);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)entry->stream);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)entry->behavior_bitfield);
    sqlite3_bind_blob(stmt, 6, entry->signing_pubkey, 65, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 7, entry->encryption_pubkey, 65, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)entry->nonce_trials_per_byte);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)entry->payload_length_extra_bytes);
    sqlite3_bind_int64(stmt, 10, received_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static int load_row(sqlite3_stmt *stmt, struct bm_cached_pubkey *out)
{
    memset(out, 0, sizeof(*out));

    const void *ripe = sqlite3_column_blob(stmt, 0);
    if (sqlite3_column_bytes(stmt, 0) != 20)
    {
        return -1;
    }
    memcpy(out->ripe, ripe, 20);

    const void *tag = sqlite3_column_blob(stmt, 1);
    if (tag != NULL && sqlite3_column_bytes(stmt, 1) == 32)
    {
        memcpy(out->tag, tag, 32);
    }

    out->address_version = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->stream = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->behavior_bitfield = (uint32_t)sqlite3_column_int64(stmt, 4);

    const void *sign_pub = sqlite3_column_blob(stmt, 5);
    const void *enc_pub = sqlite3_column_blob(stmt, 6);
    if (sqlite3_column_bytes(stmt, 5) != 65 || sqlite3_column_bytes(stmt, 6) != 65)
    {
        return -1;
    }
    memcpy(out->signing_pubkey, sign_pub, 65);
    memcpy(out->encryption_pubkey, enc_pub, 65);

    out->nonce_trials_per_byte = (uint64_t)sqlite3_column_int64(stmt, 7);
    out->payload_length_extra_bytes = (uint64_t)sqlite3_column_int64(stmt, 8);
    return 0;
}

int bm_pubkey_cache_lookup_by_ripe(sqlite3 *db, const unsigned char ripe[20], struct bm_cached_pubkey *out)
{
    static const char *SQL =
        "SELECT ripe, tag, address_version, stream, behavior_bitfield, signing_pubkey, "
        "encryption_pubkey, nonce_trials_per_byte, payload_length_extra_bytes "
        "FROM pubkey_cache WHERE ripe = ?1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int result = (rc == SQLITE_ROW) ? load_row(stmt, out) : -1;
    sqlite3_finalize(stmt);
    return result;
}

int bm_pubkey_cache_lookup_by_tag(sqlite3 *db, const unsigned char tag[32], struct bm_cached_pubkey *out)
{
    static const char *SQL =
        "SELECT ripe, tag, address_version, stream, behavior_bitfield, signing_pubkey, "
        "encryption_pubkey, nonce_trials_per_byte, payload_length_extra_bytes "
        "FROM pubkey_cache WHERE tag = ?1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, tag, 32, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int result = (rc == SQLITE_ROW) ? load_row(stmt, out) : -1;
    sqlite3_finalize(stmt);
    return result;
}

int bm_pubkey_cache_mark_used_personally(sqlite3 *db, const unsigned char ripe[20])
{
    static const char *SQL = "UPDATE pubkey_cache SET used_personally = 1 WHERE ripe = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* --- pending getpubkey要求 --- */

int bm_pubkey_cache_record_request(sqlite3 *db, const unsigned char ripe[20],
                                    uint64_t address_version, uint64_t stream, int64_t requested_time)
{
    static const char *SQL =
        "INSERT INTO pubkey_requests (ripe, address_version, stream, requested_time) "
        "VALUES (?1,?2,?3,?4) "
        "ON CONFLICT(ripe) DO UPDATE SET requested_time=excluded.requested_time;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)address_version);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)stream);
    sqlite3_bind_int64(stmt, 4, requested_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pubkey_cache_has_recent_request(sqlite3 *db, const unsigned char ripe[20],
                                        int64_t now, int64_t max_age_seconds)
{
    static const char *SQL = "SELECT requested_time FROM pubkey_requests WHERE ripe = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return 0;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);

    int recent = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        int64_t requested_time = sqlite3_column_int64(stmt, 0);
        recent = (now - requested_time) < max_age_seconds;
    }
    sqlite3_finalize(stmt);
    return recent;
}

int bm_pubkey_cache_list_pending_requests(sqlite3 *db, struct bm_pubkey_request **out_list, size_t *out_count)
{
    static const char *SQL = "SELECT ripe, address_version, stream FROM pubkey_requests;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }

    size_t cap = 8;
    size_t count = 0;
    struct bm_pubkey_request *list = malloc(sizeof(*list) * cap);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (sqlite3_column_bytes(stmt, 0) != 20)
        {
            continue;
        }
        if (count >= cap)
        {
            cap *= 2;
            list = realloc(list, sizeof(*list) * cap);
        }
        memcpy(list[count].ripe, sqlite3_column_blob(stmt, 0), 20);
        list[count].address_version = (uint64_t)sqlite3_column_int64(stmt, 1);
        list[count].stream = (uint64_t)sqlite3_column_int64(stmt, 2);
        count++;
    }
    sqlite3_finalize(stmt);

    *out_list = list;
    *out_count = count;
    return 0;
}

void bm_pubkey_request_list_free(struct bm_pubkey_request *list)
{
    free(list);
}

int bm_pubkey_cache_clear_request(sqlite3 *db, const unsigned char ripe[20])
{
    static const char *SQL = "DELETE FROM pubkey_requests WHERE ripe = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pubkey_cache_set_self_response(sqlite3 *db, const unsigned char ripe[20],
                                       const unsigned char object_hash[32], int64_t expires_time)
{
    static const char *SQL =
        "INSERT INTO self_pubkey_response_cache (ripe, object_hash, expires_time) VALUES (?1,?2,?3) "
        "ON CONFLICT(ripe) DO UPDATE SET object_hash=excluded.object_hash, expires_time=excluded.expires_time;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, object_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, expires_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_pubkey_cache_get_self_response(sqlite3 *db, const unsigned char ripe[20], int64_t now,
                                       unsigned char out_hash[32])
{
    static const char *SQL = "SELECT object_hash, expires_time FROM self_pubkey_response_cache WHERE ripe = ?1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_blob(stmt, 1, ripe, 20, SQLITE_TRANSIENT);

    int found = 0;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        int64_t expires_time = sqlite3_column_int64(stmt, 1);
        if (expires_time > now)
        {
            const void *hash = sqlite3_column_blob(stmt, 0);
            if (sqlite3_column_bytes(stmt, 0) == 32)
            {
                memcpy(out_hash, hash, 32);
                found = 1;
            }
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
    {
        return -1;
    }
    return found;
}

/* --- objectパース --- */

int bm_parse_pubkey_v2(const unsigned char *object, size_t object_len, struct bm_cached_pubkey *out)
{
    struct bm_object_header hdr;
    if (bm_object_parse_header(object, object_len, &hdr) != 0)
    {
        return -1;
    }
    if (hdr.object_type != BM_OBJECT_PUBKEY || hdr.version != 2)
    {
        return -1;
    }

    const unsigned char *p = object + hdr.header_len;
    size_t remaining = object_len - hdr.header_len;
    if (remaining != 4 + 64 + 64)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->address_version = 2;
    out->stream = hdr.stream;
    out->behavior_bitfield = read_be32(p);
    out->signing_pubkey[0] = 0x04;
    memcpy(out->signing_pubkey + 1, p + 4, 64);
    out->encryption_pubkey[0] = 0x04;
    memcpy(out->encryption_pubkey + 1, p + 4 + 64, 64);
    bm_address_calc_ripe(out->signing_pubkey, out->encryption_pubkey, out->ripe);
    return 0;
}

int bm_parse_pubkey_v3(const unsigned char *object, size_t object_len, struct bm_cached_pubkey *out)
{
    struct bm_object_header hdr;
    if (bm_object_parse_header(object, object_len, &hdr) != 0)
    {
        return -1;
    }
    if (hdr.object_type != BM_OBJECT_PUBKEY || hdr.version != 3)
    {
        return -1;
    }

    const unsigned char *p = object + hdr.header_len;
    size_t remaining = object_len - hdr.header_len;
    size_t offset = 0;

    if (offset + 4 + 64 + 64 > remaining)
    {
        return -1;
    }
    uint32_t bitfield = read_be32(p + offset);
    offset += 4;
    unsigned char sign_pub[65];
    sign_pub[0] = 0x04;
    memcpy(sign_pub + 1, p + offset, 64);
    offset += 64;
    unsigned char enc_pub[65];
    enc_pub[0] = 0x04;
    memcpy(enc_pub + 1, p + offset, 64);
    offset += 64;

    uint64_t nonce_trials = 0;
    uint64_t extra_bytes = 0;
    size_t consumed = bm_varint_decode(p + offset, remaining - offset, &nonce_trials);
    if (consumed == 0)
    {
        return -1;
    }
    offset += consumed;
    consumed = bm_varint_decode(p + offset, remaining - offset, &extra_bytes);
    if (consumed == 0)
    {
        return -1;
    }
    offset += consumed;

    size_t presig_offset = offset;
    uint64_t sig_len = 0;
    consumed = bm_varint_decode(p + offset, remaining - offset, &sig_len);
    if (consumed == 0 || offset + consumed + sig_len > remaining)
    {
        return -1;
    }
    offset += consumed;
    const unsigned char *sig = p + offset;

    size_t header_no_nonce_len = hdr.header_len - 8;
    unsigned char *to_sign = malloc(header_no_nonce_len + presig_offset);
    memcpy(to_sign, object + 8, header_no_nonce_len);
    memcpy(to_sign + header_no_nonce_len, p, presig_offset);
    int ok = bm_crypto_verify(to_sign, header_no_nonce_len + presig_offset, sig, sig_len, sign_pub);
    free(to_sign);
    if (ok != 1)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->address_version = 3;
    out->stream = hdr.stream;
    out->behavior_bitfield = bitfield;
    memcpy(out->signing_pubkey, sign_pub, 65);
    memcpy(out->encryption_pubkey, enc_pub, 65);
    out->nonce_trials_per_byte = nonce_trials;
    out->payload_length_extra_bytes = extra_bytes;
    bm_address_calc_ripe(out->signing_pubkey, out->encryption_pubkey, out->ripe);
    return 0;
}

int bm_parse_pubkey_v4(const unsigned char *object, size_t object_len,
                        const unsigned char candidate_ripe[20], uint64_t candidate_version,
                        uint64_t candidate_stream, struct bm_cached_pubkey *out)
{
    struct bm_object_header hdr;
    if (bm_object_parse_header(object, object_len, &hdr) != 0)
    {
        return -1;
    }
    if (hdr.object_type != BM_OBJECT_PUBKEY || hdr.version != 4)
    {
        return -1;
    }
    if (hdr.header_len + 32 > object_len)
    {
        return -1;
    }

    const unsigned char *tag = object + hdr.header_len;
    const unsigned char *ciphertext = tag + 32;
    size_t ciphertext_len = object_len - hdr.header_len - 32;

    unsigned char priv_enc[32];
    unsigned char expected_tag[32];
    bm_address_derive_secret_and_tag(candidate_version, candidate_stream, candidate_ripe, priv_enc, expected_tag);
    if (memcmp(tag, expected_tag, 32) != 0)
    {
        OPENSSL_cleanse(priv_enc, sizeof(priv_enc));
        return -1; /* candidate宛てではない */
    }

    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    int rc = bm_crypto_ecies_decrypt(ciphertext, ciphertext_len, priv_enc, &decrypted, &decrypted_len);
    OPENSSL_cleanse(priv_enc, sizeof(priv_enc));
    if (rc != 0)
    {
        return -1;
    }

    size_t p = 0;
    if (p + 4 + 64 + 64 > decrypted_len)
    {
        free(decrypted);
        return -1;
    }
    uint32_t bitfield = read_be32(decrypted + p);
    p += 4;
    unsigned char sign_pub[65];
    sign_pub[0] = 0x04;
    memcpy(sign_pub + 1, decrypted + p, 64);
    p += 64;
    unsigned char enc_pub[65];
    enc_pub[0] = 0x04;
    memcpy(enc_pub + 1, decrypted + p, 64);
    p += 64;

    uint64_t nonce_trials = 0;
    uint64_t extra_bytes = 0;
    size_t consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &nonce_trials);
    if (consumed == 0)
    {
        free(decrypted);
        return -1;
    }
    p += consumed;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &extra_bytes);
    if (consumed == 0)
    {
        free(decrypted);
        return -1;
    }
    p += consumed;

    size_t presig_offset = p;
    uint64_t sig_len = 0;
    consumed = bm_varint_decode(decrypted + p, decrypted_len - p, &sig_len);
    if (consumed == 0 || p + consumed + sig_len > decrypted_len)
    {
        free(decrypted);
        return -1;
    }
    p += consumed;
    const unsigned char *sig = decrypted + p;

    /* 署名対象 = 平文部(ヘッダ+tag、nonce抜き) || dataToEncrypt(署名を除く) */
    size_t header_no_nonce_len = hdr.header_len - 8;
    unsigned char *to_sign = malloc(header_no_nonce_len + 32 + presig_offset);
    memcpy(to_sign, object + 8, header_no_nonce_len);
    memcpy(to_sign + header_no_nonce_len, tag, 32);
    memcpy(to_sign + header_no_nonce_len + 32, decrypted, presig_offset);
    int ok = bm_crypto_verify(to_sign, header_no_nonce_len + 32 + presig_offset, sig, sig_len, sign_pub);
    free(to_sign);
    if (ok != 1)
    {
        free(decrypted);
        return -1;
    }

    /* 整合性チェック: 復号できたpubkeyから計算したripeがcandidateと一致するはず */
    unsigned char computed_ripe[20];
    bm_address_calc_ripe(sign_pub, enc_pub, computed_ripe);
    if (memcmp(computed_ripe, candidate_ripe, 20) != 0)
    {
        free(decrypted);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->address_version = candidate_version;
    out->stream = candidate_stream;
    memcpy(out->ripe, candidate_ripe, 20);
    memcpy(out->tag, tag, 32);
    out->behavior_bitfield = bitfield;
    memcpy(out->signing_pubkey, sign_pub, 65);
    memcpy(out->encryption_pubkey, enc_pub, 65);
    out->nonce_trials_per_byte = nonce_trials;
    out->payload_length_extra_bytes = extra_bytes;

    free(decrypted);
    return 0;
}
