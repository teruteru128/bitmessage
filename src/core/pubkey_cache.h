#ifndef BM_CORE_PUBKEY_CACHE_H
#define BM_CORE_PUBKEY_CACHE_H

/*
 * pubkey_cache(identity.db、§2.3)の操作と、type=pubkeyオブジェクトのパース/検証。
 * message_builder.cのbm_build_pubkey_v2/v3/v4(構築)と対になる、受信側の逆方向処理。
 *
 * v1スコープ: 実際のネットワーク受信オブジェクトをここへ流し込む配線(object_sync_thread)は
 * まだ無い(§1のTODO)。ここでは自己完結したパース/検証/DB操作のみを提供し、
 * message_builder.cで組み立てたテスト用objectで正しさを検証する。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

struct bm_cached_pubkey
{
    unsigned char ripe[20];
    unsigned char tag[32];    /* version<4では全0(未使用) */
    uint64_t address_version;
    uint64_t stream;
    uint32_t behavior_bitfield;
    unsigned char signing_pubkey[65];
    unsigned char encryption_pubkey[65];
    uint64_t nonce_trials_per_byte;      /* version<3では0(未定義) */
    uint64_t payload_length_extra_bytes; /* 同上 */
};

/* --- DB操作(identity.db) --- */

/* 既存行があればUPDATE、なければINSERT。成功時0 */
int bm_pubkey_cache_upsert(sqlite3 *db, const struct bm_cached_pubkey *entry, int64_t received_time);

/* 見つかれば0、見つからない/エラー時は非0 */
int bm_pubkey_cache_lookup_by_ripe(sqlite3 *db, const unsigned char ripe[20], struct bm_cached_pubkey *out);
int bm_pubkey_cache_lookup_by_tag(sqlite3 *db, const unsigned char tag[32], struct bm_cached_pubkey *out);

/* 自分がこのpubkeyを使って送信した(used_personally=1)ことを記録する。掃除対象から除外するため。成功時0 */
int bm_pubkey_cache_mark_used_personally(sqlite3 *db, const unsigned char ripe[20]);

/* --- objectパース(§5.2の逆方向) --- */

/* type=pubkey, version=2の完全なobject(nonce込み)をパースする。署名が無いため構造検証のみ。成功時0 */
int bm_parse_pubkey_v2(const unsigned char *object, size_t object_len, struct bm_cached_pubkey *out);

/* version=3。埋め込み署名を検証する(失敗時は非0を返す)。成功時0 */
int bm_parse_pubkey_v3(const unsigned char *object, size_t object_len, struct bm_cached_pubkey *out);

/*
 * version=4。tagは平文で読めるが、暗号文を解くには「これは誰のpubkeyか」というあて推量の
 * アドレス(candidate_ripe/version/stream)が必要(§5.2: privEnc = SHA512(varint(version)||
 * varint(stream)||ripe)[0:32])。candidate宛だと仮定して復号・署名検証を試みる。
 * 事前にbm_address_derive_secret_and_tagで計算したtagとobject中のtagを比較すれば、
 * 復号を試みる前に見込みのないobjectを弾ける。成功時0(outのripeはcandidate_ripeと一致する)。
 */
int bm_parse_pubkey_v4(const unsigned char *object, size_t object_len,
                        const unsigned char candidate_ripe[20], uint64_t candidate_version,
                        uint64_t candidate_stream, struct bm_cached_pubkey *out);

#endif /* BM_CORE_PUBKEY_CACHE_H */
