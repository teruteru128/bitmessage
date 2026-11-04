#ifndef BM_CORE_PQ_PUBKEY_CACHE_H
#define BM_CORE_PQ_PUBKEY_CACHE_H

/*
 * §11 2026-11-04 項目55の段5: 他人のv5公開鍵のキャッシュと、発行したv5 getpubkeyの記録
 * (identity.db、DESIGN-PQ.md §7.2)。BM_HAVE_PQのビルドでのみコンパイルされる。
 *
 * v4以前のpubkey_cache/pubkey_requestsとは別の表にした。v4の表はripe(20byte)がキーで鍵も
 * 65byte固定なので(struct bm_cached_pubkey)、v5の行を混ぜると既存の全ての読み手が誤読しうる
 * (v5 identityをidentitiesと別の表にしたのと同じ理由、段3)。
 *
 * キーはどちらの表もtag。tagはversion・stream・idから決まり(address_v5.h)、pubkeyオブジェクトに
 * 平文で載っているので、受信したobjectから対応する要求を直接引ける(v4は要求を全件列挙して
 * 順に試している)。
 */

#include <sqlite3.h>
#include <stdint.h>

#include "../pq/address_v5.h"
#include "../pq/pq_object.h"

struct bm_pq_pubkey_request
{
    uint64_t address_version;
    uint64_t stream;
    unsigned char id[BM_PQV5_ID_LEN];
};

/* bm_identity_store_init_schemaから呼ばれる(BM_HAVE_PQのビルドのみ)。成功時0 */
int bm_pq_pubkey_cache_init_schema(sqlite3 *db);

/* getpubkeyを発行したことを記録する。既存行があればrequested_timeだけ更新する。成功時0 */
int bm_pq_pubkey_cache_record_request(sqlite3 *db, uint64_t address_version, uint64_t stream,
                                      const unsigned char id[BM_PQV5_ID_LEN], int64_t requested_time);

/* max_age_seconds以内に同じtagのgetpubkeyを発行済みなら1、そうでなければ0
 * (bm_pubkey_cache_has_recent_requestのv5版。短時間に同じ宛先へ何度も発行しないため) */
int bm_pq_pubkey_cache_has_recent_request(sqlite3 *db, const unsigned char tag[32], int64_t now,
                                          int64_t max_age_seconds);

/* tagに対応する未解決の要求があれば0でoutを埋める。無い場合・エラー時は非0 */
int bm_pq_pubkey_cache_find_request(sqlite3 *db, const unsigned char tag[32], struct bm_pq_pubkey_request *out);

/* 要求を完了扱いにする。該当行が無くてもエラーにしない。成功時0 */
int bm_pq_pubkey_cache_clear_request(sqlite3 *db, const unsigned char tag[32]);

/*
 * 検証済みのpubkey(bm_pq_parse_pubkeyの結果)を保存する。既存行があれば置き換える。
 * idは署名と共に検証した要求側の値を渡す。成功時0
 */
int bm_pq_pubkey_cache_upsert(sqlite3 *db, const unsigned char id[BM_PQV5_ID_LEN],
                              const struct bm_pq_pubkey_parsed *pubkey, int64_t received_time);

/*
 * §11 2026-11-04 項目57: v5のmsg/broadcastに載っていた差出人の公開鍵を保存し、同じ宛先の未解決の
 * 要求があれば消す。v5のmsgが公開鍵(3200byte)を丸ごと運ぶのは、返信のためにgetpubkeyを出さずに
 * 済ませるため(DESIGN-PQ.md §10.4)で、本家もprocessmsg/processbroadcastで同じことをしている
 * ("Let's store the public key in case we want to reply to this person.")。呼び出し側は署名を
 * 検証済みで、idは中の公開鍵から再計算したものを渡すので、別人の鍵をこのアドレスに結び付けることは
 * できない。行を増やすにはPoWを払って自分宛に開封できるmsgを作る必要がある。成功時0
 */
int bm_pq_pubkey_cache_store_sender(sqlite3 *db, uint64_t address_version, uint64_t stream,
                                    const unsigned char id[BM_PQV5_ID_LEN], uint32_t bitfield,
                                    const unsigned char sig_pk[BM_PQV5_SIG_PK_LEN],
                                    const unsigned char kem_pk[BM_PQV5_KEM_PK_LEN], uint64_t nonce_trials_per_byte,
                                    uint64_t payload_length_extra_bytes, int64_t now);

/* (version, stream, id)のpubkeyがあれば0でoutを埋める。無い場合・エラー時は非0 */
int bm_pq_pubkey_cache_lookup(sqlite3 *db, uint64_t address_version, uint64_t stream,
                              const unsigned char id[BM_PQV5_ID_LEN], struct bm_pq_pubkey_parsed *out);

#endif /* BM_CORE_PQ_PUBKEY_CACHE_H */
