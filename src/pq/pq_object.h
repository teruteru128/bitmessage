#ifndef BM_PQ_OBJECT_H
#define BM_PQ_OBJECT_H

/*
 * v5(ポスト量子)オブジェクトの組み立て・解析。DESIGN-PQ.md §7。
 *
 * objectType(0..3)は既存のまま、objectVersionだけを新しい値に上げる方式:
 *   getpubkey  type=0 objectVersion=5
 *   pubkey     type=1 objectVersion=5
 *   msg        type=2 objectVersion=2
 *   broadcast  type=3 objectVersion=6
 * 既存ノードはこれらを「中継はするが自分では解釈しない」ことがPyBitmessage・
 * MiNode-Refined・本実装のソース確認で裏付けられている(DESIGN-PQ.md §2)。
 *
 * ビルダーの戻り値は既存のcore/message_builder.hと同じ「PoW前(nonce抜き)のペイロード」。
 * パーサは逆に、ネットワークから届く形(先頭8byteのPoW nonce込み)を受け取る。
 */

#include <stddef.h>
#include <stdint.h>

#include "address_v5.h"
#include "pq_hybrid.h"

/*
 * §11 2026-09-18 オブジェクト種別ごとの署名ドメイン分離ラベルは削除した(ユーザー指摘)。
 * 署名対象には必ず共通ヘッダ(objectType 4byte + objectVersion)が含まれるので、
 * 種別間の分離は既に達成されており重複だった。v4も同じ理屈でラベル無し。
 */

#define BM_PQ_MSG_OBJECT_VERSION 2
#define BM_PQ_PUBKEY_OBJECT_VERSION 5
#define BM_PQ_GETPUBKEY_OBJECT_VERSION 5
#define BM_PQ_BROADCAST_OBJECT_VERSION 6

/* 送信元として使うidentityに付随する、アドレス自体には含まれないパラメータ */
struct bm_pq_sender_info
{
    const struct bm_pqv5_identity *identity;
    uint32_t bitfield;
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
};

/* --- getpubkey (type=0, objectVersion=5) --- */
unsigned char *bm_pq_build_getpubkey(uint64_t address_version, uint64_t stream,
                                      const unsigned char id[BM_PQV5_ID_LEN],
                                      uint64_t expires_time, size_t *out_len);

/* --- pubkey (type=1, objectVersion=5) --- */
unsigned char *bm_pq_build_pubkey(const struct bm_pq_sender_info *from, uint64_t expires_time,
                                   size_t *out_len);

struct bm_pq_pubkey_parsed
{
    uint64_t address_version;
    uint64_t stream;
    uint32_t bitfield;
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
};

/*
 * 候補アドレス(version/stream/id)を1件受け取り、tagが一致したらアドレス由来鍵で
 * 開封し、署名検証と「中の公開鍵から再計算したidが候補と一致するか」まで確認する。
 * 成功時0。tag不一致(=この候補宛てではない)も非0で返る(安価な早期棄却)。
 */
int bm_pq_parse_pubkey(const unsigned char *object, size_t object_len,
                        uint64_t address_version, uint64_t stream,
                        const unsigned char id[BM_PQV5_ID_LEN],
                        struct bm_pq_pubkey_parsed *out);

/* --- msg (type=2, objectVersion=2) --- */

/*
 * to_kem_pkは宛先の公開鍵(pubkeyオブジェクト由来)。to_idはなりすまし転送対策として
 * 平文中に埋める宛先identifier。ackはNULL可。
 */
unsigned char *bm_pq_build_msg(const struct bm_pq_sender_info *from, uint64_t to_stream,
                                const unsigned char to_id[BM_PQV5_ID_LEN],
                                const unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN],
                                uint64_t encoding, const unsigned char *message, size_t message_len,
                                const unsigned char *ack, size_t ack_len,
                                uint64_t expires_time, size_t *out_len);

struct bm_pq_msg_parsed
{
    uint64_t from_address_version;
    uint64_t from_stream;
    uint32_t bitfield;
    unsigned char from_sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char from_kem_pk[BM_PQV5_KEM_PK_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    unsigned char to_id[BM_PQV5_ID_LEN];
    unsigned char from_id[BM_PQV5_ID_LEN]; /* 中の公開鍵から再計算したもの */
    uint64_t encoding;
    unsigned char *message; /* malloc、bm_pq_msg_parsed_freeで解放 */
    size_t message_len;
    unsigned char *ack;
    size_t ack_len;
};

/*
 * 自分のKEM秘密鍵で開封を試みる。開封成功後、署名検証まで行う。
 * to_idが自分のidと一致するかの検証は呼び出し側の責務(v4のtoRipe検証と同じ)。成功時0。
 */
int bm_pq_parse_msg(const unsigned char *object, size_t object_len,
                     const unsigned char kem_sk[BM_PQV5_KEM_SK_LEN],
                     struct bm_pq_msg_parsed *out);
void bm_pq_msg_parsed_free(struct bm_pq_msg_parsed *parsed);

/* --- broadcast (type=3, objectVersion=6) --- */
unsigned char *bm_pq_build_broadcast(const struct bm_pq_sender_info *from,
                                      uint64_t encoding, const unsigned char *message, size_t message_len,
                                      uint64_t expires_time, size_t *out_len);

struct bm_pq_broadcast_parsed
{
    uint64_t from_address_version;
    uint64_t from_stream;
    uint32_t bitfield;
    unsigned char from_sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char from_kem_pk[BM_PQV5_KEM_PK_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    unsigned char from_id[BM_PQV5_ID_LEN];
    uint64_t encoding;
    unsigned char *message;
    size_t message_len;
};

/* 購読中アドレス(version/stream/id)を候補として1件試す。tag不一致なら即失敗。成功時0 */
int bm_pq_parse_broadcast(const unsigned char *object, size_t object_len,
                           uint64_t address_version, uint64_t stream,
                           const unsigned char id[BM_PQV5_ID_LEN],
                           struct bm_pq_broadcast_parsed *out);
void bm_pq_broadcast_parsed_free(struct bm_pq_broadcast_parsed *parsed);

#endif /* BM_PQ_OBJECT_H */
