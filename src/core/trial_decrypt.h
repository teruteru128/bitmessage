#ifndef BM_CORE_TRIAL_DECRYPT_H
#define BM_CORE_TRIAL_DECRYPT_H

/*
 * decrypt_worker_thread(§1.1)。message_builder.cの逆方向: 受信objectをkeyring内の
 * unlocked鍵全てでトライアル復号し、成功したらinbox(messages.db)へ保存する。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "../common/address_limits.h"

#include "keyring.h"

struct bm_decoded_msg
{
    uint64_t from_address_version;
    uint64_t from_stream;
    char from_address[BM_ADDRESS_STR_MAX];
    char to_address[BM_ADDRESS_STR_MAX];
    char *subject;              /* malloc、bm_decoded_msg_freeで解放 */
    char *body;                 /* malloc、bm_decoded_msg_freeで解放 */
    unsigned char *ack_payload; /* malloc、NULL可(ack_payload_len=0のとき) */
    size_t ack_payload_len;
};

/*
 * type=msgの完全なobject(nonce込み)を、keyring内のunlocked鍵全てでトライアル復号する。
 * 成功時0でoutを埋める(bm_decoded_msg_freeで解放すること)。以下は全て失敗(非0)として扱う:
 * 手持ちのどの鍵でも復号できない/toRipe不一致(なりすまし転送対策、§5.3)/署名検証失敗。
 */
int bm_trial_decrypt_msg(bm_keyring_t *kr, const unsigned char *object, size_t object_len,
                          struct bm_decoded_msg *out);

/*
 * §11 2026-08-31 bm_trial_decrypt_msgの単一identity限定版。keyring全体ではなく指定した1件の
 * identityだけでトライアル復号を試みる(理由・使い所はtrial_decrypt.cのコメント、および
 * object_sync.hのbm_object_sync_backfill_trial_decrypt参照)。成功時0。
 */
int bm_trial_decrypt_msg_single(const struct bm_unlocked_identity *identity, const unsigned char *object,
                                 size_t object_len, struct bm_decoded_msg *out);

void bm_decoded_msg_free(struct bm_decoded_msg *msg);

/*
 * bm_trial_decrypt_msgを呼び、成功したらinboxへ保存する(msg_id=objectのinventory hash)。成功時0。
 * out_ack_payload/out_ack_payload_lenが非NULLで、復号したmsgにack_payload(§5.5のfullAckPayload、
 * P2P "object"パケット)が埋め込まれていれば、その所有権(malloc済みバッファ)を呼び出し側へ渡す
 * (*out_ack_payload_len==0ならack無し、*out_ack_payloadはNULLのまま)。trial_decrypt.cはcore層で
 * infra層(object_pool.dbへの検証・挿入)に依存しない方針のため、中身の検証・保存は呼び出し側
 * (infra/object_sync.c)の責務とする。不要なら両方NULLを渡してよい(内部で解放する)。
 */
int bm_trial_decrypt_and_store(bm_keyring_t *kr, sqlite3 *db,
                                const unsigned char *object, size_t object_len,
                                unsigned char **out_ack_payload, size_t *out_ack_payload_len);

/* §11 2026-08-31 bm_trial_decrypt_and_storeの単一identity限定版(bm_trial_decrypt_msg_single参照) */
int bm_trial_decrypt_and_store_single(const struct bm_unlocked_identity *identity, sqlite3 *db,
                                       const unsigned char *object, size_t object_len, int64_t now,
                                       unsigned char **out_ack_payload, size_t *out_ack_payload_len);

#ifdef BM_HAVE_PQ
/*
 * §11 2026-11-04 項目55の段5: v5のmsg(objectVersion 2)の試行復号とinboxへの保存。address==NULLなら
 * unlock済みの全v5 identityを、非NULLならその1件だけを試す(bm_pq_keyring_open_msg参照)。
 * out_ack_*の扱いはbm_trial_decrypt_and_storeと同じ。成功時0。
 * §11 2026-11-04 項目57: identity_dbが非NULLなら、msgに載っていた差出人の公開鍵を保存する
 * (返信にgetpubkeyを要らなくするため。pq_pubkey_cache.hのbm_pq_pubkey_cache_store_sender)。
 */
int bm_pq_trial_decrypt_and_store(bm_keyring_t *kr, const char *address, sqlite3 *identity_db, sqlite3 *db,
                                  const unsigned char *object, size_t object_len, int64_t now,
                                  unsigned char **out_ack_payload, size_t *out_ack_payload_len);
#endif

void *bm_trial_decrypt_thread(void *arg);

#endif /* BM_CORE_TRIAL_DECRYPT_H */
