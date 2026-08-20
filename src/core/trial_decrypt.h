#ifndef BM_CORE_TRIAL_DECRYPT_H
#define BM_CORE_TRIAL_DECRYPT_H

/*
 * decrypt_worker_thread(§1.1)。message_builder.cの逆方向: 受信objectをkeyring内の
 * unlocked鍵全てでトライアル復号し、成功したらinbox(messages.db)へ保存する。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "keyring.h"

struct bm_decoded_msg
{
    uint64_t from_address_version;
    uint64_t from_stream;
    char from_address[40];
    char to_address[40];
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
void bm_decoded_msg_free(struct bm_decoded_msg *msg);

/* bm_trial_decrypt_msgを呼び、成功したらinboxへ保存する(msg_id=objectのinventory hash)。成功時0 */
int bm_trial_decrypt_and_store(bm_keyring_t *kr, sqlite3 *db,
                                const unsigned char *object, size_t object_len);

void *bm_trial_decrypt_thread(void *arg);

#endif /* BM_CORE_TRIAL_DECRYPT_H */
