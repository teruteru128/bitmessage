#ifndef BM_CORE_KEYRING_H
#define BM_CORE_KEYRING_H

/*
 * 鍵ライフサイクル管理(§7)。in-memoryキーリングとunlock/lock/delete API。
 * v1スコープでは骨組みのみ(TODO)。KEK導出(scrypt)・AES-256-GCMラップ解除は
 * identity_store実装後に着手する。
 */

#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#define BM_KEYRING_MAX_ADDRESS_LEN 40

struct bm_unlocked_identity
{
    char address[BM_KEYRING_MAX_ADDRESS_LEN];
    unsigned char ripe[20];
    unsigned char priv_signing[32];
    unsigned char priv_encryption[32];
    unsigned char pub_signing[65];
    unsigned char pub_encryption[65];
    time_t unlocked_at;
    struct bm_unlocked_identity *next;
};

typedef struct
{
    struct bm_unlocked_identity *head;
    pthread_rwlock_t lock;
} bm_keyring_t;

void bm_keyring_init(bm_keyring_t *kr);
void bm_keyring_destroy(bm_keyring_t *kr); /* 全エントリをゼロ埋めしてから解放する */

/* 成功時0。失敗(passphrase誤り等)時は非0。TODO: identity_store実装後に中身を実装 */
int bm_keyring_unlock(bm_keyring_t *kr, const char *address, const char *passphrase);

/* OPENSSL_cleanseでゼロ埋めしてから除去する。見つからなければ非0 */
int bm_keyring_lock(bm_keyring_t *kr, const char *address);
void bm_keyring_lock_all(bm_keyring_t *kr);

/* ripeで検索する。見つかればtrueを返しoutにコピーする(呼び出し側が用意した領域へ) */
bool bm_keyring_find_by_ripe(bm_keyring_t *kr, const unsigned char ripe[20],
                              struct bm_unlocked_identity *out);

#endif /* BM_CORE_KEYRING_H */
