#ifndef BM_CORE_KEYRING_H
#define BM_CORE_KEYRING_H

/*
 * 鍵ライフサイクル管理(§7)。in-memoryキーリングとunlock/lock/delete、
 * および新規identity作成時のKEKラップ処理。
 *
 * §7.1: 秘密鍵はscryptで導出したKEK(KEK自体はディスクに保存しない)でAES-256-GCM
 * ラップして identity.db に保存する。AAD=address文字列。
 */

#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
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

/*
 * 新規identityをKEKでラップしてidentity.dbへ保存する(address自体はaddress.cで生成済みのものを渡す)。
 * 成功時0。
 */
int bm_keyring_create_identity(sqlite3 *db, const char *address, const char *label,
                                int address_version, int stream,
                                const unsigned char pub_signing[65],
                                const unsigned char pub_encryption[65],
                                const unsigned char priv_signing[32],
                                const unsigned char priv_encryption[32],
                                const char *passphrase,
                                uint64_t nonce_trials_per_byte,
                                uint64_t payload_length_extra_bytes);

/*
 * identity.dbからラップ済み鍵を読み、passphraseから導出したKEKで復号してkeyringへ追加する。
 * passphrase誤り・改竄検出(AEAD tag不一致)・address不在は全て非0を返す。
 */
int bm_keyring_unlock(bm_keyring_t *kr, sqlite3 *db, const char *address, const char *passphrase);

/* OPENSSL_cleanseでゼロ埋めしてから除去する。見つからなければ非0。identity.db側は変更しない */
int bm_keyring_lock(bm_keyring_t *kr, const char *address);
void bm_keyring_lock_all(bm_keyring_t *kr);

/* keyringからロック相当の消去をした上でidentity.dbから該当行を完全削除する(復元不可) */
int bm_keyring_delete_identity(bm_keyring_t *kr, sqlite3 *db, const char *address);

/* ripeで検索する。見つかればtrueを返しoutにコピーする(呼び出し側が用意した領域へ) */
bool bm_keyring_find_by_ripe(bm_keyring_t *kr, const unsigned char ripe[20],
                              struct bm_unlocked_identity *out);

#endif /* BM_CORE_KEYRING_H */
