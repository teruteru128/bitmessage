#include "keyring.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

void bm_keyring_init(bm_keyring_t *kr)
{
    kr->head = NULL;
    pthread_rwlock_init(&kr->lock, NULL);
}

void bm_keyring_destroy(bm_keyring_t *kr)
{
    pthread_rwlock_wrlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    while (cur != NULL)
    {
        struct bm_unlocked_identity *next = cur->next;
        OPENSSL_cleanse(cur, sizeof(*cur));
        free(cur);
        cur = next;
    }
    kr->head = NULL;
    pthread_rwlock_unlock(&kr->lock);
    pthread_rwlock_destroy(&kr->lock);
}

int bm_keyring_unlock(bm_keyring_t *kr, const char *address, const char *passphrase)
{
    (void)kr;
    (void)address;
    (void)passphrase;
    /* TODO(§7.1, §7.2): identity_storeからKDFパラメータ・ラップ済み鍵を取得し、
     * scrypt(passphrase)でKEKを導出、AES-256-GCMで復号してkeyringへ追加する。 */
    return -1;
}

int bm_keyring_lock(bm_keyring_t *kr, const char *address)
{
    pthread_rwlock_wrlock(&kr->lock);
    struct bm_unlocked_identity **cur = &kr->head;
    while (*cur != NULL)
    {
        if (strncmp((*cur)->address, address, BM_KEYRING_MAX_ADDRESS_LEN) == 0)
        {
            struct bm_unlocked_identity *victim = *cur;
            *cur = victim->next;
            OPENSSL_cleanse(victim, sizeof(*victim));
            free(victim);
            pthread_rwlock_unlock(&kr->lock);
            return 0;
        }
        cur = &(*cur)->next;
    }
    pthread_rwlock_unlock(&kr->lock);
    return -1;
}

void bm_keyring_lock_all(bm_keyring_t *kr)
{
    pthread_rwlock_wrlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    while (cur != NULL)
    {
        struct bm_unlocked_identity *next = cur->next;
        OPENSSL_cleanse(cur, sizeof(*cur));
        free(cur);
        cur = next;
    }
    kr->head = NULL;
    pthread_rwlock_unlock(&kr->lock);
}

bool bm_keyring_find_by_ripe(bm_keyring_t *kr, const unsigned char ripe[20],
                              struct bm_unlocked_identity *out)
{
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    while (cur != NULL)
    {
        if (memcmp(cur->ripe, ripe, 20) == 0)
        {
            memcpy(out, cur, sizeof(*out));
            out->next = NULL;
            pthread_rwlock_unlock(&kr->lock);
            return true;
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&kr->lock);
    return false;
}
