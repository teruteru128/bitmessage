#include "keyring.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "identity_store.h"

/* §7.1のKDFパラメータ既定値。N=2^15はインタラクティブ用途として妥当な強度
 * (概算メモリ使用量 128*N*r = 128*32768*8 ≈ 32MiB) */
#define BM_KEYRING_SCRYPT_N 32768ULL
#define BM_KEYRING_SCRYPT_R 8U
#define BM_KEYRING_SCRYPT_P 1U
#define BM_KEYRING_SCRYPT_MAXMEM (64 * 1024 * 1024)

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

/* row->kdf_paramsは自分自身が書いた固定フォーマットのJSON文字列のみを想定した簡易パーサ
 * (第三者由来の任意JSONは扱わない。汎用JSONパーサは導入しない)。 */
static int parse_kdf_params(const char *json, uint64_t *n, unsigned int *r, unsigned int *p)
{
    unsigned long long n_val = 0;
    unsigned int r_val = 0;
    unsigned int p_val = 0;
    if (sscanf(json, "{\"N\":%llu,\"r\":%u,\"p\":%u}", &n_val, &r_val, &p_val) != 3)
    {
        return -1;
    }
    *n = (uint64_t)n_val;
    *r = r_val;
    *p = p_val;
    return 0;
}

static int derive_kek(const char *passphrase, const unsigned char salt[BM_IDENTITY_KDF_SALT_LEN],
                       uint64_t n, unsigned int r, unsigned int p, unsigned char out_kek[32])
{
    return EVP_PBE_scrypt(passphrase, strlen(passphrase), salt, BM_IDENTITY_KDF_SALT_LEN,
                           n, r, p, BM_KEYRING_SCRYPT_MAXMEM, out_kek, 32) == 1
        ? 0 : -1;
}

/* out = nonce(12) || ciphertext(32) || tag(16)。§7.1 */
static int aes256gcm_wrap(const unsigned char kek[32], const unsigned char *aad, size_t aad_len,
                           const unsigned char plaintext[32], unsigned char out[BM_IDENTITY_WRAPPED_KEY_LEN])
{
    unsigned char *nonce = out;
    unsigned char *ciphertext = out + 12;
    unsigned char *tag = out + 12 + 32;

    if (RAND_bytes(nonce, 12) != 1)
    {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }
    int ret = -1;
    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
        && EVP_EncryptInit_ex(ctx, NULL, NULL, kek, nonce) == 1
        && (aad_len == 0 || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1)
        && EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 32) == 1
        && EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1)
    {
        ret = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int aes256gcm_unwrap(const unsigned char kek[32], const unsigned char *aad, size_t aad_len,
                             const unsigned char in[BM_IDENTITY_WRAPPED_KEY_LEN], unsigned char out_plaintext[32])
{
    const unsigned char *nonce = in;
    const unsigned char *ciphertext = in + 12;
    const unsigned char *tag = in + 12 + 32;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }
    int ret = -1;
    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
        && EVP_DecryptInit_ex(ctx, NULL, NULL, kek, nonce) == 1
        && (aad_len == 0 || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1)
        && EVP_DecryptUpdate(ctx, out_plaintext, &len, ciphertext, 32) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1
        && EVP_DecryptFinal_ex(ctx, out_plaintext + len, &len) == 1)
    {
        ret = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int bm_keyring_create_identity(sqlite3 *db, const char *address, const char *label,
                                int address_version, int stream,
                                const unsigned char pub_signing[65],
                                const unsigned char pub_encryption[65],
                                const unsigned char priv_signing[32],
                                const unsigned char priv_encryption[32],
                                const char *passphrase,
                                uint64_t nonce_trials_per_byte,
                                uint64_t payload_length_extra_bytes)
{
    struct bm_identity_row row;
    memset(&row, 0, sizeof(row));
    strncpy(row.address, address, BM_IDENTITY_ADDRESS_MAX - 1);
    strncpy(row.label, label != NULL ? label : "", BM_IDENTITY_LABEL_MAX - 1);
    row.enabled = 1;
    row.is_chan = 0;
    row.address_version = address_version;
    row.stream = stream;
    memcpy(row.signing_pubkey, pub_signing, 65);
    memcpy(row.encryption_pubkey, pub_encryption, 65);
    strncpy(row.kdf_algo, "scrypt", BM_IDENTITY_KDF_ALGO_MAX - 1);

    if (RAND_bytes(row.kdf_salt, BM_IDENTITY_KDF_SALT_LEN) != 1)
    {
        return -1;
    }
    snprintf(row.kdf_params, BM_IDENTITY_KDF_PARAMS_MAX, "{\"N\":%llu,\"r\":%u,\"p\":%u}",
             (unsigned long long)BM_KEYRING_SCRYPT_N, BM_KEYRING_SCRYPT_R, BM_KEYRING_SCRYPT_P);

    unsigned char kek[32];
    if (derive_kek(passphrase, row.kdf_salt, BM_KEYRING_SCRYPT_N, BM_KEYRING_SCRYPT_R, BM_KEYRING_SCRYPT_P, kek) != 0)
    {
        return -1;
    }

    size_t addr_len = strlen(address);
    int rc1 = aes256gcm_wrap(kek, (const unsigned char *)address, addr_len, priv_signing, row.wrapped_priv_signing_key);
    int rc2 = aes256gcm_wrap(kek, (const unsigned char *)address, addr_len, priv_encryption, row.wrapped_priv_encryption_key);
    OPENSSL_cleanse(kek, sizeof(kek));
    if (rc1 != 0 || rc2 != 0)
    {
        return -1;
    }

    row.nonce_trials_per_byte = nonce_trials_per_byte;
    row.payload_length_extra_bytes = payload_length_extra_bytes;
    row.created_time = time(NULL);

    return bm_identity_store_insert(db, &row);
}

int bm_keyring_unlock(bm_keyring_t *kr, sqlite3 *db, const char *address, const char *passphrase)
{
    struct bm_identity_row row;
    if (bm_identity_store_load(db, address, &row) != 0)
    {
        return -1;
    }

    uint64_t n = 0;
    unsigned int r = 0;
    unsigned int p = 0;
    if (parse_kdf_params(row.kdf_params, &n, &r, &p) != 0)
    {
        return -1;
    }

    unsigned char kek[32];
    if (derive_kek(passphrase, row.kdf_salt, n, r, p, kek) != 0)
    {
        return -1;
    }

    size_t addr_len = strlen(address);
    unsigned char priv_signing[32];
    unsigned char priv_encryption[32];
    int rc1 = aes256gcm_unwrap(kek, (const unsigned char *)address, addr_len,
                                row.wrapped_priv_signing_key, priv_signing);
    int rc2 = aes256gcm_unwrap(kek, (const unsigned char *)address, addr_len,
                                row.wrapped_priv_encryption_key, priv_encryption);
    OPENSSL_cleanse(kek, sizeof(kek));

    if (rc1 != 0 || rc2 != 0)
    {
        /* passphrase誤り、またはラップ済みデータの改竄(AEAD tag不一致) */
        OPENSSL_cleanse(priv_signing, sizeof(priv_signing));
        OPENSSL_cleanse(priv_encryption, sizeof(priv_encryption));
        return -1;
    }

    struct bm_unlocked_identity *entry = malloc(sizeof(*entry));
    if (entry == NULL)
    {
        OPENSSL_cleanse(priv_signing, sizeof(priv_signing));
        OPENSSL_cleanse(priv_encryption, sizeof(priv_encryption));
        return -1;
    }
    memset(entry, 0, sizeof(*entry));
    strncpy(entry->address, address, BM_KEYRING_MAX_ADDRESS_LEN - 1);
    memcpy(entry->priv_signing, priv_signing, 32);
    memcpy(entry->priv_encryption, priv_encryption, 32);
    memcpy(entry->pub_signing, row.signing_pubkey, 65);
    memcpy(entry->pub_encryption, row.encryption_pubkey, 65);
    bm_address_calc_ripe(entry->pub_signing, entry->pub_encryption, entry->ripe);
    entry->unlocked_at = time(NULL);

    OPENSSL_cleanse(priv_signing, sizeof(priv_signing));
    OPENSSL_cleanse(priv_encryption, sizeof(priv_encryption));

    pthread_rwlock_wrlock(&kr->lock);
    entry->next = kr->head;
    kr->head = entry;
    pthread_rwlock_unlock(&kr->lock);

    return 0;
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

int bm_keyring_delete_identity(bm_keyring_t *kr, sqlite3 *db, const char *address)
{
    bm_keyring_lock(kr, address); /* 見つからなくても(既にロック中でも)問題ない */
    return bm_identity_store_delete(db, address);
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
