#include "keyring.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
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

/* KEKが分かった状態でGCM復号しkeyringへ追加する共通部分(§7.4でscrypt個別方式/vault-hkdf方式の
 * 双方から呼べるよう分離した)。成功時0、passphrase誤り・改竄検出(AEAD tag不一致)は非0 */
static int unlock_with_kek(bm_keyring_t *kr, const struct bm_identity_row *row, const unsigned char kek[32])
{
    size_t addr_len = strlen(row->address);
    unsigned char priv_signing[32];
    unsigned char priv_encryption[32];
    int rc1 = aes256gcm_unwrap(kek, (const unsigned char *)row->address, addr_len,
                                row->wrapped_priv_signing_key, priv_signing);
    int rc2 = aes256gcm_unwrap(kek, (const unsigned char *)row->address, addr_len,
                                row->wrapped_priv_encryption_key, priv_encryption);

    if (rc1 != 0 || rc2 != 0)
    {
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
    strncpy(entry->address, row->address, BM_KEYRING_MAX_ADDRESS_LEN - 1);
    memcpy(entry->priv_signing, priv_signing, 32);
    memcpy(entry->priv_encryption, priv_encryption, 32);
    memcpy(entry->pub_signing, row->signing_pubkey, 65);
    memcpy(entry->pub_encryption, row->encryption_pubkey, 65);
    bm_address_calc_ripe(entry->pub_signing, entry->pub_encryption, entry->ripe);
    entry->address_version = (uint64_t)row->address_version;
    entry->stream = (uint64_t)row->stream;
    entry->nonce_trials_per_byte = row->nonce_trials_per_byte;
    entry->payload_length_extra_bytes = row->payload_length_extra_bytes;
    entry->unlocked_at = time(NULL);

    OPENSSL_cleanse(priv_signing, sizeof(priv_signing));
    OPENSSL_cleanse(priv_encryption, sizeof(priv_encryption));

    pthread_rwlock_wrlock(&kr->lock);
    entry->next = kr->head;
    kr->head = entry;
    pthread_rwlock_unlock(&kr->lock);

    return 0;
}

/*
 * §7.4 2026-08-29 vault方式(DESIGN.md §11-19)。master_kek(passphrase由来の重いKDFを
 * vault_saltで1回だけ通したもの)から、行固有のkdf_salt+address文字列を使ってHKDF-Expandで
 * 軽量にラップ鍵を導出する。addressをinfoに混ぜることで、ある行のkekを別の行に転用する
 * ような取り違えを防ぐ(aes256gcm_wrap/unwrapのAAD=addressと同じ意図)。
 */
static int hkdf_expand_wrap_key(const unsigned char master_kek[32],
                                 const unsigned char row_salt[BM_IDENTITY_KDF_SALT_LEN],
                                 const char *address, unsigned char out_kek[32])
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL)
    {
        return -1;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL)
    {
        return -1;
    }

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[6];
    size_t idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)master_kek, 32);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)row_salt,
                                                       BM_IDENTITY_KDF_SALT_LEN);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)address, strlen(address));
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[idx] = OSSL_PARAM_construct_end();

    int ret = (EVP_KDF_derive(kctx, out_kek, 32, params) == 1) ? 0 : -1;
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* vault_kdf_paramsをpassphraseに適用してmaster KEKを導出する(scryptそのもの、vault作成時と
 * 同じパラメータを使う想定)。derive_kekのラッパー、失敗時非0 */
static int derive_master_kek(const char *passphrase, const unsigned char vault_salt[BM_IDENTITY_VAULT_SALT_LEN],
                              const char *vault_kdf_params, unsigned char out_master_kek[32])
{
    uint64_t n = 0;
    unsigned int r = 0;
    unsigned int p = 0;
    if (parse_kdf_params(vault_kdf_params, &n, &r, &p) != 0)
    {
        return -1;
    }
    return derive_kek(passphrase, vault_salt, n, r, p, out_master_kek);
}

/*
 * §7.4 2026-08-29 vault canary: 「master KEKが正しいか」を検証するための既知平文
 * (秘匿性は無い固定値)。scryptは誤ったpassphraseでも必ず何らかの32byte値を返すため、
 * これが無いと「vaultは既にあるが異なるpassphraseでunlockAllAddressesを呼んだ」際に
 * 誤ったmaster KEKかどうか判定できず、たまたま旧方式(個別scrypt)の行がその誤った
 * passphraseと一致した場合に誤ったmaster KEKでre-wrapしてvault全体を壊しかねない
 * (§11-19参照)。vault作成時にこの平文をmaster KEKでラップして保存しておき、以後は
 * 必ずこれを復号できることを確認してからmaster KEKを使う。
 */
static const unsigned char VAULT_CANARY_PLAINTEXT[32] = {
    'b', 'm', '-', 'v', 'a', 'u', 'l', 't', '-', 'c', 'a', 'n', 'a', 'r', 'y', '-',
    'v', '1', '-', 'o', 'k', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const unsigned char VAULT_CANARY_AAD[] = "bm-vault-canary-v1-ctx";

/* master_kekでcanaryを復号し、期待する平文と一致するかを検証する。成功(=正しいmaster_kek)時0 */
static int verify_vault_canary(const unsigned char master_kek[32],
                                const unsigned char canary[BM_IDENTITY_WRAPPED_KEY_LEN])
{
    unsigned char check[32];
    int rc = aes256gcm_unwrap(master_kek, VAULT_CANARY_AAD, sizeof(VAULT_CANARY_AAD) - 1, canary, check);
    int ok = (rc == 0 && memcmp(check, VAULT_CANARY_PLAINTEXT, sizeof(VAULT_CANARY_PLAINTEXT)) == 0);
    OPENSSL_cleanse(check, sizeof(check));
    return ok ? 0 : -1;
}

/* vault方式の行をunlockする(KEK取得方法がHKDFになるだけでunlock_with_kek以降は共通) */
static int unlock_with_vault(bm_keyring_t *kr, const struct bm_identity_row *row,
                              const unsigned char master_kek[32])
{
    unsigned char kek[32];
    if (hkdf_expand_wrap_key(master_kek, row->kdf_salt, row->address, kek) != 0)
    {
        return -1;
    }
    int rc = unlock_with_kek(kr, row, kek);
    OPENSSL_cleanse(kek, sizeof(kek));
    return rc;
}

/*
 * §11-19相談メモ(2026-08-29)のlazy migration方針: 旧方式(個別scrypt)でunlock済みの
 * アドレスを、その場でvault方式へ書き換える。既にkeyring上にある平文鍵(bm_keyring_unlock
 * 成功直後の状態)を再利用するので、DBから再度passphraseで復号し直す(=scryptをもう一度
 * 回す)必要はない。saltはscrypt用に生成されたものをHKDFに転用せず新規生成し直す
 * (用途分離)。失敗しても呼び出し元のunlock自体は成功扱いのまま進めてよい
 * (re-wrapは次回以降の高速化のための最適化に過ぎず、失敗しても次回また旧方式で
 * 個別scryptされるだけで機能的な問題は無い)。成功時0。
 */
static int rewrap_to_vault(sqlite3 *db, bm_keyring_t *kr, const char *address,
                            const unsigned char master_kek[32])
{
    struct bm_unlocked_identity unlocked;
    if (!bm_keyring_find_by_address(kr, address, &unlocked))
    {
        return -1;
    }

    unsigned char new_salt[BM_IDENTITY_KDF_SALT_LEN];
    if (RAND_bytes(new_salt, sizeof(new_salt)) != 1)
    {
        return -1;
    }
    unsigned char kek[32];
    if (hkdf_expand_wrap_key(master_kek, new_salt, address, kek) != 0)
    {
        return -1;
    }

    size_t addr_len = strlen(address);
    unsigned char wrapped_signing[BM_IDENTITY_WRAPPED_KEY_LEN];
    unsigned char wrapped_encryption[BM_IDENTITY_WRAPPED_KEY_LEN];
    int rc1 = aes256gcm_wrap(kek, (const unsigned char *)address, addr_len,
                              unlocked.priv_signing, wrapped_signing);
    int rc2 = aes256gcm_wrap(kek, (const unsigned char *)address, addr_len,
                              unlocked.priv_encryption, wrapped_encryption);
    OPENSSL_cleanse(kek, sizeof(kek));
    OPENSSL_cleanse(&unlocked, sizeof(unlocked));
    if (rc1 != 0 || rc2 != 0)
    {
        return -1;
    }

    return bm_identity_store_update_wrapped_keys(db, address, "vault-hkdf", new_salt,
                                                  wrapped_signing, wrapped_encryption);
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
    int rc = unlock_with_kek(kr, &row, kek);
    OPENSSL_cleanse(kek, sizeof(kek));
    return rc;
}

int bm_keyring_export(sqlite3 *db, const char *address, const char *passphrase,
                       unsigned char out_priv_signing[32], unsigned char out_priv_encryption[32])
{
    struct bm_identity_row row;
    if (bm_identity_store_load(db, address, &row) != 0)
    {
        return -1;
    }

    unsigned char kek[32];
    if (strcmp(row.kdf_algo, "vault-hkdf") == 0)
    {
        unsigned char vault_salt[BM_IDENTITY_VAULT_SALT_LEN];
        char vault_kdf_params[BM_IDENTITY_KDF_PARAMS_MAX];
        unsigned char vault_canary[BM_IDENTITY_WRAPPED_KEY_LEN];
        unsigned char master_kek[32];
        if (bm_identity_store_load_vault(db, vault_salt, vault_kdf_params, vault_canary) != 0
            || derive_master_kek(passphrase, vault_salt, vault_kdf_params, master_kek) != 0
            || verify_vault_canary(master_kek, vault_canary) != 0)
        {
            return -1;
        }
        int rc = hkdf_expand_wrap_key(master_kek, row.kdf_salt, address, kek);
        OPENSSL_cleanse(master_kek, sizeof(master_kek));
        if (rc != 0)
        {
            return -1;
        }
    }
    else
    {
        uint64_t n = 0;
        unsigned int r = 0;
        unsigned int p = 0;
        if (parse_kdf_params(row.kdf_params, &n, &r, &p) != 0
            || derive_kek(passphrase, row.kdf_salt, n, r, p, kek) != 0)
        {
            return -1;
        }
    }

    size_t addr_len = strlen(address);
    int rc1 = aes256gcm_unwrap(kek, (const unsigned char *)address, addr_len,
                                row.wrapped_priv_signing_key, out_priv_signing);
    int rc2 = aes256gcm_unwrap(kek, (const unsigned char *)address, addr_len,
                                row.wrapped_priv_encryption_key, out_priv_encryption);
    OPENSSL_cleanse(kek, sizeof(kek));
    if (rc1 != 0 || rc2 != 0)
    {
        OPENSSL_cleanse(out_priv_signing, 32);
        OPENSSL_cleanse(out_priv_encryption, 32);
        return -1;
    }
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

int bm_keyring_mark_as_chan(sqlite3 *db, const char *address)
{
    return bm_identity_store_set_is_chan(db, address, 1);
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

bool bm_keyring_find_by_tag(bm_keyring_t *kr, const unsigned char tag[32],
                             struct bm_unlocked_identity *out)
{
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    while (cur != NULL)
    {
        if (cur->address_version >= 4)
        {
            unsigned char secret[32];
            unsigned char computed_tag[32];
            bm_address_derive_secret_and_tag(cur->address_version, cur->stream, cur->ripe, secret, computed_tag);
            OPENSSL_cleanse(secret, sizeof(secret));
            if (memcmp(computed_tag, tag, 32) == 0)
            {
                memcpy(out, cur, sizeof(*out));
                out->next = NULL;
                pthread_rwlock_unlock(&kr->lock);
                return true;
            }
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&kr->lock);
    return false;
}

bool bm_keyring_find_by_address(bm_keyring_t *kr, const char *address,
                                 struct bm_unlocked_identity *out)
{
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_identity *cur = kr->head;
    while (cur != NULL)
    {
        if (strncmp(cur->address, address, BM_KEYRING_MAX_ADDRESS_LEN) == 0)
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

int bm_keyring_unlock_all(bm_keyring_t *kr, sqlite3 *db, const char *passphrase,
                           struct bm_unlock_all_entry **out_results, size_t *out_count)
{
    struct bm_identity_summary *list = NULL;
    size_t count = 0;
    if (bm_identity_store_list(db, &list, &count) != 0)
    {
        return -1;
    }

    struct bm_unlock_all_entry *results = malloc(sizeof(*results) * (count > 0 ? count : 1));
    if (results == NULL)
    {
        free(list);
        return -1;
    }

    /* §7.4 vaultが既にあればmaster KEKをここで1回だけ導出してループ全体で使い回す
     * (無ければ、下のループで初めて旧方式のunlockに成功した時点で遅延生成する)。
     * vault_existsとhave_master_kekを分けているのは、「vaultはあるが渡されたpassphraseが
     * vaultのものと異なる」場合に、下のループで誤って新規vault作成を試みない
     * (=誤ったmaster KEKでre-wrapしてvaultを壊す事故を防ぐ)ため。 */
    unsigned char vault_salt[BM_IDENTITY_VAULT_SALT_LEN];
    char vault_kdf_params[BM_IDENTITY_KDF_PARAMS_MAX];
    unsigned char vault_canary[BM_IDENTITY_WRAPPED_KEY_LEN];
    unsigned char master_kek[32] = {0};
    int vault_exists = (bm_identity_store_load_vault(db, vault_salt, vault_kdf_params, vault_canary) == 0);
    int have_master_kek = 0;
    if (vault_exists && derive_master_kek(passphrase, vault_salt, vault_kdf_params, master_kek) == 0
        && verify_vault_canary(master_kek, vault_canary) == 0)
    {
        have_master_kek = 1;
    }

    for (size_t i = 0; i < count; i++)
    {
        strncpy(results[i].address, list[i].address, BM_KEYRING_MAX_ADDRESS_LEN - 1);
        results[i].address[BM_KEYRING_MAX_ADDRESS_LEN - 1] = '\0';

        struct bm_unlocked_identity dummy;
        if (bm_keyring_find_by_address(kr, list[i].address, &dummy))
        {
            results[i].unlocked = 1; /* 既にunlock済み、再試行しない */
            continue;
        }

        struct bm_identity_row row;
        if (bm_identity_store_load(db, list[i].address, &row) != 0)
        {
            results[i].unlocked = 0;
            continue;
        }

        if (strcmp(row.kdf_algo, "vault-hkdf") == 0)
        {
            /* master KEKが導出できていない(=vaultはあるがpassphrase不一致)場合は
             * 個別に試す意味が無い(vault方式はmaster KEK前提)ので即失敗扱い */
            results[i].unlocked = (have_master_kek && unlock_with_vault(kr, &row, master_kek) == 0) ? 1 : 0;
            continue;
        }

        /* 旧方式(個別scrypt)。成功したらvault方式へre-wrapする(lazy migration、上記コメント参照) */
        int rc = bm_keyring_unlock(kr, db, list[i].address, passphrase);
        results[i].unlocked = (rc == 0) ? 1 : 0;
        if (rc != 0)
        {
            continue;
        }
        if (!have_master_kek && !vault_exists)
        {
            unsigned char new_vault_salt[BM_IDENTITY_VAULT_SALT_LEN];
            char new_vault_params[BM_IDENTITY_KDF_PARAMS_MAX];
            unsigned char new_canary[BM_IDENTITY_WRAPPED_KEY_LEN];
            snprintf(new_vault_params, sizeof(new_vault_params), "{\"N\":%llu,\"r\":%u,\"p\":%u}",
                     (unsigned long long)BM_KEYRING_SCRYPT_N, BM_KEYRING_SCRYPT_R, BM_KEYRING_SCRYPT_P);
            if (RAND_bytes(new_vault_salt, sizeof(new_vault_salt)) == 1
                && derive_kek(passphrase, new_vault_salt, BM_KEYRING_SCRYPT_N, BM_KEYRING_SCRYPT_R,
                               BM_KEYRING_SCRYPT_P, master_kek) == 0
                && aes256gcm_wrap(master_kek, VAULT_CANARY_AAD, sizeof(VAULT_CANARY_AAD) - 1,
                                   VAULT_CANARY_PLAINTEXT, new_canary) == 0
                && bm_identity_store_create_vault(db, new_vault_salt, new_vault_params, new_canary) == 0)
            {
                have_master_kek = 1;
                vault_exists = 1;
            }
        }
        if (have_master_kek)
        {
            rewrap_to_vault(db, kr, list[i].address, master_kek);
        }
    }

    OPENSSL_cleanse(master_kek, sizeof(master_kek));
    free(list);
    *out_results = results;
    *out_count = count;
    return 0;
}
