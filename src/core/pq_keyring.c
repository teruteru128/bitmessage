#include "pq_keyring.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../pq/pq_hybrid.h"
#include "keyring_internal.h"
#include "pq_identity_store.h"

int bm_pq_keyring_create_identity(sqlite3 *db, const struct bm_pqv5_identity *identity, const char *label,
                                  const char *passphrase, uint64_t nonce_trials_per_byte,
                                  uint64_t payload_length_extra_bytes, int64_t now,
                                  char out_address[BM_KEYRING_MAX_ADDRESS_LEN])
{
    char *address = bm_pqv5_address_encode(identity->version, identity->stream, identity->id);
    if (address == NULL)
    {
        return -1;
    }
    if (strlen(address) >= BM_IDENTITY_ADDRESS_MAX)
    {
        free(address);
        return -1;
    }

    /* 行は大きい(公開鍵だけで3.2KB)のでスタックに置かない */
    struct bm_pq_identity_row *row = calloc(1, sizeof(*row));
    if (row == NULL)
    {
        free(address);
        return -1;
    }
    snprintf(row->address, sizeof(row->address), "%s", address);
    snprintf(row->label, sizeof(row->label), "%s", label != NULL ? label : "");
    row->enabled = 1;
    row->address_version = identity->version;
    row->stream = identity->stream;
    memcpy(row->id, identity->id, BM_PQV5_ID_LEN);
    memcpy(row->sig_pk, identity->sig_pk, BM_PQV5_SIG_PK_LEN);
    memcpy(row->kem_pk, identity->kem_pk, BM_PQV5_KEM_PK_LEN);
    snprintf(row->kdf_algo, sizeof(row->kdf_algo), "%s", "scrypt");
    row->nonce_trials_per_byte = nonce_trials_per_byte;
    row->payload_length_extra_bytes = payload_length_extra_bytes;
    row->created_time = now;

    int rc = -1;
    unsigned char kek[32];
    if (bm_keyring_internal_new_scrypt_kek(passphrase, row->kdf_salt, row->kdf_params, kek) == 0
        && bm_keyring_internal_wrap(kek, (const unsigned char *)address, strlen(address),
                                    (const unsigned char *)&identity->seeds, BM_PQV5_COMPONENT_SEEDS_LEN,
                                    row->wrapped_seeds)
               == 0
        && bm_pq_identity_store_insert(db, row) == 0)
    {
        rc = 0;
        if (out_address != NULL)
        {
            snprintf(out_address, BM_KEYRING_MAX_ADDRESS_LEN, "%s", address);
        }
    }
    OPENSSL_cleanse(kek, sizeof(kek));
    free(row);
    free(address);
    return rc;
}

static struct bm_unlocked_pq_identity *find_locked(bm_keyring_t *kr, const char *address)
{
    for (struct bm_unlocked_pq_identity *cur = kr->pq_head; cur != NULL; cur = cur->next)
    {
        if (strncmp(cur->address, address, BM_KEYRING_MAX_ADDRESS_LEN) == 0)
        {
            return cur;
        }
    }
    return NULL;
}

/*
 * 保存された公開鍵が、アドレスに埋め込まれたidと一致するか(id = SHA3-256(sig_pk || kem_pk)、
 * address_v5.h)、アドレスのversion/streamが行と一致するかを確かめる。公開鍵は平文で保存
 * しているので、DBを書き換えられた場合にここで弾く(seed側はGCMのAAD=アドレスで縛られる)。
 */
static int row_is_consistent(const struct bm_pq_identity_row *row)
{
    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char addr_id[BM_PQV5_ID_LEN];
    unsigned char calc_id[BM_PQV5_ID_LEN];
    if (bm_pqv5_address_decode(row->address, &version, &stream, addr_id) != 0)
    {
        return 0;
    }
    bm_pqv5_calc_id(row->sig_pk, row->kem_pk, calc_id);
    return version == row->address_version && stream == row->stream
        && memcmp(addr_id, row->id, BM_PQV5_ID_LEN) == 0 && memcmp(calc_id, row->id, BM_PQV5_ID_LEN) == 0;
}

int bm_pq_keyring_unlock(bm_keyring_t *kr, sqlite3 *db, const char *address, const char *passphrase,
                         int64_t now)
{
    struct bm_pq_identity_row *row = malloc(sizeof(*row));
    struct bm_unlocked_pq_identity *entry = calloc(1, sizeof(*entry));
    if (row == NULL || entry == NULL)
    {
        free(row);
        free(entry);
        return -1;
    }

    int rc = -1;
    unsigned char kek[32];
    if (bm_pq_identity_store_load(db, address, row) != 0 || !row_is_consistent(row)
        || bm_keyring_internal_resolve_kek(db, row->kdf_algo, row->kdf_salt, row->kdf_params, row->address,
                                           passphrase, kek)
               != 0)
    {
        goto out;
    }
    if (bm_keyring_internal_unwrap(kek, (const unsigned char *)row->address, strlen(row->address),
                                   row->wrapped_seeds, BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN,
                                   (unsigned char *)&entry->seeds)
        != 0)
    {
        goto out; /* passphrase誤り・改竄 */
    }

    snprintf(entry->address, sizeof(entry->address), "%s", row->address);
    entry->address_version = row->address_version;
    entry->stream = row->stream;
    memcpy(entry->id, row->id, BM_PQV5_ID_LEN);
    bm_pqv5_derive_secret_and_tag(row->address_version, row->stream, row->id, NULL, entry->tag);
    memcpy(entry->sig_pk, row->sig_pk, BM_PQV5_SIG_PK_LEN);
    memcpy(entry->kem_pk, row->kem_pk, BM_PQV5_KEM_PK_LEN);
    entry->nonce_trials_per_byte = row->nonce_trials_per_byte;
    entry->payload_length_extra_bytes = row->payload_length_extra_bytes;
    entry->unlocked_at = now;

    pthread_rwlock_wrlock(&kr->lock);
    if (find_locked(kr, entry->address) == NULL)
    {
        entry->next = kr->pq_head;
        kr->pq_head = entry;
        entry = NULL; /* 所有権はkeyringへ */
    }
    pthread_rwlock_unlock(&kr->lock);
    rc = 0; /* 既にunlock済みだった場合も成功(下で写しを捨てる) */

out:
    OPENSSL_cleanse(kek, sizeof(kek));
    if (entry != NULL)
    {
        OPENSSL_cleanse(entry, sizeof(*entry));
        free(entry);
    }
    free(row);
    return rc;
}

static void copy_public(const struct bm_unlocked_pq_identity *src, struct bm_pq_identity_public *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->address, sizeof(out->address), "%s", src->address);
    out->address_version = src->address_version;
    out->stream = src->stream;
    memcpy(out->id, src->id, BM_PQV5_ID_LEN);
    memcpy(out->tag, src->tag, sizeof(out->tag));
    memcpy(out->sig_pk, src->sig_pk, BM_PQV5_SIG_PK_LEN);
    memcpy(out->kem_pk, src->kem_pk, BM_PQV5_KEM_PK_LEN);
    out->nonce_trials_per_byte = src->nonce_trials_per_byte;
    out->payload_length_extra_bytes = src->payload_length_extra_bytes;
}

bool bm_pq_keyring_find_by_address(bm_keyring_t *kr, const char *address, struct bm_pq_identity_public *out)
{
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_pq_identity *cur = find_locked(kr, address);
    if (cur != NULL && out != NULL)
    {
        copy_public(cur, out);
    }
    pthread_rwlock_unlock(&kr->lock);
    return cur != NULL;
}

bool bm_pq_keyring_find_by_tag(bm_keyring_t *kr, const unsigned char tag[32], struct bm_pq_identity_public *out)
{
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_pq_identity *found = NULL;
    for (struct bm_unlocked_pq_identity *cur = kr->pq_head; cur != NULL; cur = cur->next)
    {
        if (memcmp(cur->tag, tag, 32) == 0)
        {
            found = cur;
            break;
        }
    }
    if (found != NULL && out != NULL)
    {
        copy_public(found, out);
    }
    pthread_rwlock_unlock(&kr->lock);
    return found != NULL;
}

int bm_pq_keyring_get_secret_keys(bm_keyring_t *kr, const char *address, unsigned char *out_sig_sk,
                                  unsigned char *out_kem_sk)
{
    /* 展開済みならその写しを返す */
    pthread_rwlock_rdlock(&kr->lock);
    struct bm_unlocked_pq_identity *cur = find_locked(kr, address);
    if (cur == NULL)
    {
        pthread_rwlock_unlock(&kr->lock);
        return -1;
    }
    if (cur->expanded)
    {
        if (out_sig_sk != NULL)
        {
            memcpy(out_sig_sk, cur->sig_sk, BM_PQV5_SIG_SK_LEN);
        }
        if (out_kem_sk != NULL)
        {
            memcpy(out_kem_sk, cur->kem_sk, BM_PQV5_KEM_SK_LEN);
        }
        pthread_rwlock_unlock(&kr->lock);
        return 0;
    }
    /* 未展開: seedの写しを取ってロックを外し、展開(0.4〜0.6ms)はロックの外で行う。
     * keyring全体を書き込みロックで握ったまま鍵生成すると、その間ほかの全スレッドの
     * 鍵の参照が止まるため */
    struct bm_pqv5_component_seeds seeds = cur->seeds;
    uint64_t stream = cur->stream;
    pthread_rwlock_unlock(&kr->lock);

    struct bm_pqv5_identity *expanded = malloc(sizeof(*expanded));
    if (expanded == NULL)
    {
        OPENSSL_cleanse(&seeds, sizeof(seeds));
        return -1;
    }
    int rc = -1;
    if (bm_pqv5_identity_from_component_seeds(stream, &seeds, expanded) != 0)
    {
        goto out;
    }

    pthread_rwlock_wrlock(&kr->lock);
    cur = find_locked(kr, address); /* 展開の間にlockされていれば無い */
    if (cur != NULL)
    {
        /* seedから作った鍵が、unlock時に照合済みの公開鍵(=アドレスのid)と一致しなければ
         * seedが壊れている。黙ってアドレスと違う鍵で署名・復号しない */
        if (memcmp(expanded->sig_pk, cur->sig_pk, BM_PQV5_SIG_PK_LEN) == 0
            && memcmp(expanded->kem_pk, cur->kem_pk, BM_PQV5_KEM_PK_LEN) == 0)
        {
            if (!cur->expanded)
            {
                memcpy(cur->sig_sk, expanded->sig_sk, BM_PQV5_SIG_SK_LEN);
                memcpy(cur->kem_sk, expanded->kem_sk, BM_PQV5_KEM_SK_LEN);
                cur->expanded = 1;
            }
            if (out_sig_sk != NULL)
            {
                memcpy(out_sig_sk, cur->sig_sk, BM_PQV5_SIG_SK_LEN);
            }
            if (out_kem_sk != NULL)
            {
                memcpy(out_kem_sk, cur->kem_sk, BM_PQV5_KEM_SK_LEN);
            }
            rc = 0;
        }
    }
    pthread_rwlock_unlock(&kr->lock);

out:
    OPENSSL_cleanse(&seeds, sizeof(seeds));
    OPENSSL_cleanse(expanded, sizeof(*expanded));
    free(expanded);
    return rc;
}

static void free_entry(struct bm_unlocked_pq_identity *entry)
{
    OPENSSL_cleanse(entry, sizeof(*entry));
    free(entry);
}

void bm_pq_keyring_clear_locked(bm_keyring_t *kr)
{
    struct bm_unlocked_pq_identity *cur = kr->pq_head;
    while (cur != NULL)
    {
        struct bm_unlocked_pq_identity *next = cur->next;
        free_entry(cur);
        cur = next;
    }
    kr->pq_head = NULL;
}

int bm_pq_keyring_remove_locked(bm_keyring_t *kr, const char *address)
{
    for (struct bm_unlocked_pq_identity **cur = &kr->pq_head; *cur != NULL; cur = &(*cur)->next)
    {
        if (strncmp((*cur)->address, address, BM_KEYRING_MAX_ADDRESS_LEN) == 0)
        {
            struct bm_unlocked_pq_identity *victim = *cur;
            *cur = victim->next;
            free_entry(victim);
            return 0;
        }
    }
    return -1;
}
