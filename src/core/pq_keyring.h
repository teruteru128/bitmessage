#ifndef BM_CORE_PQ_KEYRING_H
#define BM_CORE_PQ_KEYRING_H

/*
 * §11 2026-11-04 項目55の段3: v5(ポスト量子)identityのkeyring(DESIGN-PQ.md §9.3)。
 * BM_HAVE_PQのビルドでのみコンパイルされる。bm_keyring_t(keyring.h)のpq_headに
 * v4以前とは別のリストとして持ち、ロックはv4以前と共通のkr->lockを使う。
 *
 * 秘密鍵の持ち方: identity.dbには成分seed(160byte)だけをラップして保存し、unlockしても
 * seedを復号するだけで、展開済みの秘密鍵(sig_sk 4064byte・kem_sk 2432byte)は作らない。
 * 初めて秘密鍵が要るとき(bm_pq_keyring_get_secret_keys)に展開してキャッシュする(遅延生成)。
 * 展開は1 identityあたり0.4〜0.6ms(DESIGN-PQ.md §8.1.1)だが、v4で実際にあった規模
 * (数十万本の一括unlock)だと1スレッドで数分になるので、unlockの時点では払わない。
 */

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#include "../pq/address_v5.h"
#include "../pq/pq_object.h"
#include "keyring.h"

struct bm_unlocked_pq_identity
{
    char address[BM_KEYRING_MAX_ADDRESS_LEN];
    uint64_t address_version;
    uint64_t stream;
    unsigned char id[BM_PQV5_ID_LEN];
    unsigned char tag[32]; /* bm_pqv5_derive_secret_and_tagの後半。v5のgetpubkeyはこれで引く */
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    struct bm_pqv5_component_seeds seeds; /* 秘密 */
    int expanded;                         /* 1ならsig_sk/kem_skが有効 */
    unsigned char sig_sk[BM_PQV5_SIG_SK_LEN];
    unsigned char kem_sk[BM_PQV5_KEM_SK_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    int64_t unlocked_at;
    struct bm_unlocked_pq_identity *next;
};

/* unlock済みv5 identityの公開情報(秘密を含まない写し)。findの結果として返す */
struct bm_pq_identity_public
{
    char address[BM_KEYRING_MAX_ADDRESS_LEN];
    uint64_t address_version;
    uint64_t stream;
    unsigned char id[BM_PQV5_ID_LEN];
    unsigned char tag[32];
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
};

/*
 * 生成したv5 identity(成分seedを含む)を、passphraseから行ごとのscryptで作ったKEKでラップして
 * identity.dbへ保存する(v4のbm_keyring_create_identityと同じ規則)。out_addressには
 * "BM-..."を書く(NULL可)。同じアドレスが既にあれば失敗する。成功時0。
 */
int bm_pq_keyring_create_identity(sqlite3 *db, const struct bm_pqv5_identity *identity, const char *label,
                                  const char *passphrase, uint64_t nonce_trials_per_byte,
                                  uint64_t payload_length_extra_bytes, int64_t now,
                                  char out_address[BM_KEYRING_MAX_ADDRESS_LEN]);

/*
 * identity.dbのv5の行を読み、公開鍵とアドレスのidの整合を確かめ、passphraseから求めたKEKで
 * 成分seedを復号してkeyringへ追加する。既にunlock済みなら何もせず0。passphrase誤り・改竄
 * (GCMタグ不一致・公開鍵とidの不一致)・アドレス不在は全て非0。
 */
int bm_pq_keyring_unlock(bm_keyring_t *kr, sqlite3 *db, const char *address, const char *passphrase,
                         int64_t now);

/* unlock済みならoutに公開情報を写してtrue */
bool bm_pq_keyring_find_by_address(bm_keyring_t *kr, const char *address, struct bm_pq_identity_public *out);
bool bm_pq_keyring_find_by_tag(bm_keyring_t *kr, const unsigned char tag[32], struct bm_pq_identity_public *out);

/*
 * unlock済みのv5 identityの展開済み秘密鍵をout_*へ写す(どちらもNULL可)。未展開なら成分seedから
 * 展開し、展開した公開鍵が保存済みのものと一致することを確かめてからキャッシュする。
 * 未unlock・展開の失敗・公開鍵の不一致は非0。out_*は使い終わったらOPENSSL_cleanseすること。
 */
int bm_pq_keyring_get_secret_keys(bm_keyring_t *kr, const char *address, unsigned char *out_sig_sk,
                                  unsigned char *out_kem_sk);

/*
 * §11 2026-11-04 項目55の段5: v5のmsg(objectVersion 2、nonce込みの完全なobject)を、unlock済みの
 * v5 identityの鍵で開封する。addressがNULLなら全identityを試し、非NULLならその1件だけを試す
 * (unlock直後のbackfill用。v4のbm_trial_decrypt_msg_singleと同じ理由で、keyring全体を
 * 総当たりしない)。未展開の鍵は先に展開する(1件0.4〜0.6ms、そのidentityで初回だけ)。
 *
 * 次の場合は成功にしない: 開封や署名検証の失敗 / 平文のto_idがそのidentityのidと違う
 * (なりすまし転送対策、DESIGN-PQ.md §7.3) / fromAddressVersionが5でない(v5の鍵はv4以前の
 * アドレスとして表せない。これを通すと、署名は正しいのに鍵と対応しない差出人アドレスが作れる)。
 *
 * 成功時0でoutを埋め(bm_pq_msg_parsed_freeで解放すること)、宛先のアドレスをout_to_addressへ
 * 書く。失敗時は非0で、outは解放済み。
 */
int bm_pq_keyring_open_msg(bm_keyring_t *kr, const char *address, const unsigned char *object, size_t object_len,
                           struct bm_pq_msg_parsed *out, char out_to_address[BM_KEYRING_MAX_ADDRESS_LEN]);

/* 以下2つはkeyring.cから、kr->lockを書き込みで握った状態で呼ぶ */
void bm_pq_keyring_clear_locked(bm_keyring_t *kr);
int bm_pq_keyring_remove_locked(bm_keyring_t *kr, const char *address); /* 外したら0、無ければ-1 */

#endif /* BM_CORE_PQ_KEYRING_H */
