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
    uint64_t address_version;
    uint64_t stream;
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
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

/*
 * §11 2026-08-29 exportAddress用(DESIGN.md §6.2/§7、importAddressと対称)。identity.dbから
 * ラップ済み鍵を読み、passphraseから導出したKEKで復号して平文を返す一回性操作。
 * unlockAddressと違いkeyringには一切触れない(呼び出し元がWIFへエンコードして返したら
 * その場で破棄する想定、keyring常駐はさせない)。行がvault-hkdf方式でもscrypt方式でも
 * 対応する(内部でkdf_algoを見て自動判別する)。成功時0、passphrase誤り・address不在は非0。
 */
int bm_keyring_export(sqlite3 *db, const char *address, const char *passphrase,
                       unsigned char out_priv_signing[32], unsigned char out_priv_encryption[32]);

/* OPENSSL_cleanseでゼロ埋めしてから除去する。見つからなければ非0。identity.db側は変更しない */
int bm_keyring_lock(bm_keyring_t *kr, const char *address);
void bm_keyring_lock_all(bm_keyring_t *kr);

/* keyringからロック相当の消去をした上でidentity.dbから該当行を完全削除する(復元不可) */
int bm_keyring_delete_identity(bm_keyring_t *kr, sqlite3 *db, const char *address);

/*
 * §11 chan仕様: identities.is_chanを1に設定する(chan識別用のフラグ、暗号的には通常の
 * deterministic addressと全く同じ扱い。共有passphraseから同じ鍵が導出されるpeer全員が
 * 同じアドレス/鍵を持つことで疑似グループチャットとして機能する)。該当行が無ければ
 * 何もしない。成功時0。
 */
int bm_keyring_mark_as_chan(sqlite3 *db, const char *address);

/* ripeで検索する。見つかればtrueを返しoutにコピーする(呼び出し側が用意した領域へ) */
bool bm_keyring_find_by_ripe(bm_keyring_t *kr, const unsigned char ripe[20],
                              struct bm_unlocked_identity *out);

/*
 * v4以降のgetpubkeyに含まれるtag(32byte)で検索する(§5.1)。address_version>=4の
 * unlocked identityそれぞれについてtagを導出し比較する(通常identity数は少数なので
 * 線形探索で十分)。見つかればtrueを返しoutにコピーする。
 */
bool bm_keyring_find_by_tag(bm_keyring_t *kr, const unsigned char tag[32],
                             struct bm_unlocked_identity *out);

/* address文字列で検索する(send_pipeline.cがfromアドレスの鍵を引く際に使う) */
bool bm_keyring_find_by_address(bm_keyring_t *kr, const char *address,
                                 struct bm_unlocked_identity *out);

struct bm_unlock_all_entry
{
    char address[BM_KEYRING_MAX_ADDRESS_LEN];
    int unlocked; /* 成功(または既にunlock済みでスキップ)なら1、passphrase不一致等なら0 */
};

/*
 * §11 2026-08-29 数千件規模の一括インポート運用向け(DESIGN.md §11-19)。
 * identity.dbの全行に対し、共通のpassphraseで順にbm_keyring_unlock相当の処理を試みる。
 * 各行のkdf_saltは個別のまま(スキーマ変更なし)なので、行ごとにAEADタグ検証が走り、
 * 「全アドレスが同一passphrase」という前提を強制しない設計にしてある
 * (不一致の行は黙ってunlocked=0として結果に含めるだけで処理を中断しない)。
 * 既にkeyringにunlock済みのアドレスは再試行せずunlocked=1として扱う。
 * 成功時0、*out_countに全identity数(結果配列の要素数)を設定する。
 * *out_resultsはmalloc(呼び出し側でfreeすること)。
 */
int bm_keyring_unlock_all(bm_keyring_t *kr, sqlite3 *db, const char *passphrase,
                           struct bm_unlock_all_entry **out_results, size_t *out_count);

#endif /* BM_CORE_KEYRING_H */
