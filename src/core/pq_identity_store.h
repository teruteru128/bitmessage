#ifndef BM_CORE_PQ_IDENTITY_STORE_H
#define BM_CORE_PQ_IDENTITY_STORE_H

/*
 * §11 2026-11-04 項目55の段3: v5(ポスト量子)identityのidentity.dbへの保存
 * (DESIGN-PQ.md §9.3)。BM_HAVE_PQのビルドでのみコンパイルされる。
 *
 * v4以前のidentities表とは別の表(pq_identities)にした。鍵の形が全く違い(公開鍵だけで
 * 3200byte、秘密は成分seed 160byte)、identities表の固定長の列(65byteの公開鍵・60byteの
 * ラップ済み鍵2本)へ押し込むと、既存の全ての読み手がv5の行を誤って解釈しうるため。
 * 秘密鍵はこのモジュールを常にラップ済みの状態でのみ通る(identity_store.hと同じ規律。
 * 平文のseedの扱いはpq_keyring.cの責務)。
 *
 * 公開鍵は平文で保存する(v4のidentities表と同じ。アドレス一覧やgetpubkeyへの自応答の判定に
 * unlockを要らなくするため)。公開鍵を改竄されても、idとの照合(pq_keyring.c)と、seedの
 * GCM(AAD=アドレス、アドレスはidを含む)で検出できる。
 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "../pq/address_v5.h"
#include "identity_store.h"
#include "keyring_internal.h"

#define BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN (BM_PQV5_COMPONENT_SEEDS_LEN + BM_KEYRING_WRAP_OVERHEAD)

struct bm_pq_identity_row
{
    char address[BM_IDENTITY_ADDRESS_MAX];
    char label[BM_IDENTITY_LABEL_MAX];
    int enabled;
    uint64_t address_version;
    uint64_t stream;
    unsigned char id[BM_PQV5_ID_LEN];
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    char kdf_algo[BM_IDENTITY_KDF_ALGO_MAX];
    unsigned char kdf_salt[BM_IDENTITY_KDF_SALT_LEN];
    char kdf_params[BM_IDENTITY_KDF_PARAMS_MAX];
    unsigned char wrapped_seeds[BM_PQ_IDENTITY_WRAPPED_SEEDS_LEN];
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    int64_t created_time;
};

/* bm_identity_store_init_schemaから呼ばれる(BM_HAVE_PQのビルドのみ)。成功時0 */
int bm_pq_identity_store_init_schema(sqlite3 *db);

/* 成功時0。同じaddressが既にあれば失敗する(INSERT、UPSERTしない) */
int bm_pq_identity_store_insert(sqlite3 *db, const struct bm_pq_identity_row *row);

/* 見つかれば0。見つからない・列の長さが期待と違う(壊れた行)・エラーは非0 */
int bm_pq_identity_store_load(sqlite3 *db, const char *address, struct bm_pq_identity_row *out);

/* 該当行が無くてもエラーにしない。成功時0 */
int bm_pq_identity_store_delete(sqlite3 *db, const char *address);

/* 全v5 identityの一覧(identity_store.hのbm_identity_summaryと同じ形、is_chanは常に0)。
 * *out_listはmalloc、呼び出し側でfreeする。成功時0(0件でも成功) */
int bm_pq_identity_store_list(sqlite3 *db, struct bm_identity_summary **out_list, size_t *out_count);

#endif /* BM_CORE_PQ_IDENTITY_STORE_H */
