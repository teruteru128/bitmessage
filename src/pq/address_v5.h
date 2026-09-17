#ifndef BM_PQ_ADDRESS_V5_H
#define BM_PQ_ADDRESS_V5_H

/*
 * v5(ポスト量子)アドレスの生成・エンコード・デコード。DESIGN-PQ.md §4。
 *
 * 既存のv2〜v4アドレス(core/address.c)との違い:
 *   - identifierがRIPEMD160(SHA512(...))の20byteではなくSHA3-256の32byte
 *     (理由はDESIGN-PQ.md §4.1。20byteだと衝突計算量が2^80で、ML-DSA-65/ML-KEM-768に
 *      対して明らかに弱い環になる)
 *   - identifier計算にversion/streamを含める(pubkeyオブジェクトのstream跨ぎ再利用を防ぐ)
 *   - ripe先頭に0x00を要求する探索ループを廃止(アドレスを数文字縮めるためだけの
 *     仕掛けで、32byte identifierでは効果が相対的に小さい。null_bytes引数自体は
 *     ベンチマーク用に残してある)
 * 変えていない点: "BM-" + Base58(varint(version)||varint(stream)||id||checksum) という
 * 全体の形と、checksum = double_sha512(...)[0:4]。既存のアドレス検証ツールが
 * バージョンを知らなくてもチェックサムだけは検証できる状態を保つため。
 */

#include <stddef.h>
#include <stdint.h>

#include "pq_hybrid.h"

#define BM_PQV5_ADDRESS_VERSION 5
#define BM_PQV5_ID_LEN 32

/* identifier・tag導出のドメイン分離ラベル */
#define BM_PQV5_LABEL_ID "BitmessagePQ-v5-id"
#define BM_PQV5_LABEL_TAG "BitmessagePQ-v5-tag"
#define BM_PQV5_LABEL_DETERMINISTIC "BitmessagePQ-v5-deterministic"

struct bm_pqv5_identity
{
    uint64_t version;
    uint64_t stream;
    unsigned char sig_pk[BM_PQV5_SIG_PK_LEN];
    unsigned char sig_sk[BM_PQV5_SIG_SK_LEN];
    unsigned char kem_pk[BM_PQV5_KEM_PK_LEN];
    unsigned char kem_sk[BM_PQV5_KEM_SK_LEN];
    unsigned char id[BM_PQV5_ID_LEN];
    /* 決定性生成時のnonce(ランダム生成時は0) */
    uint64_t sig_nonce;
    uint64_t kem_nonce;
};

/* id = SHA3-256(label || varint(version) || varint(stream) || sig_pk || kem_pk) */
void bm_pqv5_calc_id(uint64_t version, uint64_t stream,
                      const unsigned char sig_pk[BM_PQV5_SIG_PK_LEN],
                      const unsigned char kem_pk[BM_PQV5_KEM_PK_LEN],
                      unsigned char out_id[BM_PQV5_ID_LEN]);

/*
 * SHA3-512(label || varint(version) || varint(stream) || id) を
 * 前半32byte(アドレス由来KEM鍵のseed)と後半32byte(tag)に分ける。
 * v4のbm_address_derive_secret_and_tagと同じ役割。out_*はNULL可。
 */
void bm_pqv5_derive_secret_and_tag(uint64_t version, uint64_t stream,
                                    const unsigned char id[BM_PQV5_ID_LEN],
                                    unsigned char out_seed[BM_PQV5_SEED_LEN],
                                    unsigned char out_tag[32]);

/* アドレス由来のKEM鍵ペア(そのアドレスを知っている人なら誰でも作れる) */
int bm_pqv5_address_kem_keypair(uint64_t version, uint64_t stream,
                                 const unsigned char id[BM_PQV5_ID_LEN],
                                 unsigned char out_pk[BM_PQV5_KEM_PK_LEN],
                                 unsigned char out_sk[BM_PQV5_KEM_SK_LEN]);

/* "BM-..."文字列(malloc、呼び出し側でfree)。失敗時NULL */
char *bm_pqv5_address_encode(uint64_t version, uint64_t stream, const unsigned char id[BM_PQV5_ID_LEN]);

/*
 * "BM-"は省略可。checksum検証・version==5検証・非正規エンコーディング
 * (先頭0x00が残っている)の拒否まで行う。成功時0。
 */
int bm_pqv5_address_decode(const char *address, uint64_t *out_version, uint64_t *out_stream,
                            unsigned char out_id[BM_PQV5_ID_LEN]);

/* 2本のseedからidentityを組み立てる(idまで計算する)。成功時0 */
int bm_pqv5_identity_from_seeds(uint64_t stream,
                                 const unsigned char sig_seed[BM_PQV5_SEED_LEN],
                                 const unsigned char kem_seed[BM_PQV5_SEED_LEN],
                                 struct bm_pqv5_identity *out);

/* CSPRNGから新規identityを作る。成功時0 */
int bm_pqv5_identity_generate_random(uint64_t stream, struct bm_pqv5_identity *out);

/*
 * パスフレーズ由来の決定性生成。
 *   sig_seed = SHA3-512(label || 0x00 || passphrase || varint(nonce))[0:32]
 *   kem_seed = SHA3-512(label || 0x00 || passphrase || varint(nonce+1))[0:32]
 * nonceは start_nonce から2ずつ進め、idの先頭null_bytesバイトが0x00になるまで探索する
 * (null_bytes=0なら1回で確定=探索なし。v5の既定は0)。成功時0。
 */
int bm_pqv5_identity_generate_deterministic(const char *passphrase, uint64_t stream,
                                             uint64_t start_nonce, int null_bytes,
                                             struct bm_pqv5_identity *out);

#endif /* BM_PQ_ADDRESS_V5_H */
