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
 *   - id先頭に0x00を要求する探索ループは維持する(既定1byte、v4と同じ)。ただし
 *     「どちらの鍵を引き直して探索するか」を選べるようにした(enum bm_pqv5_search_mode)
 * 変えていない点: "BM-" + Base58(varint(version)||varint(stream)||id||checksum) という
 * 全体の形と、checksum = double_sha512(...)[0:4]。既存のアドレス検証ツールが
 * バージョンを知らなくてもチェックサムだけは検証できる状態を保つため。
 */

#include <stddef.h>
#include <stdint.h>

#include "pq_hybrid.h"

#define BM_PQV5_ADDRESS_VERSION 5
#define BM_PQV5_ID_LEN 32

/*
 * §11 2026-09-17 id先頭に要求する0x00バイト数の既定値。
 *
 * v4(PyBitmessageのnumberOfNullBytesDemandedOnFrontOfRipeHash)と同じく1にした。
 * この探索はプロトコル上の要求ではなく「base58エンコード時に先頭0x00が除去される
 * のを利用してアドレス文字列を短くする」ためだけのもの(DESIGN-PQ.md §4.2に一次資料)
 * だが、1byte要求すると**全アドレスの長さが53文字に揃う**(要求しないと255/256が
 * 54文字、1/256が53文字以下とばらつく)。ユーザー判断で「長さは揃えたほうがいい」と
 * なったため1を既定とした(2026-09-17)。
 */
#define BM_PQV5_DEFAULT_NULL_BYTES 1

/*
 * §11 2026-09-17 v5アドレスの鍵は4成分(ML-DSA / Ed25519 / ML-KEM / X25519)から成る。
 * 決定性生成では1本のroot(64byte)から成分ごとに独立したサブseedを導出する:
 *
 *   root          = SHA3-512(label || 0x00 || passphrase || varint(nonce))
 *   sub_seed(c,k) = SHAKE128(root || component_label(c) || 0x00 || varint(k), 必要長)
 *
 * こうしてあるのは、id先頭0x00の探索(null_bytes>=1)で**どの成分だけを引き直すかを
 * 選べるようにする**ため。成分ごとに鍵生成コストが大きく違うので、一番安い成分だけを
 * 回せば探索が最も安く済む(実測はDESIGN-PQ.md §8.2)。X-Wingの「32byte seed 1本から
 * ML-KEMとX25519の両方を導出する」構造のままではX25519だけを引き直せないため、
 * そこはあえて分離した(X-Wingの公開鍵・暗号文・共有秘密の計算自体は仕様通り)。
 *
 * identityはnonceと4本のカウンタを保持するので、決定性は完全に保たれる
 * (同じパスフレーズ・nonce・カウンタなら必ず同じアドレス)。
 */
enum bm_pqv5_component
{
    BM_PQV5_COMP_MLDSA = 0,
    BM_PQV5_COMP_ED25519,
    BM_PQV5_COMP_MLKEM,
    BM_PQV5_COMP_X25519,
    BM_PQV5_COMP_COUNT
};

#define BM_PQV5_ROOT_LEN 64

/*
 * 探索で引き直す成分。既定は最も安いX25519(スカラー倍1回だけ)。
 *
 * 値はenum bm_pqv5_componentと一致させてある(探索本体がmodeをそのまま成分番号として
 * 使うため)。ここを独立した番号にしていて実際に取り違えるバグを出したので、
 * 定義でCOMP側に結び付けて再発しないようにした(2026-09-17)。
 */
enum bm_pqv5_search_mode
{
    BM_PQV5_SEARCH_MLDSA = BM_PQV5_COMP_MLDSA,
    BM_PQV5_SEARCH_ED25519 = BM_PQV5_COMP_ED25519,
    BM_PQV5_SEARCH_MLKEM = BM_PQV5_COMP_MLKEM,
    BM_PQV5_SEARCH_X25519 = BM_PQV5_COMP_X25519,
    BM_PQV5_SEARCH_ALL = BM_PQV5_COMP_COUNT /* 4成分とも引き直す(v4のペア増加に相当) */
};

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
    /* 決定性生成時のアドレス番号(ランダム生成時は0)と、探索で進んだ成分カウンタ。
     * この2つ+パスフレーズがあればアドレスを完全に再現できる */
    uint64_t nonce;
    uint32_t counters[BM_PQV5_COMP_COUNT];
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

/* root(64byte)と成分カウンタからidentityを組み立てる(idまで計算する)。成功時0 */
int bm_pqv5_identity_from_root(uint64_t stream, const unsigned char root[BM_PQV5_ROOT_LEN],
                                const uint32_t counters[BM_PQV5_COMP_COUNT],
                                struct bm_pqv5_identity *out);

/* CSPRNGから新規identityを作る。null_bytes/modeの意味は決定性生成と同じ。成功時0 */
int bm_pqv5_identity_generate_random(uint64_t stream, int null_bytes,
                                      enum bm_pqv5_search_mode mode,
                                      struct bm_pqv5_identity *out);

/*
 * パスフレーズ由来の決定性生成。nonceがアドレス番号(同じパスフレーズから複数の
 * アドレスを作るときに変える値)。idの先頭null_bytesバイトが0x00になるまで、
 * modeで指定した成分のカウンタを1ずつ進めて探索する(null_bytes=0なら探索なし)。成功時0。
 */
int bm_pqv5_identity_generate_deterministic(const char *passphrase, uint64_t stream,
                                             uint64_t nonce, int null_bytes,
                                             enum bm_pqv5_search_mode mode,
                                             struct bm_pqv5_identity *out);

#endif /* BM_PQ_ADDRESS_V5_H */
