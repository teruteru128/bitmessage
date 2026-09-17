#ifndef BM_PQ_HYBRID_H
#define BM_PQ_HYBRID_H

/*
 * v5プロファイル(profile 1)のハイブリッド署名・ハイブリッドKEM・AEAD封緘。
 * DESIGN-PQ.md §5(暗号プリミティブ)・§6。
 *
 *   署名: ML-DSA-65 + Ed25519 (両方の検証が通って初めて有効)
 *   KEM : X-Wing (ML-KEM-768 + X25519、draft-connolly-cfrg-xwing-kem の combiner)
 *   AEAD: AES-256-GCM (鍵はKEMの共有秘密そのもの、nonceは全0固定)
 *
 * 「PQ単独ではなくハイブリッド」にしている理由はDESIGN-PQ.md §3.3を参照
 * (格子暗号の実装バグ・将来の解読の両方に対する保険。Ed25519/X25519を足す
 * コストは公開鍵64byte・署名64byte・ct 32byteで、ML-DSA/ML-KEM本体に対して数%)。
 */

#include <stddef.h>

/* ML-DSA-65 pk(1952) || Ed25519 pk(32) */
#define BM_PQV5_SIG_PK_LEN 1984
/* ML-DSA-65 sk(4032) || Ed25519 seed(32) */
#define BM_PQV5_SIG_SK_LEN 4064
/* ML-DSA-65 sig(3309) || Ed25519 sig(64) */
#define BM_PQV5_SIG_LEN 3373
/* ML-KEM-768 pk(1184) || X25519 pk(32) */
#define BM_PQV5_KEM_PK_LEN 1216
/* ML-KEM-768 sk(2400) || X25519 sk(32) */
#define BM_PQV5_KEM_SK_LEN 2432
/* ML-KEM-768 ct(1088) || X25519 ct(32) */
#define BM_PQV5_KEM_CT_LEN 1120
/* 署名鍵・KEM鍵とも32byteのseedから決定性生成する */
#define BM_PQV5_SEED_LEN 32
#define BM_PQV5_AEAD_TAG_LEN 16
/* seal後の固定増分: KEM暗号文 + GCMタグ */
#define BM_PQV5_SEAL_OVERHEAD (BM_PQV5_KEM_CT_LEN + BM_PQV5_AEAD_TAG_LEN)

/* --- ハッシュ(v5プロファイルはSHA-3系で統一。理由はDESIGN-PQ.md §5.4) --- */
void bm_pq_sha3_256(const unsigned char *data, size_t len, unsigned char out[32]);
void bm_pq_sha3_512(const unsigned char *data, size_t len, unsigned char out[64]);
int bm_pq_shake128(const unsigned char *data, size_t len, unsigned char *out, size_t out_len);

/* --- ハイブリッド署名 --- */

/*
 * seed(32byte)から署名鍵ペアを決定性生成する。内部で
 *   SHAKE128(seed, 64) = xi_MLDSA(32) || ed25519_seed(32)
 * に展開してから各アルゴリズムのKeyGenへ渡す(X-Wingの鍵展開と同じ作法)。成功時0。
 */
int bm_pqv5_sig_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_SIG_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_SIG_SK_LEN]);

/*
 * §11 2026-09-17 4成分それぞれを独立に作り直すための粒度の細かいAPI。
 *
 * アドレス生成の探索ループ(address_v5.h の enum bm_pqv5_search_mode)で
 * 「どの鍵を引き直すか」を選べるようにするために必要。成分ごとに鍵生成コストが
 * 大きく違う(実測: ML-DSA-65 224us / ML-KEM-768 83us / X25519・Ed25519は
 * スカラー倍1回)ので、一番安い成分だけを回せば探索が最も安く済む。
 *
 * out_pk/out_skは完成した鍵ブロブで、該当成分のオフセットだけを書き換える。
 * 4本を全部呼べばbm_pqv5_*_keypair_from_seedと同等の鍵ブロブになる(seedの
 * 導出元が違うだけ)。成功時0。
 */
int bm_pqv5_sig_set_mldsa(const unsigned char xi[32], unsigned char *out_pk, unsigned char *out_sk);
int bm_pqv5_sig_set_ed25519(const unsigned char seed[32], unsigned char *out_pk, unsigned char *out_sk);
int bm_pqv5_kem_set_mlkem(const unsigned char coins[64], unsigned char *out_pk, unsigned char *out_sk);
int bm_pqv5_kem_set_x25519(const unsigned char sk32[32], unsigned char *out_pk, unsigned char *out_sk);

/*
 * labelは用途ごとのドメイン分離文字列(NUL終端、pq_object.hのBM_PQ_SIGLABEL_*)。
 * 実際に署名される入力は label || 0x00 || msg で、ML-DSAとEd25519の両方に同じ
 * 入力を与える。成功時0。
 */
int bm_pqv5_sign(const char *label, const unsigned char *msg, size_t msg_len,
                  const unsigned char sk[BM_PQV5_SIG_SK_LEN],
                  unsigned char out_sig[BM_PQV5_SIG_LEN]);

/* 両方の署名が検証できたときだけ1。片方でも失敗したら0 */
int bm_pqv5_verify(const char *label, const unsigned char *msg, size_t msg_len,
                    const unsigned char sig[BM_PQV5_SIG_LEN],
                    const unsigned char pk[BM_PQV5_SIG_PK_LEN]);

/* --- ハイブリッドKEM(X-Wing)とAEAD封緘 --- */

int bm_pqv5_kem_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_KEM_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_KEM_SK_LEN]);

/*
 * 封緘: out = KEM暗号文(1120) || AES-256-GCM(平文) || GCMタグ(16)。
 * out_lenには BM_PQV5_SEAL_OVERHEAD + pt_len が入る(呼び出し側が事前に
 * その長さのバッファを用意する)。aadは認証のみされ暗号化されない部分
 * (オブジェクトの平文ヘッダ)。成功時0。
 */
int bm_pqv5_seal(const unsigned char recipient_pk[BM_PQV5_KEM_PK_LEN],
                  const unsigned char *aad, size_t aad_len,
                  const unsigned char *pt, size_t pt_len,
                  unsigned char *out, size_t *out_len);

/*
 * 開封。aadが封緘時と1bitでも違えばGCMタグ検証で失敗する。
 * out_lenには in_len - BM_PQV5_SEAL_OVERHEAD が入る。成功時0、
 * 復号失敗(=自分宛てでない/改竄)時は非0。
 */
int bm_pqv5_open(const unsigned char sk[BM_PQV5_KEM_SK_LEN],
                  const unsigned char *aad, size_t aad_len,
                  const unsigned char *in, size_t in_len,
                  unsigned char *out, size_t *out_len);

#endif /* BM_PQ_HYBRID_H */
