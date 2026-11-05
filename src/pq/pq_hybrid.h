#ifndef BM_PQ_HYBRID_H
#define BM_PQ_HYBRID_H

/*
 * v5プロファイル(profile 1)のハイブリッド署名・ハイブリッドKEM・AEAD封緘。
 * DESIGN-PQ.md §5(暗号プリミティブ)・§6。
 *
 *   署名: ML-DSA-65 + Ed25519 (両方の検証が通って初めて有効)
 *   KEM : X-Wing (ML-KEM-768 + X25519、draft-connolly-cfrg-xwing-kem-11に準拠)
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
int bm_pq_shake256(const unsigned char *data, size_t len, unsigned char *out, size_t out_len);

/* --- ハイブリッド署名 --- */

/*
 * seed(32byte)から署名鍵ペアを決定性生成する。内部で
 *   SHAKE128(seed, 64) = xi_MLDSA(32) || ed25519_seed(32)
 * に展開してから各アルゴリズムのKeyGenへ渡す。成功時0。
 * X-Wingと同じ「seed 1本を展開する」作法だが、このハイブリッド署名はこのプロジェクト独自の
 * 構成なのでdraftの範囲外。§5.2 2026-11-05 X-Wing側はSHAKE256へ揃えたが、draftのChange logが
 * 「この出力長ならSHAKE128と256で安全性は変わらない」としているので、こちらは変えていない。
 */
int bm_pqv5_sig_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_SIG_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_SIG_SK_LEN]);

/*
 * ML-DSAとEd25519の両方に**同じmsgをそのまま**与えて署名する。成功時0。
 *
 * §11 2026-09-18: 当初は用途ごとのドメイン分離ラベルをmsgの先頭に連結していたが、
 * 削除した(ユーザー指摘)。オブジェクト署名の対象には必ず共通ヘッダ
 * (objectType 4byte + objectVersion)が含まれるので、種別間の分離は既に達成されており
 * ラベルは重複でしかない。v4(ECDSA)がラベル無しで済んでいるのと同じ理屈。
 * ML-DSAのcontext string(FIPS 204 §5.2)も空のまま。
 */
int bm_pqv5_sign(const unsigned char *msg, size_t msg_len,
                  const unsigned char sk[BM_PQV5_SIG_SK_LEN],
                  unsigned char out_sig[BM_PQV5_SIG_LEN]);

/* 両方の署名が検証できたときだけ1。片方でも失敗したら0 */
int bm_pqv5_verify(const unsigned char *msg, size_t msg_len,
                    const unsigned char sig[BM_PQV5_SIG_LEN],
                    const unsigned char pk[BM_PQV5_SIG_PK_LEN]);

/* --- ハイブリッドKEM(X-Wing)とAEAD封緘 --- */

int bm_pqv5_kem_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_KEM_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_KEM_SK_LEN]);

/*
 * X-Wingのカプセル化・脱カプセル化(ss = 32byte)。封緘の内部処理だが、draftのテストベクタと
 * 共有秘密を突き合わせるために公開している(AEADを通すと共有秘密を直接比べられない)。成功時0。
 */
int bm_pqv5_xwing_encaps(const unsigned char pk[BM_PQV5_KEM_PK_LEN],
                         unsigned char out_ct[BM_PQV5_KEM_CT_LEN], unsigned char out_ss[32]);
int bm_pqv5_xwing_decaps(const unsigned char sk[BM_PQV5_KEM_SK_LEN],
                         const unsigned char ct[BM_PQV5_KEM_CT_LEN], unsigned char out_ss[32]);

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
