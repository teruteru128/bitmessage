/* pq_hybrid.h の説明を参照。DESIGN-PQ.md §5・§6。 */

#include "pq_hybrid.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "pq_crypto.h"

#define MLDSA_PK_LEN 1952
#define MLDSA_SK_LEN 4032
#define MLDSA_SIG_LEN 3309
#define MLKEM_PK_LEN 1184
#define MLKEM_SK_LEN 2400
#define MLKEM_CT_LEN 1088
#define ED25519_PK_LEN 32
#define ED25519_SK_LEN 32
#define ED25519_SIG_LEN 64
#define X25519_LEN 32

/* v5プロファイルで使うPQアルゴリズム(ここを変えると別プロファイル=別アドレス版になる) */
#define PQV5_SIG_ALG BM_PQ_SIG_ML_DSA_65
#define PQV5_KEM_ALG BM_PQ_KEM_ML_KEM_768

void bm_pq_sha3_256(const unsigned char *data, size_t len, unsigned char out[32])
{
    unsigned int outlen = 0;
    EVP_Digest(data, len, out, &outlen, EVP_sha3_256(), NULL);
}

void bm_pq_sha3_512(const unsigned char *data, size_t len, unsigned char out[64])
{
    unsigned int outlen = 0;
    EVP_Digest(data, len, out, &outlen, EVP_sha3_512(), NULL);
}

int bm_pq_shake128(const unsigned char *data, size_t len, unsigned char *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (ctx == NULL)
    {
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake128(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, len) == 1 &&
        EVP_DigestFinalXOF(ctx, out, out_len) == 1)
    {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* --- Ed25519 / X25519の薄いヘルパ(OpenSSL 3.0のEVP raw key APIのみ使用) --- */

static int ed25519_public_from_seed(const unsigned char seed[ED25519_SK_LEN],
                                     unsigned char out_pk[ED25519_PK_LEN])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, ED25519_SK_LEN);
    size_t len = ED25519_PK_LEN;
    int rc = -1;
    if (pkey == NULL)
    {
        return -1;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, out_pk, &len) == 1 && len == ED25519_PK_LEN)
    {
        rc = 0;
    }
    EVP_PKEY_free(pkey);
    return rc;
}

static int ed25519_sign(const unsigned char seed[ED25519_SK_LEN],
                         const unsigned char *msg, size_t msg_len,
                         unsigned char out_sig[ED25519_SIG_LEN])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, ED25519_SK_LEN);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t siglen = ED25519_SIG_LEN;
    int rc = -1;
    if (pkey != NULL && ctx != NULL &&
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(ctx, out_sig, &siglen, msg, msg_len) == 1 &&
        siglen == ED25519_SIG_LEN)
    {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static int ed25519_verify(const unsigned char pk[ED25519_PK_LEN],
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char sig[ED25519_SIG_LEN])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, ED25519_PK_LEN);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (pkey != NULL && ctx != NULL &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, sig, ED25519_SIG_LEN, msg, msg_len) == 1)
    {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static int x25519_public_from_private(const unsigned char sk[X25519_LEN],
                                       unsigned char out_pk[X25519_LEN])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_LEN);
    size_t len = X25519_LEN;
    int rc = -1;
    if (pkey == NULL)
    {
        return -1;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, out_pk, &len) == 1 && len == X25519_LEN)
    {
        rc = 0;
    }
    EVP_PKEY_free(pkey);
    return rc;
}

static int x25519_shared(const unsigned char sk[X25519_LEN], const unsigned char peer_pk[X25519_LEN],
                          unsigned char out[X25519_LEN])
{
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_LEN);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, X25519_LEN);
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = X25519_LEN;
    int rc = -1;

    if (priv != NULL && peer != NULL)
    {
        ctx = EVP_PKEY_CTX_new(priv, NULL);
    }
    /* OpenSSLは共有秘密が全0(低位数点)になる場合にderiveを失敗させる。
     * X-Wing draftが要求する「all-zero output のチェック」はこれで満たされる */
    if (ctx != NULL && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, out, &len) == 1 && len == X25519_LEN)
    {
        rc = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return rc;
}

/* --- ハイブリッド署名 --- */

int bm_pqv5_sig_set_mldsa(const unsigned char xi[32], unsigned char *out_pk, unsigned char *out_sk)
{
    return bm_pq_sig_keypair_from_seed(PQV5_SIG_ALG, xi, out_pk, out_sk);
}

int bm_pqv5_sig_set_ed25519(const unsigned char seed[32], unsigned char *out_pk, unsigned char *out_sk)
{
    memcpy(out_sk + MLDSA_SK_LEN, seed, ED25519_SK_LEN);
    return ed25519_public_from_seed(seed, out_pk + MLDSA_PK_LEN);
}

int bm_pqv5_kem_set_mlkem(const unsigned char coins[64], unsigned char *out_pk, unsigned char *out_sk)
{
    return bm_pq_kem_keypair_from_seed(PQV5_KEM_ALG, coins, out_pk, out_sk);
}

int bm_pqv5_kem_set_x25519(const unsigned char sk32[32], unsigned char *out_pk, unsigned char *out_sk)
{
    memcpy(out_sk + MLKEM_SK_LEN, sk32, X25519_LEN);
    return x25519_public_from_private(sk32, out_pk + MLKEM_PK_LEN);
}

int bm_pqv5_sig_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_SIG_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_SIG_SK_LEN])
{
    unsigned char expanded[64];
    int rc = -1;
    if (bm_pq_shake128(seed, BM_PQV5_SEED_LEN, expanded, sizeof(expanded)) != 0)
    {
        return -1;
    }
    if (bm_pqv5_sig_set_mldsa(expanded, out_pk, out_sk) == 0 &&
        bm_pqv5_sig_set_ed25519(expanded + 32, out_pk, out_sk) == 0)
    {
        rc = 0;
    }
    OPENSSL_cleanse(expanded, sizeof(expanded));
    return rc;
}

/*
 * 署名対象を label || 0x00 || msg として組み立てる。labelは短い固定文字列なので
 * mallocせずにmsgと2回に分けて渡したいところだが、ML-DSA参照実装のAPIが
 * 連続バッファしか受け取らない(Ed25519側のEVP_DigestSignも同様)ため連結する。
 */
static unsigned char *build_signing_input(const char *label, const unsigned char *msg, size_t msg_len,
                                           size_t *out_len)
{
    size_t label_len = strlen(label);
    size_t total = label_len + 1 + msg_len;
    unsigned char *buf = OPENSSL_malloc(total);
    if (buf == NULL)
    {
        return NULL;
    }
    memcpy(buf, label, label_len);
    buf[label_len] = 0x00;
    memcpy(buf + label_len + 1, msg, msg_len);
    *out_len = total;
    return buf;
}

int bm_pqv5_sign(const char *label, const unsigned char *msg, size_t msg_len,
                  const unsigned char sk[BM_PQV5_SIG_SK_LEN],
                  unsigned char out_sig[BM_PQV5_SIG_LEN])
{
    size_t input_len = 0;
    unsigned char *input = build_signing_input(label, msg, msg_len, &input_len);
    size_t mldsa_len = 0;
    int rc = -1;

    if (input == NULL)
    {
        return -1;
    }
    if (bm_pq_sig_sign(PQV5_SIG_ALG, input, input_len, sk, out_sig, &mldsa_len) == 0 &&
        mldsa_len == MLDSA_SIG_LEN &&
        ed25519_sign(sk + MLDSA_SK_LEN, input, input_len, out_sig + MLDSA_SIG_LEN) == 0)
    {
        rc = 0;
    }
    OPENSSL_free(input);
    return rc;
}

int bm_pqv5_verify(const char *label, const unsigned char *msg, size_t msg_len,
                    const unsigned char sig[BM_PQV5_SIG_LEN],
                    const unsigned char pk[BM_PQV5_SIG_PK_LEN])
{
    size_t input_len = 0;
    unsigned char *input = build_signing_input(label, msg, msg_len, &input_len);
    int ok = 0;

    if (input == NULL)
    {
        return 0;
    }
    /* 両方通って初めて有効。片方でも落ちたら無効(ハイブリッドの意味がなくなるため
     * 「どちらか通ればOK」には絶対にしない) */
    if (bm_pq_sig_verify(PQV5_SIG_ALG, sig, MLDSA_SIG_LEN, input, input_len, pk) == 1 &&
        ed25519_verify(pk + MLDSA_PK_LEN, input, input_len, sig + MLDSA_SIG_LEN) == 1)
    {
        ok = 1;
    }
    OPENSSL_free(input);
    return ok;
}

/* --- X-Wing (ML-KEM-768 + X25519) --- */

/*
 * draft-connolly-cfrg-xwing-kem のcombiner:
 *   ss = SHA3-256( XWingLabel || ss_M || ss_X || ct_X || pk_X )
 * XWingLabelは6byteのASCII "\.//^\"。
 */
static void xwing_combiner(const unsigned char ss_m[32], const unsigned char ss_x[32],
                            const unsigned char ct_x[32], const unsigned char pk_x[32],
                            unsigned char out_ss[32])
{
    static const unsigned char label[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };
    unsigned char buf[6 + 32 * 4];
    memcpy(buf, label, sizeof(label));
    memcpy(buf + 6, ss_m, 32);
    memcpy(buf + 38, ss_x, 32);
    memcpy(buf + 70, ct_x, 32);
    memcpy(buf + 102, pk_x, 32);
    bm_pq_sha3_256(buf, sizeof(buf), out_ss);
    OPENSSL_cleanse(buf, sizeof(buf));
}

int bm_pqv5_kem_keypair_from_seed(const unsigned char seed[BM_PQV5_SEED_LEN],
                                   unsigned char out_pk[BM_PQV5_KEM_PK_LEN],
                                   unsigned char out_sk[BM_PQV5_KEM_SK_LEN])
{
    /* X-Wing draftの鍵展開: expanded = SHAKE128(seed, 96)、
     * 前64byteがML-KEMの(d,z)、後32byteがX25519の秘密鍵。
     * ただしdraftが秘密鍵を32byteのseedのまま保持するのに対し、この実装は
     * 展開後の形(ML-KEM sk || X25519 sk)で保持する。アドレス由来鍵のように
     * 「seedから毎回導出する」用途と、identityのように「保存した鍵を使う」用途の
     * 両方があり、後者で毎回ML-KEMのKeyGenをやり直すのを避けるため。 */
    unsigned char expanded[96];
    int rc = -1;
    if (bm_pq_shake128(seed, BM_PQV5_SEED_LEN, expanded, sizeof(expanded)) != 0)
    {
        return -1;
    }
    if (bm_pqv5_kem_set_mlkem(expanded, out_pk, out_sk) == 0 &&
        bm_pqv5_kem_set_x25519(expanded + 64, out_pk, out_sk) == 0)
    {
        rc = 0;
    }
    OPENSSL_cleanse(expanded, sizeof(expanded));
    return rc;
}

static int xwing_encaps(const unsigned char pk[BM_PQV5_KEM_PK_LEN],
                         unsigned char out_ct[BM_PQV5_KEM_CT_LEN], unsigned char out_ss[32])
{
    unsigned char eph_sk[X25519_LEN];
    unsigned char ss_m[32];
    unsigned char ss_x[32];
    int rc = -1;

    if (RAND_bytes(eph_sk, sizeof(eph_sk)) != 1)
    {
        return -1;
    }
    if (bm_pq_kem_encaps(PQV5_KEM_ALG, pk, out_ct, ss_m) == 0 &&
        x25519_public_from_private(eph_sk, out_ct + MLKEM_CT_LEN) == 0 &&
        x25519_shared(eph_sk, pk + MLKEM_PK_LEN, ss_x) == 0)
    {
        xwing_combiner(ss_m, ss_x, out_ct + MLKEM_CT_LEN, pk + MLKEM_PK_LEN, out_ss);
        rc = 0;
    }
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk));
    OPENSSL_cleanse(ss_m, sizeof(ss_m));
    OPENSSL_cleanse(ss_x, sizeof(ss_x));
    return rc;
}

static int xwing_decaps(const unsigned char sk[BM_PQV5_KEM_SK_LEN],
                         const unsigned char ct[BM_PQV5_KEM_CT_LEN], unsigned char out_ss[32])
{
    unsigned char ss_m[32];
    unsigned char ss_x[32];
    unsigned char pk_x[X25519_LEN];
    int rc = -1;

    if (bm_pq_kem_decaps(PQV5_KEM_ALG, ct, sk, ss_m) == 0 &&
        x25519_shared(sk + MLKEM_SK_LEN, ct + MLKEM_CT_LEN, ss_x) == 0 &&
        x25519_public_from_private(sk + MLKEM_SK_LEN, pk_x) == 0)
    {
        xwing_combiner(ss_m, ss_x, ct + MLKEM_CT_LEN, pk_x, out_ss);
        rc = 0;
    }
    OPENSSL_cleanse(ss_m, sizeof(ss_m));
    OPENSSL_cleanse(ss_x, sizeof(ss_x));
    return rc;
}

/* --- AEAD封緘 --- */

/*
 * nonceは全0固定。KEMの共有秘密は封緘ごとに新しく作られる(=AES-GCMの鍵が
 * 1回しか使われない)ので、nonce再利用の危険が構造的に無い。HPKEのbase modeで
 * seq=0の最初の1通だけを送るのと同じ状況。12byteをワイヤに載せる必要も無くなる。
 */
static const unsigned char g_zero_nonce[12] = { 0 };

static int aead_seal(const unsigned char key[32], const unsigned char *aad, size_t aad_len,
                      const unsigned char *pt, size_t pt_len,
                      unsigned char *out_ct, unsigned char out_tag[BM_PQV5_AEAD_TAG_LEN])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL)
    {
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(g_zero_nonce), NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, g_zero_nonce) == 1 &&
        (aad_len == 0 || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        (pt_len == 0 || EVP_EncryptUpdate(ctx, out_ct, &len, pt, (int)pt_len) == 1) &&
        EVP_EncryptFinal_ex(ctx, out_ct + pt_len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BM_PQV5_AEAD_TAG_LEN, out_tag) == 1)
    {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int aead_open(const unsigned char key[32], const unsigned char *aad, size_t aad_len,
                      const unsigned char *ct, size_t ct_len,
                      const unsigned char tag[BM_PQV5_AEAD_TAG_LEN], unsigned char *out_pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL)
    {
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(g_zero_nonce), NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, g_zero_nonce) == 1 &&
        (aad_len == 0 || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        (ct_len == 0 || EVP_DecryptUpdate(ctx, out_pt, &len, ct, (int)ct_len) == 1) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, BM_PQV5_AEAD_TAG_LEN,
                            (void *)(uintptr_t)tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, out_pt + ct_len, &len) == 1)
    {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int bm_pqv5_seal(const unsigned char recipient_pk[BM_PQV5_KEM_PK_LEN],
                  const unsigned char *aad, size_t aad_len,
                  const unsigned char *pt, size_t pt_len,
                  unsigned char *out, size_t *out_len)
{
    unsigned char key[32];
    int rc = -1;

    if (xwing_encaps(recipient_pk, out, key) == 0 &&
        aead_seal(key, aad, aad_len, pt, pt_len,
                  out + BM_PQV5_KEM_CT_LEN, out + BM_PQV5_KEM_CT_LEN + pt_len) == 0)
    {
        *out_len = BM_PQV5_SEAL_OVERHEAD + pt_len;
        rc = 0;
    }
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

int bm_pqv5_open(const unsigned char sk[BM_PQV5_KEM_SK_LEN],
                  const unsigned char *aad, size_t aad_len,
                  const unsigned char *in, size_t in_len,
                  unsigned char *out, size_t *out_len)
{
    unsigned char key[32];
    size_t ct_len;
    int rc = -1;

    if (in_len < BM_PQV5_SEAL_OVERHEAD)
    {
        return -1;
    }
    ct_len = in_len - BM_PQV5_SEAL_OVERHEAD;

    /* ML-KEMのDecapsはimplicit rejectionのため常に「成功」する(pq_crypto.c参照)。
     * 自分宛てでない封緘はここではなくAEADタグの検証で落ちる */
    if (xwing_decaps(sk, in, key) == 0 &&
        aead_open(key, aad, aad_len, in + BM_PQV5_KEM_CT_LEN, ct_len,
                  in + BM_PQV5_KEM_CT_LEN + ct_len, out) == 0)
    {
        *out_len = ct_len;
        rc = 0;
    }
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}
