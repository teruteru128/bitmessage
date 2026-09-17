#ifndef BM_PQ_ADDRESS_V5_H
#define BM_PQ_ADDRESS_V5_H

/*
 * v5(ポスト量子)アドレスの生成・エンコード・デコード。DESIGN-PQ.md §4。
 *
 * 既存のv2〜v4アドレス(core/address.c)との違い:
 *   - identifierがRIPEMD160(SHA512(...))の20byteではなくSHA3-256の32byte
 *     (理由はDESIGN-PQ.md §4.1。20byteだと衝突計算量が2^80で、ML-DSA-65/ML-KEM-768に
 *      対して明らかに弱い環になる)
 * 変えていない点(2026-09-18のユーザー判断で、当初入れていた差異を取り下げた):
 *   - idは「公開鍵だけのハッシュ」。version/streamを混ぜない。混ぜるとv3/v4のripeが
 *     持っていた「同じ鍵を別version/別streamでも表現できる」性質を潰すうえ、
 *     version/streamの束縛はtagと署名対象のヘッダが既に担っており冗長だった
 *   - ドメイン分離ラベルを付けない(パスフレーズからのseed導出だけは付ける)
 *   - id先頭に0x00を1byte要求する探索ループ(v4と同じ既定)
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
 * §11 2026-09-18 探索(id先頭0x00)で引き直す鍵。
 *
 * 決定性生成とランダム生成で作法が違うが、これはv4(PyBitmessage
 * class_addressGenerator.py)も同じ:
 *
 *   決定性: 署名鍵nonce(偶数側)とKEM鍵nonce(奇数側)を持ち、**KEM鍵側だけ**を
 *           2ずつ進めて引き直す。KEM鍵はX-Wing仕様通り32byteのseed 1本から
 *           ML-KEMとX25519の両方を導出する(seedを分解しない)。
 *           実測0.169 ms/候補 → 期待43ms(§8.2)。
 *           ちなみにv4の決定性生成は両方のnonceを進めていたが、片方で十分。
 *   ランダム: 署名鍵とML-KEM鍵は最初に1回だけ引き、**X25519鍵だけ**を毎回引き直す。
 *           乱数から作る以上seedの圧縮表現を保つ必要が無く、一番安い成分だけを
 *           回せる。実測0.092 ms/候補 → 期待23ms。
 *           v4のランダム生成も署名鍵を固定して暗号化鍵だけを引き直している。
 *
 * どちらの経路でもidは「4つの公開鍵のハッシュ」なので一様にばらつき、
 * 暗号学的な差は無い。
 */

/*
 * パスフレーズからのseed導出だけに付けるドメイン分離ラベル。
 * id・tag・署名にはラベルを付けない(v4と同じ形)。ここだけ残すのは、ユーザーが
 * 同じパスフレーズを他のシステムでも使う現実があり、v4の
 * SHA512(passphrase||varint(nonce))と構造が同型だからである(コストはゼロ)。
 */
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
    /* 決定性生成時の鍵nonce(ランダム生成時は0)。パスフレーズとこの2つがあれば
     * アドレスを完全に再現できる(v4のstruct bm_generated_addressと同じ役割) */
    uint64_t sig_nonce;
    uint64_t kem_nonce;
};

/* id = SHA3-256(sig_pk || kem_pk)。v3/v4のripeと同じく公開鍵だけのハッシュ */
void bm_pqv5_calc_id(const unsigned char sig_pk[BM_PQV5_SIG_PK_LEN],
                      const unsigned char kem_pk[BM_PQV5_KEM_PK_LEN],
                      unsigned char out_id[BM_PQV5_ID_LEN]);

/*
 * SHA3-512(varint(version) || varint(stream) || id) を
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

/*
 * CSPRNGから新規identityを作る。X25519鍵だけを引き直して探索する(上記の説明参照)。
 * 生成されるKEM秘密鍵はX-Wingの32byte seed表現を持たない(ML-KEM鍵とX25519鍵が
 * 独立な乱数由来になるため)が、鍵ブロブとしては決定性生成のものと同じ形。成功時0。
 */
int bm_pqv5_identity_generate_random(uint64_t stream, int null_bytes,
                                      struct bm_pqv5_identity *out);

/*
 * パスフレーズ由来の決定性生成(v4と同じ2 nonce構成)。
 *   seed(n) = SHA3-512(BM_PQV5_LABEL_DETERMINISTIC || 0x00 || passphrase || varint(n))[0:32]
 * 署名鍵はstart_nonce(偶数側)で固定し、KEM鍵のnonce(start_nonce+1、奇数側)を
 * 2ずつ進めてidの先頭null_bytesバイトが0x00になるまで探索する
 * (null_bytes=0なら探索なし)。成功時0。
 */
int bm_pqv5_identity_generate_deterministic(const char *passphrase, uint64_t stream,
                                             uint64_t start_nonce, int null_bytes,
                                             struct bm_pqv5_identity *out);

/*
 * §11 2026-09-18 同じパスフレーズから2本目以降のアドレスを作るときの start_nonce。
 *
 * **素朴に 0, 2, 4, ... と渡してはいけない。** 探索はKEM鍵nonceを2ずつ進めるので、
 * 1本目が nonce 1,3,5,... を消費した後に2本目を start_nonce=2(=KEM nonce 3から)で
 * 始めると、**別のアドレスが同じKEM鍵を持ちうる**。
 *
 * 本家PyBitmessageは signingKeyNonce/encryptionKeyNonce をアドレス生成ループの外で
 * 初期化し、複数アドレスを作る間ずっと進め続けることでこれを避けている
 * (class_addressGenerator.py l.240-241 が l.246 のforループの外にある)。
 * こちらはstart_nonceを呼び出し側が渡すAPIなので、同じ規律をこの関数で表現する。
 */
uint64_t bm_pqv5_next_start_nonce(const struct bm_pqv5_identity *previous);

#endif /* BM_PQ_ADDRESS_V5_H */
