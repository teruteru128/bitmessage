#ifndef BM_CORE_ADDRESS_H
#define BM_CORE_ADDRESS_H

/*
 * BMアドレスのエンコード・鍵導出・決定性アドレス生成。DESIGN.md §3.3。
 * 移植元: study/libstudy/src/bm_sonota.c(鍵導出・ripe計算はそのまま踏襲可能だったため移植)。
 * §3.5の規律に従い、OpenSSLの型(EC_KEY等)はこのヘッダに一切出さない。
 */

#include <stddef.h>
#include <stdint.h>

#define BM_PRIVATE_KEY_LEN 32
#define BM_PUBLIC_KEY_LEN 65 /* 0x04 || X(32byte) || Y(32byte)、ripe計算にはこの65byteのまま使う(§3.3) */
#define BM_RIPE_LEN 20

/* priv = SHA512(passphrase || encodeVarint(nonce))[0:32] */
void bm_address_derive_private_key(const char *passphrase, uint64_t nonce,
                                    unsigned char out_priv[BM_PRIVATE_KEY_LEN]);

/* secp256k1上でpriv*Gを計算する。成功時0 */
int bm_address_get_public_key(const unsigned char priv[BM_PRIVATE_KEY_LEN],
                               unsigned char out_pub[BM_PUBLIC_KEY_LEN]);

/* ripe = RIPEMD160(SHA512(sign_pub(65byte) || enc_pub(65byte))) */
void bm_address_calc_ripe(const unsigned char sign_pub[BM_PUBLIC_KEY_LEN],
                           const unsigned char enc_pub[BM_PUBLIC_KEY_LEN],
                           unsigned char out_ripe[BM_RIPE_LEN]);

/*
 * "BM-..."形式の文字列にエンコードする(malloc、呼び出し側でfree)。
 * version 2/3は先頭最大2byte、version 4は先頭0x00バイトを全て除去してから
 * エンコードする(§3.3のルール)。失敗時NULL。
 */
char *bm_address_encode(uint64_t version, uint64_t stream, const unsigned char *ripe, size_t ripe_len);

/* WIF(Wallet Import Format)文字列にエンコードする(malloc、呼び出し側でfree) */
char *bm_address_encode_wif(const unsigned char priv[BM_PRIVATE_KEY_LEN]);

/*
 * §11 2026-08-29 WIF文字列をデコードする(PyBitmessage highlevelcrypto.decodeWalletImportFormat
 * 準拠。0x80プレフィックス+32byte秘密鍵+4byteチェックサム(double SHA256)の計37byte構成のみを
 * 扱う。Bitmessageは圧縮公開鍵を使わないため、Bitcoin側にある圧縮鍵フラグ(末尾0x01、計38byte)
 * には対応しない)。成功時0、Base58デコード失敗・長さ不正・プレフィックス不一致・
 * チェックサム不一致は非0。
 */
int bm_address_decode_wif(const char *wif, unsigned char out_priv[BM_PRIVATE_KEY_LEN]);

/*
 * "BM-..."(先頭の"BM-"は省略可)をデコードする。addresses.py decodeAddress準拠:
 * checksum検証(double_sha512)、version範囲(1〜4)、ripe長の妥当性、v4の非マレアビリティ検証
 * (先頭0x00バイトが残っていたら不正な非正規エンコーディングとして拒否)を行う。
 * 成功時0、失敗時非0(out_versionにエラー種別は返さない、v1では成否のみ)。
 */
int bm_address_decode(const char *address, uint64_t *out_version, uint64_t *out_stream,
                       unsigned char out_ripe[BM_RIPE_LEN]);

/*
 * SHA512(varint(version)||varint(stream)||ripe)。前半32byteがpubkey v4/broadcastの
 * 暗号化鍵、後半32byteがtag(§3.3, §5.2, §5.4で共通利用)。out_secret/out_tagはNULL可。
 */
void bm_address_derive_secret_and_tag(uint64_t version, uint64_t stream, const unsigned char ripe[BM_RIPE_LEN],
                                       unsigned char out_secret[BM_PRIVATE_KEY_LEN],
                                       unsigned char out_tag[32]);

struct bm_generated_address
{
    unsigned char priv_signing[BM_PRIVATE_KEY_LEN];
    unsigned char priv_encryption[BM_PRIVATE_KEY_LEN];
    unsigned char pub_signing[BM_PUBLIC_KEY_LEN];
    unsigned char pub_encryption[BM_PUBLIC_KEY_LEN];
    unsigned char ripe[BM_RIPE_LEN];
    uint64_t signing_nonce;
    uint64_t encryption_nonce;
};

/*
 * パスフレーズから決定性アドレスの鍵一式を生成する(§3.3のnonce探索ループ)。
 * null_bytes: ripe先頭に要求する0x00バイト数(通常1、「もっと短いアドレス」指定時2)。
 * 成功時0。
 */
int bm_address_generate_deterministic(const char *passphrase, int null_bytes,
                                       struct bm_generated_address *out);

#endif /* BM_CORE_ADDRESS_H */
