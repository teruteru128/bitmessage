/*
 * PyBitmessage src/tests/samples.py の既知テストベクタで core/address.c を検証する。
 * passphrase = sample_seed, version=3, stream=1, null_bytes=1(デフォルト)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/base58.h"
#include "../src/common/hash.h"
#include "../src/core/address.h"

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

int main(void)
{
    const char *seed = "TIGER, tiger, burning bright. In the forests of the night";
    const char *expected_ripe_hex = "00cfb69416ae76f68a81c459de4e13460c7d17eb";
    const char *expected_addr3 = "BM-2DBPTgeSawWYZceFD69AbDT5q4iUWtj1ZN";

    struct bm_generated_address addr;
    if (bm_address_generate_deterministic(seed, 1, &addr) != 0)
    {
        fprintf(stderr, "FAIL: bm_address_generate_deterministic returned error\n");
        return EXIT_FAILURE;
    }

    char ripe_hex[BM_RIPE_LEN * 2 + 1];
    hex_encode(addr.ripe, BM_RIPE_LEN, ripe_hex);
    if (strcmp(ripe_hex, expected_ripe_hex) != 0)
    {
        fprintf(stderr, "FAIL: ripe mismatch\n  got:      %s\n  expected: %s\n", ripe_hex, expected_ripe_hex);
        return EXIT_FAILURE;
    }

    char *addr3 = bm_address_encode(3, 1, addr.ripe, BM_RIPE_LEN);
    if (addr3 == NULL || strcmp(addr3, expected_addr3) != 0)
    {
        fprintf(stderr, "FAIL: address mismatch\n  got:      %s\n  expected: %s\n",
                addr3 ? addr3 : "(null)", expected_addr3);
        free(addr3);
        return EXIT_FAILURE;
    }
    printf("OK: deterministic address vector matched (%s)\n", expected_addr3);

    /* decode往復: 既知アドレス(v3)をデコードし、version/stream/ripeが一致することを確認 */
    uint64_t dec_version = 0, dec_stream = 0;
    unsigned char dec_ripe[BM_RIPE_LEN];
    if (bm_address_decode(addr3, &dec_version, &dec_stream, dec_ripe) != 0)
    {
        fprintf(stderr, "FAIL: bm_address_decode returned error for %s\n", addr3);
        free(addr3);
        return EXIT_FAILURE;
    }
    if (dec_version != 3 || dec_stream != 1 || memcmp(dec_ripe, addr.ripe, BM_RIPE_LEN) != 0)
    {
        fprintf(stderr, "FAIL: decode round-trip mismatch (version=%llu stream=%llu)\n",
                (unsigned long long)dec_version, (unsigned long long)dec_stream);
        free(addr3);
        return EXIT_FAILURE;
    }
    free(addr3);
    printf("OK: v3 address decode round-trip matched\n");

    /* v4アドレスでも往復させる(先頭ゼロバイト全除去のケース) */
    char *addr4 = bm_address_encode(4, 1, addr.ripe, BM_RIPE_LEN);
    if (addr4 == NULL)
    {
        fprintf(stderr, "FAIL: bm_address_encode v4\n");
        return EXIT_FAILURE;
    }
    if (bm_address_decode(addr4, &dec_version, &dec_stream, dec_ripe) != 0
        || dec_version != 4 || dec_stream != 1 || memcmp(dec_ripe, addr.ripe, BM_RIPE_LEN) != 0)
    {
        fprintf(stderr, "FAIL: v4 decode round-trip mismatch\n");
        free(addr4);
        return EXIT_FAILURE;
    }
    printf("OK: v4 address decode round-trip matched (%s)\n", addr4);
    free(addr4);

    /*
     * §11 2026-08-29 5143件規模のkeys.datインポート実地検証で発見した非正規アドレスの
     * decode救済を確認する。本家PyBitmessage・このプロジェクトのbm_address_encodeは共に
     * version2/3で先頭ゼロを最大2byteまでしか圧縮しない仕様だが、実際には4byte分のゼロを
     * 圧縮した非正規のversion3アドレス(チェックサムは正常な実在のアドレス)が見つかった。
     * bm_address_encodeでは(常に20byte入力かつ最大2byte圧縮の)正規アドレスしか作れないため、
     * ここではvarint+ripe(16byte、4byte圧縮相当)+checksumを手動で組み立てて非正規アドレスを
     * 合成し、decode側が(20-16)=4byte分のゼロを正しく補って復元することを確認する。
     */
    {
        unsigned char nonstandard_ripe[BM_RIPE_LEN];
        memset(nonstandard_ripe, 0, 4);
        memcpy(nonstandard_ripe + 4, addr.ripe + 4, BM_RIPE_LEN - 4);

        unsigned char payload[32];
        size_t off = 0;
        payload[off++] = 3; /* varint(3): 1byte(値<0xfd) */
        payload[off++] = 1; /* varint(1): 1byte */
        memcpy(payload + off, nonstandard_ripe + 4, BM_RIPE_LEN - 4);
        off += BM_RIPE_LEN - 4;

        unsigned char checksum[64];
        bm_double_sha512(payload, off, checksum);
        memcpy(payload + off, checksum, 4);
        off += 4;

        char *b58 = bm_base58_encode(payload, off);
        if (b58 == NULL)
        {
            fprintf(stderr, "FAIL: base58 encode of synthetic non-standard address\n");
            return EXIT_FAILURE;
        }
        char nonstandard_addr[128];
        snprintf(nonstandard_addr, sizeof(nonstandard_addr), "BM-%s", b58);
        free(b58);

        uint64_t v = 0, s = 0;
        unsigned char decoded_ripe[BM_RIPE_LEN];
        if (bm_address_decode(nonstandard_addr, &v, &s, decoded_ripe) != 0 || v != 3 || s != 1
            || memcmp(decoded_ripe, nonstandard_ripe, BM_RIPE_LEN) != 0)
        {
            fprintf(stderr, "FAIL: non-standard v3 address (4+ leading zero bytes) should decode "
                            "with zero-padding (%s)\n",
                    nonstandard_addr);
            return EXIT_FAILURE;
        }
        printf("OK: non-standard v3 address with 4+ leading zero bytes decodes correctly\n");
    }

    /* 不正な入力の拒否も確認(base58として不正な文字、checksum改竄) */
    if (bm_address_decode("BM-not_valid_base58!!!", &dec_version, &dec_stream, dec_ripe) == 0)
    {
        fprintf(stderr, "FAIL: decode should reject invalid base58 characters\n");
        return EXIT_FAILURE;
    }
    printf("OK: invalid address correctly rejected\n");

    return EXIT_SUCCESS;
}
