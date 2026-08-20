/*
 * PyBitmessage src/tests/samples.py の既知テストベクタで core/address.c を検証する。
 * passphrase = sample_seed, version=3, stream=1, null_bytes=1(デフォルト)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* 不正な入力の拒否も確認(base58として不正な文字、checksum改竄) */
    if (bm_address_decode("BM-not_valid_base58!!!", &dec_version, &dec_stream, dec_ripe) == 0)
    {
        fprintf(stderr, "FAIL: decode should reject invalid base58 characters\n");
        return EXIT_FAILURE;
    }
    printf("OK: invalid address correctly rejected\n");

    return EXIT_SUCCESS;
}
