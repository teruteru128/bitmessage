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
    free(addr3);

    printf("OK: deterministic address vector matched (%s)\n", expected_addr3);
    return EXIT_SUCCESS;
}
