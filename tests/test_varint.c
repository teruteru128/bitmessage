/*
 * §11 2026-08-23発覚のバグ(0xfd/0xfe/0xff以降の多バイト部分がリトルエンディアンに
 * なっていた)の回帰テスト。PyBitmessageのaddresses.py encodeVarint/decodeVarintが
 * pack('>H'/'>I'/'>Q', ...)を使っている(ビッグエンディアン)ことを踏まえ、実際の
 * ワイヤーバイト列で固定の期待値と照合する。8444(Bitmessageの既定port)は必ず3byte
 * (0xfd)形式になるため、実際にpeers.dbが壊れて発覚した際の値そのものを使う。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/varint.h"

static int failures = 0;

#define CHECK(cond, msg)                                                    \
    do                                                                      \
    {                                                                       \
        if (!(cond))                                                        \
        {                                                                   \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

int main(void)
{
    /* --- 1. 8444(Bitmessageの既定port)は0xfd 0x20 0xfcというビッグエンディアンの
     * 3byte形式でエンコードされるべき。実際にこの値がリトルエンディアンで壊れて
     * peers.dbへ64544(0xfc20)として登録される形でバグが発覚した --- */
    {
        unsigned char out[9];
        size_t n = bm_varint_encode(out, 8444) - out; /* ポインタ差分で書き込みサイズを見る */
        (void)n;
        unsigned char expected[3] = {0xfd, 0x20, 0xfc};
        CHECK(bm_varint_size(8444) == 3, "varint_size(8444) should be 3");
        CHECK(memcmp(out, expected, 3) == 0, "encode(8444) should be big-endian 0xfd 0x20 0xfc");

        uint64_t decoded = 0;
        size_t consumed = bm_varint_decode(expected, sizeof(expected), &decoded);
        CHECK(consumed == 3, "decode of 0xfd 0x20 0xfc should consume 3 bytes");
        CHECK(decoded == 8444, "decode of 0xfd 0x20 0xfc should be 8444, not the byte-swapped 64544");
    }

    /* --- 2. 1byte境界(0〜252はそのまま1byte) --- */
    {
        unsigned char out[9];
        CHECK(bm_varint_size(0) == 1, "varint_size(0) == 1");
        CHECK(bm_varint_size(252) == 1, "varint_size(252) == 1");
        bm_varint_encode(out, 252);
        CHECK(out[0] == 252, "encode(252) should be a single byte 252");
    }

    /* --- 3. 4byte境界(0xfe、uint32のビッグエンディアン) --- */
    {
        unsigned char out[9];
        bm_varint_encode(out, 0x01020304ULL);
        unsigned char expected[5] = {0xfe, 0x01, 0x02, 0x03, 0x04};
        CHECK(memcmp(out, expected, 5) == 0, "encode(0x01020304) should be big-endian 0xfe 01 02 03 04");

        uint64_t decoded = 0;
        size_t consumed = bm_varint_decode(expected, sizeof(expected), &decoded);
        CHECK(consumed == 5, "decode of 0xfe form should consume 5 bytes");
        CHECK(decoded == 0x01020304ULL, "decode should recover 0x01020304");
    }

    /* --- 4. 8byte境界(0xff、uint64のビッグエンディアン) --- */
    {
        unsigned char out[9];
        uint64_t v = 0x0102030405060708ULL;
        bm_varint_encode(out, v);
        unsigned char expected[9] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        CHECK(memcmp(out, expected, 9) == 0, "encode(0x0102030405060708) should be big-endian");

        uint64_t decoded = 0;
        size_t consumed = bm_varint_decode(expected, sizeof(expected), &decoded);
        CHECK(consumed == 9, "decode of 0xff form should consume 9 bytes");
        CHECK(decoded == v, "decode should recover the original 8-byte value");
    }

    /* --- 5. 境界値でのround-trip(全サイズクラスを網羅) --- */
    {
        uint64_t values[] = {0, 1, 252, 253, 65535, 65536, 0xffffffffULL, 0x100000000ULL,
                              0xffffffffffffffffULL};
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        {
            unsigned char out[9];
            bm_varint_encode(out, values[i]);
            uint64_t decoded = 0;
            size_t consumed = bm_varint_decode(out, bm_varint_size(values[i]), &decoded);
            CHECK(consumed == bm_varint_size(values[i]), "round-trip consumed size should match varint_size");
            CHECK(decoded == values[i], "round-trip decode should recover the original value");
        }
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
