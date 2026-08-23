/*
 * §11 2026-08-23発覚のバグの回帰テスト。bm_network_format_host_port自体はIPv6の
 * bracket化(§11 IPv6ログ修正)を正しく行うが、呼び出し側(peer_connector.c等)が
 * v3 onionアドレス(56文字+".onion"=62文字)を渡すことを想定しておらず、出力バッファが
 * 64byteだったためport部分が無言で切り捨てられていた(実daemonのログで
 * "connecting to xxxxx.onion: (via SOCKS5)..."とportが空になって発覚)。
 * ここでは関数自体が十分なバッファを渡された時に正しく動くこと、
 * 呼び出し側が実際に使っているバッファサイズ(80byte)でonionアドレス+portが
 * 切り捨てられずに収まることを確認する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/infra/network.h"

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
    /* --- 1. IPv4/ホスト名(':'を含まない)はそのまま"host:port" --- */
    {
        char out[80];
        bm_network_format_host_port("203.0.113.42", 8444, out, sizeof(out));
        CHECK(strcmp(out, "203.0.113.42:8444") == 0, "IPv4 should format as host:port without brackets");
    }

    /* --- 2. IPv6(':'を含む)は"[host]:port" --- */
    {
        char out[80];
        bm_network_format_host_port("2604:8b40:f9:0:1::", 8444, out, sizeof(out));
        CHECK(strcmp(out, "[2604:8b40:f9:0:1::]:8444") == 0, "IPv6 should be bracketed");
    }

    /* --- 3. v3 onionアドレス(56文字+".onion"=62文字)。呼び出し側が実際に使っている
     * 80byteバッファで、末尾のportまで一切切り捨てられずに収まることを確認する
     * (以前は64byteバッファで切り捨てられ、ログのport部分が空になっていた) --- */
    {
        const char *onion = "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion";
        CHECK(strlen(onion) == 62, "sanity check: v3 onion address string should be 62 chars");

        char out[80]; /* peer_connector.c等が実際に使っているサイズ */
        bm_network_format_host_port(onion, 8444, out, sizeof(out));

        char expected[80];
        snprintf(expected, sizeof(expected), "%s:8444", onion);
        CHECK(strcmp(out, expected) == 0,
              "a full-length v3 onion address + port should not be truncated in an 80-byte buffer");
        CHECK(strstr(out, ":8444") != NULL, "the port digits must survive, not be truncated at the colon");
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
