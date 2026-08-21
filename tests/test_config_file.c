/*
 * core/config_file.c のテスト。
 * - 存在しないパスを渡すと既定値のまま0を返すこと
 * - 実際のINIファイルを読み込み、各セクション/キーが正しく反映されること
 * - コメント(# と ;)・空行が無視されること
 * - 不明なキー/"="の無い行があっても残りの行の解析が継続すること(1行の誤りで
 *   全体を止めない設計、config_file.h参照)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/config_file.h"

#define TEST_CONFIG_PATH "test_config_file.conf"

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

static void write_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

int main(void)
{
    /* --- 1. 存在しないパス: 既定値のまま0を返す --- */
    unlink(TEST_CONFIG_PATH);
    {
        struct bm_config_file cfg;
        int found = bm_config_file_load(TEST_CONFIG_PATH, &cfg);
        CHECK(found == 0, "loading a nonexistent path should return 0");
        CHECK(cfg.testnet == 0, "default testnet should be 0");
        CHECK(cfg.no_connect == 0, "default no_connect should be 0");
        CHECK(cfg.api_port == 8442, "default api_port should be 8442");
        CHECK(cfg.inbound_port == 0, "default inbound_port should be 0 (disabled)");
        CHECK(cfg.tor_control == 0, "default tor_control should be 0");
        CHECK(strcmp(cfg.tor_control_socket, "/run/tor/control") == 0, "default tor_control_socket");
        CHECK(strcmp(cfg.tor_control_host, "127.0.0.1") == 0, "default tor_control_host");
        CHECK(cfg.tor_control_port == 9051, "default tor_control_port should be 9051");
        CHECK(cfg.tor_virtual_port == 8444, "default tor_virtual_port should be 8444");
        CHECK(cfg.onion_address[0] == '\0', "default onion_address should be empty");
    }

    /* --- 2. 実際のINIファイル: 全セクション/キーが反映されること。コメント・空行・
     * 前後の空白は無視されることも兼ねて確認する --- */
    write_file(TEST_CONFIG_PATH,
               "# this is a comment\n"
               "; this too\n"
               "\n"
               "[network]\n"
               "testnet = 1\n"
               "no_connect=1\n"
               "\n"
               "[api]\n"
               "  port = 9442  \n"
               "\n"
               "[inbound]\n"
               "port = 18444\n"
               "\n"
               "[tor]\n"
               "control = 1\n"
               "control_socket = /custom/control\n"
               "control_host = 10.0.0.1\n"
               "control_port = 19051\n"
               "virtual_port = 28444\n"
               "onion_address = f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion\n");
    {
        struct bm_config_file cfg;
        int found = bm_config_file_load(TEST_CONFIG_PATH, &cfg);
        CHECK(found == 1, "loading an existing path should return 1");
        CHECK(cfg.testnet == 1, "[network] testnet should be parsed");
        CHECK(cfg.no_connect == 1, "[network] no_connect should be parsed");
        CHECK(cfg.api_port == 9442, "[api] port should be parsed (surrounding whitespace trimmed)");
        CHECK(cfg.inbound_port == 18444, "[inbound] port should be parsed");
        CHECK(cfg.tor_control == 1, "[tor] control should be parsed");
        CHECK(strcmp(cfg.tor_control_socket, "/custom/control") == 0, "[tor] control_socket should be parsed");
        CHECK(strcmp(cfg.tor_control_host, "10.0.0.1") == 0, "[tor] control_host should be parsed");
        CHECK(cfg.tor_control_port == 19051, "[tor] control_port should be parsed");
        CHECK(cfg.tor_virtual_port == 28444, "[tor] virtual_port should be parsed");
        CHECK(strcmp(cfg.onion_address, "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion") == 0,
              "[tor] onion_address should be parsed");
    }

    /* --- 3. 不明なキー/セクション、"="の無い行があっても他の行の解析は継続すること --- */
    write_file(TEST_CONFIG_PATH,
               "[network]\n"
               "testnet = 1\n"
               "this line has no equals sign\n"
               "unknown_key = 123\n"
               "\n"
               "[unknown_section]\n"
               "whatever = 1\n"
               "\n"
               "[api]\n"
               "port = 7777\n");
    {
        struct bm_config_file cfg;
        int found = bm_config_file_load(TEST_CONFIG_PATH, &cfg);
        CHECK(found == 1, "loading should still succeed despite malformed/unknown lines");
        CHECK(cfg.testnet == 1, "valid key before a malformed line should still be parsed");
        CHECK(cfg.api_port == 7777, "valid key after malformed/unknown lines should still be parsed");
    }

    unlink(TEST_CONFIG_PATH);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
