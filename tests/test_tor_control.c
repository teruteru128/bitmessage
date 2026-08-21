/*
 * §11 inbound接続 Stage 2のテスト。実環境のTor ControlPortに接続できる場合のみ、実際に
 * ADD_ONIONを発行して動作を検証する。
 *
 * このマシンにはシステムのTorデーモン(Debian/Ubuntuパッケージの既定設定)が動いており、
 * 実行ユーザーがdebian-torグループに所属しているため、sudo無しでUnixドメインソケット
 * (/run/tor/control)経由のCookie認証が使える。ただしCI等の他環境ではTorが存在しない/
 * ControlPortに到達できないことが普通なので、接続自体に失敗した場合は「テスト対象の
 * 前提条件が無い」として即SKIP相当(EXIT_SUCCESS)で抜ける。
 *
 * bm_tor_control_add_onionは意図的にFlags=Detachを使わない設計にした(tor_control.h参照:
 * control接続を閉じるとhidden serviceも自動的に消える。実際にFlags=Detachで検証したところ
 * 次回起動時に"550 Onion address collision"で失敗することが分かったため)。そのためこの
 * テストも、鍵の再利用(=プロセス再起動を模した動作)を検証する際は「1回目の接続を閉じてから
 * 2回目の接続で同じ鍵を使う」という手順を踏む。DEL_ONION等の明示的な後片付けは不要
 * (プロセス終了=fd close で自動的に消えるため)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/infra/tor_control.h"

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

/* テスト用の適当なポート番号(実際にリッスンしている必要は無い。ADD_ONION自体の成否には
 * 影響しない。もし実際にこのonionへ接続を試みる相手がいれば繋がらないだけ) */
#define DUMMY_VIRTUAL_PORT 18444
#define DUMMY_LOCAL_PORT 18444

static int connect_and_auth(int *out_fd)
{
    struct bm_tor_control_config config;
    memset(&config, 0, sizeof(config));
    config.control_socket_path = "/run/tor/control";
    config.control_host = "127.0.0.1";
    config.control_port = 9051;

    *out_fd = bm_tor_control_connect_and_authenticate(&config);
    return *out_fd >= 0 ? 0 : -1;
}

int main(void)
{
    int fd1 = -1;
    if (connect_and_auth(&fd1) != 0)
    {
        fprintf(stderr, "SKIP: このマシンではTor ControlPortに接続できませんでした"
                         "(Torが動いていない/権限が無い環境と判断してテストをスキップします)\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "[test] 1回目のTor ControlPort接続・認証に成功しました\n");

    /* --- 1. 新規鍵でADD_ONION --- */
    char *onion_address1 = NULL;
    char *private_key = NULL;
    int rc = bm_tor_control_add_onion(fd1, NULL, DUMMY_VIRTUAL_PORT, DUMMY_LOCAL_PORT, &onion_address1,
                                       &private_key);
    CHECK(rc == 0, "bm_tor_control_add_onion(NEW) should succeed");

    if (rc == 0)
    {
        fprintf(stderr, "[test] onion_address=%s\n", onion_address1);
        CHECK(onion_address1 != NULL, "onion_address should be set");
        CHECK(private_key != NULL, "private_key should be set for a new key");
        if (onion_address1 != NULL)
        {
            size_t len = strlen(onion_address1);
            CHECK(len > strlen(".onion") && strcmp(onion_address1 + len - strlen(".onion"), ".onion") == 0,
                  "onion_address should end with .onion");
        }
        if (private_key != NULL)
        {
            CHECK(strncmp(private_key, "ED25519-V3:", strlen("ED25519-V3:")) == 0,
                  "private_key should be in ED25519-V3: format");
        }
    }

    /* --- 2. 接続を閉じる(Flags=Detachを使っていないため、これでhidden serviceも消える) --- */
    close(fd1);

    if (rc == 0 && private_key != NULL)
    {
        /* --- 3. 別の(新しい)control接続で同じ鍵を渡し、同一のonionアドレスが決定的に
         * 再現されることを確認する(デーモン再起動後も同じ鍵から同じアドレスを再現できる
         * ことの裏付け)。1回目の接続は既に閉じているので衝突しない --- */
        int fd2 = -1;
        CHECK(connect_and_auth(&fd2) == 0, "2回目のTor ControlPort接続に成功するはず");
        if (fd2 >= 0)
        {
            char *onion_address2 = NULL;
            char *private_key2 = NULL; /* 既存鍵を渡す場合は設定されないはず */
            int rc2 = bm_tor_control_add_onion(fd2, private_key, DUMMY_VIRTUAL_PORT, DUMMY_LOCAL_PORT,
                                                &onion_address2, &private_key2);
            CHECK(rc2 == 0, "bm_tor_control_add_onion(existing key, 別接続) should succeed");
            if (rc2 == 0)
            {
                CHECK(onion_address2 != NULL && strcmp(onion_address1, onion_address2) == 0,
                      "reusing the same private key should reproduce the same onion address");
                CHECK(private_key2 == NULL, "reusing an existing key should not return a new PrivateKey line");
            }
            free(onion_address2);
            free(private_key2);
            close(fd2); /* ここでも自動的にhidden serviceが消える。後片付け不要 */
        }
    }

    free(onion_address1);
    free(private_key);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
