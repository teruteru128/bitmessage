/*
 * src/cli/http_client.c(bm_http_post_json)のテスト。セキュリティレビューで気づいた
 * 点として、このファイルにはこれまで専用のユニットテストが一つも無く、
 * tests/test_cli_integration.sh経由(実際のbitmessagedへの接続)でしか間接的に
 * 経由されていなかった。ローカルにダミーのTCPサーバーを立て、実際のHTTPリクエストの
 * 組み立て・送信・レスポンス解析を直接検証する。
 *
 * あわせて、bm_http_post_json内部のリクエストバッファ確保サイズがhostの長さを
 * 考慮していなかった(malloc(strlen(body)+strlen(auth_header)+256)にhostが含まれて
 * いなかった)問題を修正した際の回帰確認も兼ねる。ただし実際にはconnect_to()の
 * inet_pton(AF_INET, host, ...)がhostを妥当なIPv4形式(15文字程度以内)に制限して
 * いるため、この経路自体は到達不能だった(念のため確認済み)。それでも確保サイズの
 * 計算にhostを含めておくのは堅牢性のため妥当な修正である。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/cli/http_client.h"

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

struct mock_server_args
{
    int listen_fd;
    /* 受信したリクエストの先頭部分(検証用、呼び出し側が用意したバッファへ書き込む) */
    char *captured_request;
    size_t captured_cap;
    const char *response_body;
};

static void *mock_server_thread(void *arg_ptr)
{
    struct mock_server_args *args = arg_ptr;
    int client_fd = accept(args->listen_fd, NULL, NULL);
    if (client_fd < 0)
    {
        return NULL;
    }

    ssize_t n = read(client_fd, args->captured_request, args->captured_cap - 1);
    if (n > 0)
    {
        args->captured_request[n] = '\0';
    }

    char response[512];
    int resp_len = snprintf(response, sizeof(response),
                             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                             strlen(args->response_body), args->response_body);
    ssize_t written = write(client_fd, response, (size_t)resp_len);
    (void)written;
    close(client_fd);
    return NULL;
}

/* ephemeralポートで127.0.0.1をlistenし、fdと実際に割り当てられたportを返す */
static int listen_ephemeral(int *out_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0; /* 0 = カーネルに空きportを割り当てさせる */
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 1) != 0)
    {
        close(fd);
        return -1;
    }
    socklen_t addr_len = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

int main(void)
{
    /* --- 1. 認証情報無し、正常系: リクエストが正しく組み立てられ、レスポンスボディ・
     * HTTPステータスが正しく解析されること --- */
    {
        int port = 0;
        int listen_fd = listen_ephemeral(&port);
        CHECK(listen_fd >= 0, "listen_ephemeral should succeed");
        if (listen_fd >= 0)
        {
            char captured[4096];
            struct mock_server_args args = {listen_fd, captured, sizeof(captured), "{\"result\":true}"};
            pthread_t server_thread;
            pthread_create(&server_thread, NULL, mock_server_thread, &args);

            int status = -1;
            char *resp = bm_http_post_json("127.0.0.1", port, NULL, NULL,
                                            "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}", &status);
            pthread_join(server_thread, NULL);
            close(listen_fd);

            CHECK(resp != NULL, "bm_http_post_json should return a response body");
            CHECK(status == 200, "HTTP status should be parsed as 200");
            if (resp != NULL)
            {
                CHECK(strcmp(resp, "{\"result\":true}") == 0, "response body should match exactly");
                free(resp);
            }
            CHECK(strstr(captured, "POST / HTTP/1.1\r\n") != NULL, "request line should be well-formed");
            CHECK(strstr(captured, "Host: 127.0.0.1\r\n") != NULL, "Host header should match the given host");
            CHECK(strstr(captured, "Authorization:") == NULL,
                  "no Authorization header should be sent when username is NULL");
            CHECK(strstr(captured, "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}") != NULL,
                  "request body should be sent intact");
        }
    }

    /* --- 2. Basic認証あり: Authorizationヘッダが付くこと(中身のbase64デコードまでは
     * 深追いせず、ヘッダ自体の有無だけ確認する。base64エンコード自体はOpenSSLの
     * EVP_EncodeBlockに委譲しており、ここでの検証対象ではない) --- */
    {
        int port = 0;
        int listen_fd = listen_ephemeral(&port);
        CHECK(listen_fd >= 0, "listen_ephemeral should succeed (auth scenario)");
        if (listen_fd >= 0)
        {
            char captured[4096];
            struct mock_server_args args = {listen_fd, captured, sizeof(captured), "{}"};
            pthread_t server_thread;
            pthread_create(&server_thread, NULL, mock_server_thread, &args);

            int status = -1;
            char *resp = bm_http_post_json("127.0.0.1", port, "bitmessage", "secretpass", "{}", &status);
            pthread_join(server_thread, NULL);
            close(listen_fd);

            free(resp);
            CHECK(strstr(captured, "Authorization: Basic ") != NULL,
                  "Authorization header should be present when username is non-NULL");
        }
    }

    /* --- 3. 接続失敗(listenしていないport): NULLを返し、*out_http_statusは0のまま。
     * listen_ephemeralで一度bindしてから即座にcloseしたportを使うことで、確実に
     * どこもlistenしていないportを安全に得る(固定のマジックナンバーに依存しない) --- */
    {
        int probe_port = 0;
        int probe_fd = listen_ephemeral(&probe_port);
        CHECK(probe_fd >= 0, "listen_ephemeral should succeed (probe for an unused port)");
        close(probe_fd);

        int status = 123; /* 書き換えられないことを確認するため、明らかに違う初期値にしておく */
        char *resp = bm_http_post_json("127.0.0.1", probe_port, NULL, NULL, "{}", &status);
        CHECK(resp == NULL, "connecting to an unreachable port should return NULL");
        CHECK(status == 0, "out_http_status should be reset to 0 even on connect failure");
        free(resp);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    printf("%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
