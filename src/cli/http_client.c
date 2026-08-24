#include "http_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_to(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
    {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

char *bm_http_post_json(const char *host, int port, const char *username, const char *password,
                         const char *body, int *out_http_status)
{
    *out_http_status = 0;

    int fd = connect_to(host, port);
    if (fd < 0)
    {
        return NULL;
    }

    char auth_header[512] = "";
    if (username != NULL)
    {
        char credentials[256];
        snprintf(credentials, sizeof(credentials), "%s:%s", username, password != NULL ? password : "");
        unsigned char encoded[384];
        int enc_len = EVP_EncodeBlock(encoded, (const unsigned char *)credentials, (int)strlen(credentials));
        encoded[enc_len] = '\0';
        snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s\r\n", encoded);
    }

    /* セキュリティレビューで発覚: 以前は確保サイズの計算にhost(BM_API_HOST環境変数由来、
     * 長さ無制限)が含まれておらず、長いBM_API_HOSTを設定するとsprintf()がヒープ確保
     * 領域をはみ出して書き込むバッファオーバーフローになりえた。strlen(host)を
     * サイズ計算へ加え、sprintf()もsnprintf()へ置き換えて二重に安全側にした。 */
    size_t request_cap = strlen(host) + strlen(body) + strlen(auth_header) + 256;
    char *request = malloc(request_cap);
    int req_len = snprintf(request, request_cap,
                            "POST / HTTP/1.1\r\nHost: %s\r\n%sContent-Type: application/json\r\n"
                            "Content-Length: %zu\r\n\r\n%s",
                            host, auth_header, strlen(body), body);
    ssize_t written = write(fd, request, (size_t)req_len);
    free(request);
    if (written != req_len)
    {
        close(fd);
        return NULL;
    }

    size_t cap = 65536;
    size_t len = 0;
    char *resp = malloc(cap);
    for (;;)
    {
        if (len + 4096 > cap)
        {
            cap *= 2;
            resp = realloc(resp, cap);
        }
        ssize_t n = read(fd, resp + len, cap - len - 1);
        if (n <= 0)
        {
            break;
        }
        len += (size_t)n;
    }
    resp[len] = '\0';
    close(fd);

    if (len < 12 || strncmp(resp, "HTTP/1.1 ", 9) != 0)
    {
        free(resp);
        return NULL;
    }
    *out_http_status = atoi(resp + 9);

    char *body_start = strstr(resp, "\r\n\r\n");
    if (body_start == NULL)
    {
        free(resp);
        return NULL;
    }
    body_start += 4;

    size_t body_len = strlen(body_start);
    char *result = malloc(body_len + 1);
    memcpy(result, body_start, body_len + 1);
    free(resp);
    return result;
}
