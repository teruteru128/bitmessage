#include "tor_control.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "../common/logging.h"
#include "network.h"

#define BM_TOR_CONTROL_TIMEOUT_SEC 10
#define BM_TOR_CONTROL_MAX_LINES 16
#define BM_TOR_CONTROL_LINE_CAP 512

/*
 * AF_UNIXソケットへ接続する。ローカルソケットのため接続は即座に成否が決まる想定で、
 * connect_tcp_with_timeoutのような非blocking+selectのタイムアウト機構は使わない
 * (peer_connector.cのTCP版と違い、相手がリモートで無応答というケースを考慮する必要がない)。
 * 成功時fd、失敗時-1
 */
static int connect_unix(const char *path)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        return -1;
    }
    return sock;
}

/*
 * peer_connector.cのconnect_with_timeoutと同じ非blocking+selectパターン。ただしこのモジュールは
 * 確立後ブロッキングI/O+SO_RCVTIMEO/SNDTIMEOで完結させるため、接続成功後はblockingモードへ
 * 戻す(peer_connector.c側はepollへ渡すためO_NONBLOCKのままにする、という違いがある)。
 */
static int connect_tcp_with_timeout(const char *host, int port, int timeout_sec)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
    {
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0)
        {
            continue;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(sock, p->ai_addr, p->ai_addrlen);
        if (rc == 0)
        {
            fcntl(sock, F_SETFL, flags);
            break;
        }
        if (errno != EINPROGRESS)
        {
            close(sock);
            sock = -1;
            continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        rc = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0)
        {
            close(sock);
            sock = -1;
            continue;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0)
        {
            close(sock);
            sock = -1;
            continue;
        }
        fcntl(sock, F_SETFL, flags);
        break;
    }

    freeaddrinfo(res);
    return sock;
}

static void set_control_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = BM_TOR_CONTROL_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int send_all_blocking(int fd, const char *data, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = write(fd, data + sent, len - sent);
        if (n <= 0)
        {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * fdから1行(CRLF区切り)ずつ読み出す。呼び出しをまたいでバッファ/offsetを保持することで、
 * 1回のread()に複数行が含まれていても取りこぼさない(tests/test_inbound.cのmsg_readerと
 * 同じ考え方。ただしこちらは1コマンド分の応答を読み切ったら次のコマンド送信までTorから
 * データが来ないプロトコルなので、呼び出し元をまたいでline_readerを使い回す必要はない)。
 */
struct line_reader
{
    int fd;
    char buf[4096];
    size_t len;
    size_t start;
};

static int line_reader_next(struct line_reader *r, char *out_line, size_t out_cap)
{
    for (;;)
    {
        for (size_t i = r->start; i + 1 < r->len; i++)
        {
            if (r->buf[i] == '\r' && r->buf[i + 1] == '\n')
            {
                size_t line_len = i - r->start;
                if (line_len >= out_cap)
                {
                    line_len = out_cap - 1;
                }
                memcpy(out_line, r->buf + r->start, line_len);
                out_line[line_len] = '\0';
                r->start = i + 2;
                return 0;
            }
        }
        if (r->start > 0)
        {
            memmove(r->buf, r->buf + r->start, r->len - r->start);
            r->len -= r->start;
            r->start = 0;
        }
        if (r->len >= sizeof(r->buf))
        {
            return -1;
        }
        ssize_t n = read(r->fd, r->buf + r->len, sizeof(r->buf) - r->len);
        if (n <= 0)
        {
            return -1;
        }
        r->len += (size_t)n;
    }
}

struct reply_line
{
    int code;
    char sep;
    char text[BM_TOR_CONTROL_LINE_CAP];
};

static int parse_reply_line(const char *raw, struct reply_line *out)
{
    if (strlen(raw) < 4 || !isdigit((unsigned char)raw[0]) || !isdigit((unsigned char)raw[1])
        || !isdigit((unsigned char)raw[2]))
    {
        return -1;
    }
    char code_str[4] = {raw[0], raw[1], raw[2], '\0'};
    out->code = atoi(code_str);
    out->sep = raw[3];
    strncpy(out->text, raw + 4, sizeof(out->text) - 1);
    out->text[sizeof(out->text) - 1] = '\0';
    return 0;
}

/*
 * 1つのコマンドへの応答(複数行の可能性あり)を最後まで読み切る。data block("+"区切り、
 * ".\r\n"終端)を返すコマンドはPROTOCOLINFO/AUTHENTICATE/ADD_ONIONのいずれも使わないため
 * 対応しない(万一遭遇したら誤読み進めより安全側に倒してエラーにする)。
 */
static int read_full_reply(struct line_reader *lr, struct reply_line *lines, size_t max_lines, size_t *out_count)
{
    size_t count = 0;
    for (;;)
    {
        if (count >= max_lines)
        {
            bm_log_error("[tor_control] reply has too many lines (>%zu)\n", max_lines);
            return -1;
        }
        char raw[BM_TOR_CONTROL_LINE_CAP];
        if (line_reader_next(lr, raw, sizeof(raw)) != 0)
        {
            bm_log_error("[tor_control] connection closed/timed out while reading reply\n");
            return -1;
        }
        if (parse_reply_line(raw, &lines[count]) != 0)
        {
            bm_log_error("[tor_control] malformed reply line: %s\n", raw);
            return -1;
        }
        if (lines[count].sep == '+')
        {
            bm_log_error("[tor_control] unsupported data-block reply (sep='+'): %s\n", raw);
            return -1;
        }
        int final_line = (lines[count].sep == ' ');
        count++;
        if (final_line)
        {
            break;
        }
    }
    *out_count = count;
    return 0;
}

static const struct reply_line *find_line_with_prefix(const struct reply_line *lines, size_t count,
                                                        const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    for (size_t i = 0; i < count; i++)
    {
        if (strncmp(lines[i].text, prefix, prefix_len) == 0)
        {
            return &lines[i];
        }
    }
    return NULL;
}

static int hex_encode(const unsigned char *data, size_t len, char *out, size_t out_cap)
{
    if (out_cap < len * 2 + 1)
    {
        return -1;
    }
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[i * 2] = hex_digits[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex_digits[data[i] & 0xf];
    }
    out[len * 2] = '\0';
    return 0;
}

/* PROTOCOLINFOの"AUTH METHODS=... COOKIEFILE=\"...\""行からCOOKIEFILEのパスを抜き出す。
 * 成功時0、見つからなければ-1 */
static int extract_cookie_file(const char *auth_line_text, char *out_path, size_t out_cap)
{
    const char *marker = "COOKIEFILE=\"";
    const char *start = strstr(auth_line_text, marker);
    if (start == NULL)
    {
        return -1;
    }
    start += strlen(marker);
    const char *end = strchr(start, '"');
    if (end == NULL)
    {
        return -1;
    }
    size_t path_len = (size_t)(end - start);
    if (path_len >= out_cap)
    {
        return -1;
    }
    memcpy(out_path, start, path_len);
    out_path[path_len] = '\0';
    return 0;
}

/* "METHODS=COOKIE,SAFECOOKIE COOKIEFILE=..."からMETHODS値だけを見てCOOKIE系認証に
 * 対応しているか判定する(COOKIE/SAFECOOKIEのどちらでもCookie自体は同じファイルなので、
 * ヘッダのコメント通りSAFECOOKIEのHMACチャレンジは行わずCOOKIEと同じ平文送信で済ませる) */
static int auth_methods_support_cookie(const char *auth_line_text)
{
    const char *marker = "METHODS=";
    const char *start = strstr(auth_line_text, marker);
    if (start == NULL)
    {
        return 0;
    }
    start += strlen(marker);
    const char *end = strchr(start, ' ');
    size_t methods_len = (end != NULL) ? (size_t)(end - start) : strlen(start);
    if (methods_len >= 128)
    {
        methods_len = 127;
    }
    char methods[128];
    memcpy(methods, start, methods_len);
    methods[methods_len] = '\0';
    return strstr(methods, "COOKIE") != NULL;
}

int bm_tor_control_connect_and_authenticate(const struct bm_tor_control_config *config)
{
    int fd = -1;
    if (config->control_socket_path != NULL)
    {
        fd = connect_unix(config->control_socket_path);
        if (fd < 0)
        {
            bm_log_warn("[tor_control] failed to connect to unix socket %s, falling back to TCP\n",
                    config->control_socket_path);
        }
    }
    if (fd < 0)
    {
        if (config->control_host == NULL)
        {
            bm_log_error(
                    "[tor_control] no reachable ControlPort (unix socket failed, no TCP fallback configured)\n");
            return -1;
        }
        fd = connect_tcp_with_timeout(config->control_host, config->control_port, BM_TOR_CONTROL_TIMEOUT_SEC);
        if (fd < 0)
        {
            char addr_buf[80];
            bm_network_format_host_port(config->control_host, config->control_port, addr_buf, sizeof(addr_buf));
            bm_log_error(
                    "[tor_control] failed to connect to ControlPort %s (is Tor running with ControlPort "
                    "enabled?)\n",
                    addr_buf);
            return -1;
        }
    }
    set_control_timeouts(fd);

    struct line_reader lr;
    memset(&lr, 0, sizeof(lr));
    lr.fd = fd;

    static const char protocolinfo_cmd[] = "PROTOCOLINFO 1\r\n";
    if (send_all_blocking(fd, protocolinfo_cmd, sizeof(protocolinfo_cmd) - 1) != 0)
    {
        bm_log_error("[tor_control] failed to send PROTOCOLINFO\n");
        close(fd);
        return -1;
    }

    struct reply_line lines[BM_TOR_CONTROL_MAX_LINES];
    size_t line_count = 0;
    if (read_full_reply(&lr, lines, BM_TOR_CONTROL_MAX_LINES, &line_count) != 0)
    {
        close(fd);
        return -1;
    }
    if (lines[line_count - 1].code != 250)
    {
        bm_log_error("[tor_control] PROTOCOLINFO failed: %d%c%s\n", lines[line_count - 1].code,
                lines[line_count - 1].sep, lines[line_count - 1].text);
        close(fd);
        return -1;
    }

    const struct reply_line *auth_line = find_line_with_prefix(lines, line_count, "AUTH ");
    if (auth_line == NULL)
    {
        bm_log_error("[tor_control] PROTOCOLINFO reply had no AUTH line\n");
        close(fd);
        return -1;
    }

    if (!auth_methods_support_cookie(auth_line->text))
    {
        bm_log_error(
                "[tor_control] ControlPort requires HASHEDPASSWORD authentication, which is not supported "
                "(cookie auth only). AUTH line: %s\n",
                auth_line->text);
        close(fd);
        return -1;
    }

    char cookie_path[512];
    if (extract_cookie_file(auth_line->text, cookie_path, sizeof(cookie_path)) != 0)
    {
        bm_log_error("[tor_control] could not find COOKIEFILE in AUTH line: %s\n", auth_line->text);
        close(fd);
        return -1;
    }

    FILE *cookie_fp = fopen(cookie_path, "rb");
    if (cookie_fp == NULL)
    {
        bm_log_error(
                "[tor_control] failed to open cookie file %s (permission denied? this user may need to be "
                "added to Tor's control group)\n",
                cookie_path);
        close(fd);
        return -1;
    }
    unsigned char cookie[64];
    size_t cookie_len = fread(cookie, 1, sizeof(cookie), cookie_fp);
    fclose(cookie_fp);
    if (cookie_len == 0)
    {
        bm_log_error("[tor_control] cookie file %s is empty\n", cookie_path);
        close(fd);
        return -1;
    }

    char cookie_hex[sizeof(cookie) * 2 + 1];
    hex_encode(cookie, cookie_len, cookie_hex, sizeof(cookie_hex));

    char auth_cmd[16 + sizeof(cookie_hex) + 4];
    int auth_cmd_len = snprintf(auth_cmd, sizeof(auth_cmd), "AUTHENTICATE %s\r\n", cookie_hex);
    if (send_all_blocking(fd, auth_cmd, (size_t)auth_cmd_len) != 0)
    {
        bm_log_error("[tor_control] failed to send AUTHENTICATE\n");
        close(fd);
        return -1;
    }

    if (read_full_reply(&lr, lines, BM_TOR_CONTROL_MAX_LINES, &line_count) != 0)
    {
        close(fd);
        return -1;
    }
    if (lines[line_count - 1].code != 250)
    {
        bm_log_error("[tor_control] AUTHENTICATE failed: %d%c%s\n", lines[line_count - 1].code,
                lines[line_count - 1].sep, lines[line_count - 1].text);
        close(fd);
        return -1;
    }

    return fd;
}

int bm_tor_control_add_onion(int fd, const char *existing_private_key, int virtual_port, int local_port,
                              char **out_onion_address, char **out_private_key)
{
    char cmd[512];
    int written = snprintf(cmd, sizeof(cmd), "ADD_ONION %s Port=%d,127.0.0.1:%d\r\n",
                            existing_private_key != NULL ? existing_private_key : "NEW:ED25519-V3", virtual_port,
                            local_port);
    if (written < 0 || (size_t)written >= sizeof(cmd))
    {
        bm_log_error("[tor_control] ADD_ONION command too long\n");
        return -1;
    }

    if (send_all_blocking(fd, cmd, (size_t)written) != 0)
    {
        bm_log_error("[tor_control] failed to send ADD_ONION\n");
        return -1;
    }

    struct line_reader lr;
    memset(&lr, 0, sizeof(lr));
    lr.fd = fd;

    struct reply_line lines[BM_TOR_CONTROL_MAX_LINES];
    size_t line_count = 0;
    if (read_full_reply(&lr, lines, BM_TOR_CONTROL_MAX_LINES, &line_count) != 0)
    {
        return -1;
    }
    if (lines[line_count - 1].code != 250)
    {
        bm_log_error("[tor_control] ADD_ONION failed: %d%c%s\n", lines[line_count - 1].code,
                lines[line_count - 1].sep, lines[line_count - 1].text);
        return -1;
    }

    const struct reply_line *service_id_line = find_line_with_prefix(lines, line_count, "ServiceID=");
    if (service_id_line == NULL)
    {
        bm_log_error("[tor_control] ADD_ONION reply had no ServiceID line\n");
        return -1;
    }
    const char *service_id = service_id_line->text + strlen("ServiceID=");

    size_t onion_address_len = strlen(service_id) + strlen(".onion") + 1;
    char *onion_address = malloc(onion_address_len);
    if (onion_address == NULL)
    {
        return -1;
    }
    snprintf(onion_address, onion_address_len, "%s.onion", service_id);

    char *private_key_out = NULL;
    if (existing_private_key == NULL)
    {
        const struct reply_line *pk_line = find_line_with_prefix(lines, line_count, "PrivateKey=");
        if (pk_line == NULL)
        {
            bm_log_error("[tor_control] ADD_ONION with a new key did not return a PrivateKey line\n");
            free(onion_address);
            return -1;
        }
        const char *pk_value = pk_line->text + strlen("PrivateKey=");
        private_key_out = malloc(strlen(pk_value) + 1);
        if (private_key_out == NULL)
        {
            free(onion_address);
            return -1;
        }
        memcpy(private_key_out, pk_value, strlen(pk_value) + 1);
    }

    *out_onion_address = onion_address;
    if (existing_private_key == NULL)
    {
        *out_private_key = private_key_out;
    }
    return 0;
}
