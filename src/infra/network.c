#include "network.h"

#include "peer_registry.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../common/logging.h"
#include "../core/peer_manager.h"

#define INIT_RECV_BUFFER_SIZE 131072
#define MAX_EPOLL_EVENTS 64

/* §11 DoS上限の見直し。受信バッファのdoubling自体にも上限を設ける(bm_parse_messageの
 * BM_MAX_MESSAGE_LENGTHチェックと二重の防御。複数メッセージがバッファ内に連続で溜まる
 * ケースも考慮し、単一メッセージの上限より少し余裕を持たせる)。 */
#define MAX_RECV_BUFFER_SIZE (2u * (BM_MESSAGE_HEADER_SIZE + BM_MAX_MESSAGE_LENGTH))

/* §11 2026-08-23: epoll_waitのタイムアウト(socket活動が無くても定期的に
 * bm_network_idle_sweepへ戻ってくるための間隔)。BM_HANDSHAKE_TIMEOUT_SECONDS/
 * BM_IDLE_PING_TIMEOUT_SECONDSはnetwork.hで公開(テストが実際の値で境界を検証できるように
 * するため)。 */
#define BM_IDLE_SWEEP_INTERVAL_MS 5000

/* §11 2026-08-23 backlog項目5: プロセス起動時からの送受信バイト数の全体累積
 * (network.hのbm_network_get_statsのdoc参照)。切断済み接続ぶんも失われず積み上がる、
 * dandelion.cのg_stateと同じくプロセス内シングルトン+mutex保護の方針。 */
static struct
{
    pthread_mutex_t lock;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} g_net_stats = {PTHREAD_MUTEX_INITIALIZER, 0, 0};

void bm_network_get_stats(uint64_t *out_bytes_sent, uint64_t *out_bytes_received)
{
    pthread_mutex_lock(&g_net_stats.lock);
    *out_bytes_sent = g_net_stats.bytes_sent;
    *out_bytes_received = g_net_stats.bytes_received;
    pthread_mutex_unlock(&g_net_stats.lock);
}

static void net_stats_add_sent(uint64_t n)
{
    pthread_mutex_lock(&g_net_stats.lock);
    g_net_stats.bytes_sent += n;
    pthread_mutex_unlock(&g_net_stats.lock);
}

static void net_stats_add_received(uint64_t n)
{
    pthread_mutex_lock(&g_net_stats.lock);
    g_net_stats.bytes_received += n;
    pthread_mutex_unlock(&g_net_stats.lock);
}

struct bm_fd_data *bm_fd_data_new(enum bm_fd_type type, int fd)
{
    struct bm_fd_data *data = calloc(1, sizeof(struct bm_fd_data));
    if (data == NULL)
    {
        return NULL;
    }
    data->type = type;
    data->fd = fd;
    data->size = INIT_RECV_BUFFER_SIZE;
    data->length = 0;
    data->last_activity = (int64_t)time(NULL);

    data->local_len = sizeof(data->local_addr);
    if (getsockname(fd, (struct sockaddr *)&data->local_addr, &data->local_len) == -1)
    {
        bm_log("getsockname: %s\n", strerror(errno));
        free(data);
        return NULL;
    }
    /* §11 listenソケット自体には相手(peer)が存在しないためgetpeername()は常に失敗する
     * (ENOTCONN)。BM_FD_LISTEN_SOCKETの場合はpeer_addrを空のまま(未使用)にしてスキップする */
    if (type != BM_FD_LISTEN_SOCKET)
    {
        data->peer_len = sizeof(data->peer_addr);
        if (getpeername(fd, (struct sockaddr *)&data->peer_addr, &data->peer_len) == -1)
        {
            bm_log("getpeername: %s\n", strerror(errno));
            free(data);
            return NULL;
        }
    }

    data->recv_buffer = malloc(INIT_RECV_BUFFER_SIZE);
    if (data->recv_buffer == NULL)
    {
        free(data);
        return NULL;
    }
    return data;
}

void bm_fd_data_free(struct bm_fd_data *data)
{
    if (data == NULL)
    {
        return;
    }
    free(data->recv_buffer);
    free(data->user_agent);
    free(data);
}

int bm_network_listen(const char *bind_address, int port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(bind_address, port_str, &hints, &res) != 0)
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
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (bind(sock, p->ai_addr, p->ai_addrlen) == 0 && listen(sock, 16) == 0)
        {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0)
    {
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    return sock;
}

int bm_network_write_all(int fd, const unsigned char *data, size_t len, int timeout_sec)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = write(fd, data + sent, len - sent);
        if (n > 0)
        {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0)
            {
                return -1; /* タイムアウトまたはselect()自体のエラー */
            }
            continue;
        }
        return -1; /* 相手が切断した(n==0)、またはその他のエラー */
    }
    net_stats_add_sent((uint64_t)len);
    return 0;
}

/* §11 2026-08-23 backlog項目5: connを取るようにした(以前はint fdのみ)。connの
 * bytes_sentへも積むため(network.hのdoc参照、broadcast_inv経由のdup()したfdのように
 * connを持たない書き込み経路は対象外だが、verack/pong/pingはいずれもconnを持っている)。 */
static int send_header_only(struct bm_fd_data *conn, const char *command)
{
    size_t len = 0;
    unsigned char *packet = bm_create_packet(command, NULL, 0, &len);
    int rc = bm_network_write_all(conn->fd, packet, len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS);
    if (rc == 0)
    {
        conn->bytes_sent += (uint64_t)len;
    }
    free(packet);
    return rc;
}

int bm_reply_verack(struct bm_fd_data *conn)
{
    return send_header_only(conn, "verack");
}

int bm_reply_pong(struct bm_fd_data *conn)
{
    return send_header_only(conn, "pong");
}

int bm_post_version(int sock, const char *user_agent_str, int version,
                     const struct sockaddr_storage *peer_addr,
                     const struct sockaddr_storage *local_addr)
{
    size_t len = 0;
    unsigned char *msg = bm_new_version_message(user_agent_str, version, peer_addr, local_addr, &len);
    int rc = bm_network_write_all(sock, msg, len, BM_NETWORK_WRITE_TIMEOUT_LONG_SECONDS);
    free(msg);
    return rc;
}

/* 既定のコマンドディスパッチ。DESIGN.md §1.1 command_worker_thread の初版実装。
 * object/getdataはTODO(§5, §9): infra/object.c 実装後にキュー経由へ差し替える。 */
static void default_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data)
{
    (void)user_data;
    char command[13] = {0};
    memcpy(command, msg->command, 12);

    if (strncmp(msg->command, "version", 12) == 0)
    {
        struct bm_version_message ver;
        bm_parse_version_message(msg->payload, msg->length, &ver);
        bm_log("[network] version: v=%u services=%" PRIu64 " ua=%s\n",
                ver.version, ver.services, ver.user_agent);
        bm_free_version_message(&ver);
        if (bm_reply_verack(conn) != 0)
        {
            bm_log("[network] failed to reply verack\n");
        }
    }
    else if (strncmp(msg->command, "verack", 12) == 0)
    {
        bm_log("[network] verack received\n");
    }
    else if (strncmp(msg->command, "ping", 12) == 0)
    {
        if (bm_reply_pong(conn) != 0)
        {
            bm_log("[network] failed to reply pong\n");
        }
    }
    else if (strncmp(msg->command, "addr", 12) == 0)
    {
        struct bm_addr_message addr_msg;
        if (bm_parse_addr_message(msg->payload, msg->length, &addr_msg) == 0)
        {
            bm_log("[network] addr: %" PRIu64 " entries (TODO: peer_manager未実装)\n", addr_msg.count);
            bm_free_addr_message(&addr_msg);
        }
    }
    else if (strncmp(msg->command, "inv", 12) == 0)
    {
        struct bm_inventory_message inv_msg;
        if (bm_parse_inventory_message(msg->payload, msg->length, &inv_msg) == 0)
        {
            bm_log("[network] inv: %" PRIu64 " items (TODO: object_store未実装、getdata未送信)\n", inv_msg.count);
            bm_free_inventory_message(&inv_msg);
        }
    }
    else if (strncmp(msg->command, "object", 12) == 0)
    {
        bm_log("[network] object received, %u bytes (TODO: object_store/decrypt_worker未実装)\n", msg->length);
    }
    else
    {
        bm_log("[network] unhandled command: %s\n", command);
    }
}

int bm_network_handle_readable(struct bm_fd_data *conn, bm_command_handler_fn handler, void *user_data)
{
    if (handler == NULL)
    {
        handler = default_dispatch;
    }

    unsigned char buf[INIT_RECV_BUFFER_SIZE];
    for (;;)
    {
        ssize_t n = read(conn->fd, buf, sizeof(buf));
        if (n == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            bm_log("[network] read (fd=%d): %s\n", conn->fd, strerror(errno));
            return -1;
        }
        if (n == 0)
        {
            return 1; /* peer closed */
        }
        /* §11 2026-08-23: アイドルタイムアウト判定用の最終活動時刻。読み取れた時点で更新する
         * (bm_network_idle_sweep参照)。 */
        conn->last_activity = (int64_t)time(NULL);
        /* §11 2026-08-23 backlog項目5: 受信バイト数(接続ごと・全体累積の両方)を、
         * 読み取りが成功した唯一の箇所であるここで一括更新する(network.hのdoc参照)。 */
        conn->bytes_received += (uint64_t)n;
        net_stats_add_received((uint64_t)n);
        if (conn->length + (size_t)n > conn->size)
        {
            size_t new_size = conn->size;
            while (conn->length + (size_t)n > new_size)
            {
                new_size *= 2;
            }
            if (new_size > MAX_RECV_BUFFER_SIZE)
            {
                /* §11 単一メッセージの上限(BM_MAX_MESSAGE_LENGTH)は通常bm_parse_messageの
                 * BM_PARSE_MESSAGE_TOO_LARGEで先に検知されるが、それより前にここへ到達する
                 * ケース(単一read()で大量データが一度に届く等)に備えた二重の防御 */
                bm_log("[network] recv buffer would exceed %u bytes, dropping connection\n",
                        MAX_RECV_BUFFER_SIZE);
                return -1;
            }
            unsigned char *grown = realloc(conn->recv_buffer, new_size);
            if (grown == NULL)
            {
                return -1;
            }
            conn->recv_buffer = grown;
            conn->size = new_size;
        }
        memcpy(conn->recv_buffer + conn->length, buf, (size_t)n);
        conn->length += (size_t)n;
    }

    for (;;)
    {
        struct bm_message *msg = NULL;
        size_t consumed = 0;
        enum bm_parse_result result = bm_parse_message(conn->recv_buffer, conn->length, &msg, &consumed);

        if (result == BM_PARSE_INCOMPLETE)
        {
            break;
        }
        if (result == BM_PARSE_BAD_CHECKSUM)
        {
            bm_log("[network] checksum mismatch, dropping %zu bytes\n", consumed);
            memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
            conn->length -= consumed;
            continue;
        }
        if (result == BM_PARSE_BAD_MAGIC)
        {
            /* mainnet/testnet取り違え等。1byteずつresyncを試みる(ログは出さない、
             * ノイズの多いストリームだと大量に出て邪魔になるため) */
            memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
            conn->length -= consumed;
            continue;
        }
        if (result == BM_PARSE_MESSAGE_TOO_LARGE)
        {
            /* §11 巨大なlengthを申告された。resyncを試みるコスト自体もDoSになりうるため、
             * 即座に接続を切断する(呼び出し元でclose・registry除去される) */
            bm_log("[network] declared message length exceeds %u bytes, dropping connection\n",
                    BM_MAX_MESSAGE_LENGTH);
            return -1;
        }

        /* BM_PARSE_OK */
        memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->length - consumed);
        conn->length -= consumed;
        handler(conn, msg, user_data);
        bm_free_message(msg);
        if (conn->should_disconnect)
        {
            /* §11 2026-08-23 backlog項目3: ハンドラが「この接続を切るべき」と判断した
             * (network.hのdoc参照)。必要なerrorメッセージ等の送信はハンドラ側で既に
             * 済ませている前提で、切断そのものは既存の読み取りエラー経路(呼び出し元の
             * rc!=0分岐→close_connection)へそのまま合流させる。 */
            return -1;
        }
    }

    return 0;
}

void bm_inbound_rate_limiter_init(struct bm_inbound_rate_limiter *rl)
{
    rl->window_start = 0;
    rl->count_in_window = 0;
}

int bm_inbound_rate_limiter_allow(struct bm_inbound_rate_limiter *rl, int64_t now)
{
    if (now - rl->window_start >= BM_INBOUND_ACCEPT_WINDOW_SECONDS)
    {
        rl->window_start = now;
        rl->count_in_window = 0;
    }
    rl->count_in_window++;
    return rl->count_in_window <= BM_INBOUND_ACCEPT_MAX_PER_WINDOW;
}

/*
 * §11 inbound接続(Tor hidden service)対応。listenソケットがreadable(=accept可能)に
 * なった際に呼ぶ。EAGAINになるまで(=溜まっている分を全部)accept()し、各接続を
 * BM_FD_SERVER_SOCKETとしてepoll登録・registry登録する。inbound接続はこの時点では
 * まだ相手のversionを受け取っていないため、自分からは何も送らずに待つ(相手からの
 * versionを受けてobject_sync.cが自分のversionを送り返す、object_sync_dispatch参照)。
 * §11 2026-08-23 backlog項目2: 同時接続数上限/accept数レート制限を超える分はここで
 * 即座にcloseする(network.h各定数のdoc参照)。
 */
void bm_network_handle_accept(struct bm_epoll_thread_args *args, struct bm_fd_data *listener, int64_t now)
{
    for (;;)
    {
        int client_fd = accept(listener->fd, NULL, NULL);
        if (client_fd < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
                bm_log("[network] accept: %s\n", strerror(errno));
            }
            break;
        }

        if (!bm_inbound_rate_limiter_allow(&args->inbound_rate_limiter, now))
        {
            bm_log("[network] rejecting inbound connection (fd=%d): accept rate limit exceeded (>%d per %ds)\n",
                    client_fd, BM_INBOUND_ACCEPT_MAX_PER_WINDOW, BM_INBOUND_ACCEPT_WINDOW_SECONDS);
            close(client_fd);
            continue;
        }
        if (args->registry != NULL
            && bm_peer_registry_count_by_type(args->registry, BM_FD_SERVER_SOCKET) >= BM_MAX_INBOUND_CONNECTIONS)
        {
            bm_log("[network] rejecting inbound connection (fd=%d): concurrent inbound limit reached (%d)\n",
                    client_fd, BM_MAX_INBOUND_CONNECTIONS);
            close(client_fd);
            continue;
        }

        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK); /* accept()されたfdはlistenソケットの
                                                          * O_NONBLOCKを継承しないため明示的に設定 */

        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_SERVER_SOCKET, client_fd);
        if (conn == NULL)
        {
            close(client_fd);
            continue;
        }

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = conn;
        if (epoll_ctl(args->epfd, EPOLL_CTL_ADD, client_fd, &ev) != 0)
        {
            bm_log("[network] epoll_ctl (inbound accept): %s\n", strerror(errno));
            bm_fd_data_free(conn);
            close(client_fd);
            continue;
        }
        if (args->registry != NULL)
        {
            bm_peer_registry_add(args->registry, conn);
        }
        bm_log("[network] accepted inbound connection (fd=%d)\n", client_fd);
    }
}

void bm_network_extract_ip_port(const struct sockaddr_storage *addr, char *out_ip, size_t out_ip_len, int *out_port)
{
    out_ip[0] = '\0';
    *out_port = 0;
    if (addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, out_ip, out_ip_len);
        *out_port = ntohs(sin->sin_port);
    }
    else if (addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, out_ip, out_ip_len);
        *out_port = ntohs(sin6->sin6_port);
    }
}

void bm_network_resolve_peer_ip_port(const struct bm_fd_data *conn, char *out_ip, size_t out_ip_len, int *out_port)
{
    if (conn->logical_peer_ip[0] != '\0')
    {
        strncpy(out_ip, conn->logical_peer_ip, out_ip_len - 1);
        out_ip[out_ip_len - 1] = '\0';
        *out_port = conn->logical_peer_port;
        return;
    }
    bm_network_extract_ip_port(&conn->peer_addr, out_ip, out_ip_len, out_port);
}

void bm_network_format_host_port(const char *host, int port, char *out, size_t out_len)
{
    if (strchr(host, ':') != NULL)
    {
        snprintf(out, out_len, "[%s]:%d", host, port);
    }
    else
    {
        snprintf(out, out_len, "%s:%d", host, port);
    }
}

/*
 * §11 2026-08-22発覚のバグ修正+2026-08-23切り出し: 接続を切断する際の後始末一式
 * (rating失敗記録・registryからの除去・epoll登録解除・close・bm_fd_data_free)。
 * 以前はbm_network_epoll_thread内の「読み取り失敗」パス専用に直書きされていたが、
 * §11 2026-08-23で新設したアイドル/ハンドシェイクタイムアウトによる能動的な切断とも
 * 共有するため切り出した。rating失敗記録は元のコメント通りoutbound
 * (BM_FD_CLIENT_SOCKET)のみが対象(こちらから選んだ相手ではないinboundは対象外)。
 */
static void close_connection(struct bm_epoll_thread_args *args, struct bm_fd_data *conn)
{
    if (conn->type == BM_FD_CLIENT_SOCKET && args->peers_db != NULL)
    {
        char ip[BM_PEER_IP_STRLEN];
        int port = 0;
        bm_network_resolve_peer_ip_port(conn, ip, sizeof(ip), &port);
        if (ip[0] != '\0')
        {
            bm_peer_manager_record_result(args->peers_db, ip, port, 1, 0);
        }
    }
    if (args->registry != NULL)
    {
        bm_peer_registry_remove(args->registry, conn);
    }
    epoll_ctl(args->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    bm_fd_data_free(conn);
}

struct idle_sweep_ctx
{
    struct bm_epoll_thread_args *args;
    int64_t now;
};

static void idle_sweep_one(struct bm_fd_data *conn, void *user_data)
{
    struct idle_sweep_ctx *ctx = user_data;
    if (conn->type == BM_FD_LISTEN_SOCKET)
    {
        return; /* listenソケット自体は対象外 */
    }
    int64_t idle_seconds = ctx->now - conn->last_activity;

    if (!conn->handshake_complete)
    {
        if (idle_seconds > BM_HANDSHAKE_TIMEOUT_SECONDS)
        {
            bm_log("[network] closing %s connection (fd=%d): handshake not completed within %ds\n",
                    conn->type == BM_FD_SERVER_SOCKET ? "inbound" : "outbound", conn->fd,
                    BM_HANDSHAKE_TIMEOUT_SECONDS);
            close_connection(ctx->args, conn);
        }
        return;
    }

    if (idle_seconds > BM_IDLE_PING_TIMEOUT_SECONDS)
    {
        /* §11 2026-08-23: pingを送るだけで切断はしない(PyBitmessage本家と同じ)。
         * 送信直後にlast_activityをここで更新することで、無応答の相手へ毎回のsweepで
         * ping spamしてしまうのを防ぐ(次にpingを送るのはさらにBM_IDLE_PING_TIMEOUT_SECONDS
         * 経ってから)。 */
        if (send_header_only(conn, "ping") == 0)
        {
            bm_log("[network] sent idle keepalive ping (fd=%d, %s, idle %" PRId64 "s)\n", conn->fd,
                    conn->type == BM_FD_SERVER_SOCKET ? "inbound" : "outbound", idle_seconds);
            conn->last_activity = ctx->now;
        }
    }
}

void bm_network_idle_sweep(struct bm_epoll_thread_args *args, int64_t now)
{
    if (args->registry == NULL)
    {
        return; /* registry無しではどの接続が生きているか把握できない(テスト等) */
    }
    struct idle_sweep_ctx ctx = {.args = args, .now = now};
    bm_peer_registry_for_each(args->registry, idle_sweep_one, &ctx);
}

void *bm_network_epoll_thread(void *arg)
{
    struct bm_epoll_thread_args *args = arg;
    struct epoll_event events[MAX_EPOLL_EVENTS];

    for (;;)
    {
        int nfds = epoll_wait(args->epfd, events, MAX_EPOLL_EVENTS, BM_IDLE_SWEEP_INTERVAL_MS);
        if (nfds == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            bm_log("epoll_wait: %s\n", strerror(errno));
            break;
        }
        /* §11 2026-08-23: 1ループぶんの基準時刻を一度だけ取得し、accept()のレート制限判定と
         * 末尾のidle_sweepの両方で共有する(time(NULL)の呼び出しを1回に節約しつつ、同じ
         * ループ内で判定基準がずれないようにする)。 */
        int64_t now = (int64_t)time(NULL);
        for (int i = 0; i < nfds; i++)
        {
            struct bm_fd_data *conn = events[i].data.ptr;
            if (conn->type == BM_FD_LISTEN_SOCKET)
            {
                bm_network_handle_accept(args, conn, now);
                continue;
            }
            int rc = bm_network_handle_readable(conn, args->handler, args->user_data);
            if (rc != 0)
            {
                /* §11 2026-08-22発覚のバグ修正: peer_connector.cはconnect()+version送信が
                 * 成功した時点でrating+0.1を記録するが、その直後にECONNRESET等で切断されても
                 * それをratingへフィードバックする経路が無く、「TCP接続とversion送信はできるが
                 * 直後に切断される」peerのratingが下がらないまま毎回の再接続サイクルで
                 * 選ばれ続けていた(実例: 特定の1peerへの接続が9700行超のログ中3474回に
                 * わたって繰り返されていた)。ここで切断時にfailureとして-0.1を記録することで、
                 * 繰り返し切断してくるpeerは他の正常なpeerと同様ratingが下がり、
                 * peer_manager.cの低rating cleanup(既存実装)の対象にもなり得るようにする。
                 * inbound(BM_FD_SERVER_SOCKET)接続はこちらから選んだ相手ではないため対象外。
                 * (§11 2026-08-23切り出し: close_connectionへ共通化) */
                /* §11 2026-08-23 backlog項目5調査中に発覚: この経路(読み取りエラー/EOFによる
                 * 切断)は元々一切ログを出しておらず、bm_network_idle_sweep側の能動的切断
                 * (ログあり)と非対称だった。listConnections APIで接続の生死を追うように
                 * なって初めて、outbound接続がここを通って頻繁に(数秒〜十数秒単位で)切断
                 * されていることが分かったため、可視化のためログを追加した。 */
                bm_log("[network] closing %s connection (fd=%d): %s\n",
                        conn->type == BM_FD_SERVER_SOCKET ? "inbound" : "outbound", conn->fd,
                        rc == 1 ? "peer closed (EOF)" : "read error");
                close_connection(args, conn);
            }
        }
        /* §11 2026-08-23: socket活動が無くても(nfds==0のタイムアウト時も含め)定期的に
         * アイドル/ハンドシェイクタイムアウトを走査する */
        bm_network_idle_sweep(args, now);
    }
    free(args);
    return NULL;
}
