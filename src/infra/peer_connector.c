#include "peer_connector.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../common/logging.h"
#include "../core/config_store.h"
#include "../core/peer_manager.h"
#include "dandelion.h"
#include "network.h"
#include "object_sync.h"
#include "peer_registry.h"

/* §11 2026-08-23発覚のバグ修正: 以前は32件(=rating上位32件)しか候補として取得しておらず、
 * peers.dbの大半(実測417件中385件)がそもそも接続選定の対象外になっていた。256は
 * struct bm_peer_entry candidates[256]がスタック上でも問題ないサイズ(1件約112byte×256≒28KB) */
#define MAX_CANDIDATES 256
#define CONNECT_TIMEOUT_SEC 5
/* SOCKS5ハンドシェイク(特にCONNECT応答待ち)は、宛先がTor等の場合に回線構築で数秒〜十数秒
 * かかることがあるため、ローカルのプロキシ自体へのTCP接続(CONNECT_TIMEOUT_SEC)より長めに取る */
#define SOCKS5_HANDSHAKE_TIMEOUT_SEC 20

/* 非ブロッキングconnect + selectでタイムアウト付き接続を行う。成功時fd、失敗時-1 */
static int connect_with_timeout(const char *ip, int port, int timeout_sec)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(ip, port_str, &hints, &res) != 0)
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
            break; /* 即座に完了(loopback等) */
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
        break; /* 接続成功。O_NONBLOCKのままepollへ渡す */
    }

    freeaddrinfo(res);
    return sock;
}

/* O_NONBLOCKなsockに対しEAGAIN/EWOULDBLOCKをselect()で待ちながらlenバイト送り切る。成功時0 */
static int socks5_send_all(int sock, const unsigned char *buf, size_t len, int timeout_sec)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n > 0)
        {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0)
            {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return 0;
}

/* 同上の受信版。lenバイト読み切るまでselect()で待つ。相手がcloseしたら失敗として扱う */
static int socks5_recv_all(int sock, unsigned char *buf, size_t len, int timeout_sec)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t n = recv(sock, buf + got, len - got, 0);
        if (n > 0)
        {
            got += (size_t)n;
            continue;
        }
        if (n == 0)
        {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0)
            {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return 0;
}

/* RFC1928のREPコードを人間が読めるメッセージへ変換する(§11 outbound Tor経路の検証:
 * 実際にTorへ繋いだ際の失敗原因切り分けを容易にするため) */
static const char *socks5_rep_to_string(unsigned char rep)
{
    switch (rep)
    {
        case 0x00: return "succeeded";
        case 0x01: return "general SOCKS server failure";
        case 0x02: return "connection not allowed by ruleset";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "command not supported";
        case 0x08: return "address type not supported";
        default: return "unknown REP code";
    }
}

/*
 * SOCKS5(RFC1928)のno-auth CONNECTハンドシェイク。sockは既にproxyへ接続済み(O_NONBLOCK)で
 * あること。宛先は常にドメイン名形式(ATYP=0x03)で送る: dest_hostが数字IPの文字列であっても
 * Tor等のSOCKS5サーバーは正しく扱う(ローカルでDNS解決せずそのままCONNECT先として使うため、
 * 将来onionアドレスに対応する際もこの経路がそのまま使える)。成功時0。失敗時は原因を
 * bm_log_warn("[peer_connector] socks5: ...")で診断ログに出す(§11、実際にTorへ繋いだ
 * 際の切り分けを容易にするため)
 */
static int socks5_connect(int sock, const char *dest_host, int dest_port, int timeout_sec)
{
    char addr_buf[80];
    bm_network_format_host_port(dest_host, dest_port, addr_buf, sizeof(addr_buf));

    size_t host_len = strlen(dest_host);
    if (host_len == 0 || host_len > 255)
    {
        bm_log_warn("[peer_connector] socks5: destination host name too long (%zu bytes)\n", host_len);
        return -1;
    }

    unsigned char greeting[3] = {0x05, 0x01, 0x00}; /* version=5, 1 method, no-auth */
    if (socks5_send_all(sock, greeting, sizeof(greeting), timeout_sec) != 0)
    {
        bm_log_warn("[peer_connector] socks5: failed to send greeting to proxy\n");
        return -1;
    }
    unsigned char method_resp[2];
    if (socks5_recv_all(sock, method_resp, sizeof(method_resp), timeout_sec) != 0)
    {
        bm_log_warn("[peer_connector] socks5: no greeting response from proxy (unreachable/not a "
                        "SOCKS5 server?)\n");
        return -1;
    }
    if (method_resp[0] != 0x05 || method_resp[1] != 0x00)
    {
        bm_log_warn("[peer_connector] socks5: proxy rejected no-auth (version=0x%02x method=0x%02x)\n",
                method_resp[0], method_resp[1]);
        return -1;
    }

    unsigned char req[4 + 1 + 255 + 2];
    size_t req_len = 0;
    req[req_len++] = 0x05;
    req[req_len++] = 0x01; /* CMD=CONNECT */
    req[req_len++] = 0x00; /* RSV */
    req[req_len++] = 0x03; /* ATYP=domain name */
    req[req_len++] = (unsigned char)host_len;
    memcpy(req + req_len, dest_host, host_len);
    req_len += host_len;
    req[req_len++] = (unsigned char)((dest_port >> 8) & 0xff);
    req[req_len++] = (unsigned char)(dest_port & 0xff);
    if (socks5_send_all(sock, req, req_len, timeout_sec) != 0)
    {
        bm_log_warn("[peer_connector] socks5: failed to send CONNECT request to proxy\n");
        return -1;
    }

    unsigned char reply_head[4];
    if (socks5_recv_all(sock, reply_head, sizeof(reply_head), timeout_sec) != 0)
    {
        bm_log_warn("[peer_connector] socks5: no CONNECT reply from proxy (target %s unreachable "
                        "via Tor circuit, or proxy timed out)\n",
                addr_buf);
        return -1;
    }
    if (reply_head[0] != 0x05 || reply_head[1] != 0x00)
    {
        bm_log_warn("[peer_connector] socks5: CONNECT to %s failed: %s (REP=0x%02x)\n", addr_buf,
                socks5_rep_to_string(reply_head[1]), reply_head[1]);
        return -1;
    }

    size_t bnd_addr_len;
    switch (reply_head[3])
    {
        case 0x01:
            bnd_addr_len = 4;
            break;
        case 0x04:
            bnd_addr_len = 16;
            break;
        case 0x03:
        {
            unsigned char len_byte;
            if (socks5_recv_all(sock, &len_byte, 1, timeout_sec) != 0)
            {
                bm_log_warn("[peer_connector] socks5: failed to read BND.ADDR length\n");
                return -1;
            }
            bnd_addr_len = len_byte;
            break;
        }
        default:
            bm_log_warn("[peer_connector] socks5: unsupported BND.ADDR type 0x%02x in reply\n",
                    reply_head[3]);
            return -1;
    }
    unsigned char discard[256];
    if (socks5_recv_all(sock, discard, bnd_addr_len + 2, timeout_sec) != 0)
    {
        bm_log_warn("[peer_connector] socks5: failed to read BND.ADDR/BND.PORT\n");
        return -1; /* BND.ADDR + BND.PORT。値自体は使わない */
    }
    return 0;
}

/*
 * socks_proxyが有効ならproxy経由でSOCKS5 CONNECTして接続し、そうでなければ従来通り直結する。
 * 戻り値はconnect_with_timeoutと同じ(成功時fd、失敗時-1)。
 */
static int open_peer_connection(const char *ip, int port, int timeout_sec,
                                 const struct bm_socks_proxy_config *socks_proxy)
{
    if (socks_proxy != NULL && socks_proxy->enabled)
    {
        int sock = connect_with_timeout(socks_proxy->host, socks_proxy->port, timeout_sec);
        if (sock < 0)
        {
            char proxy_addr_buf[80];
            bm_network_format_host_port(socks_proxy->host, socks_proxy->port, proxy_addr_buf,
                                         sizeof(proxy_addr_buf));
            bm_log_warn("[peer_connector] socks5: failed to reach proxy %s (is Tor/the proxy "
                            "running?)\n",
                    proxy_addr_buf);
            return -1;
        }
        if (socks5_connect(sock, ip, port, SOCKS5_HANDSHAKE_TIMEOUT_SEC) != 0)
        {
            close(sock);
            return -1;
        }
        return sock;
    }
    return connect_with_timeout(ip, port, timeout_sec);
}

/* §11 2026-08-23発覚のバグ修正: 以前はbm_peer_manager_list_top(rating降順)の先頭から
 * 順に候補を試していたため、rating上位の少数peerだけが毎サイクル選ばれ続け(接続しても
 * すぐ切断されるpeerでも、verack成功+0.1と切断失敗-0.1がサイクルごとにほぼ相殺して
 * ratingが高いまま維持されるため)、実測で40候補中9件が11回以上・最大222回(ほぼ毎サイクル)
 * 再接続される一方、他の25件は1回しか試されない「強者総取り」状態になっていた。
 *
 * PyBitmessage本家(network/connectionchooser.pyのchooseConnection)を調査したところ、
 * 決定的な「rating上位N件」ではなく確率的な重み付きランダムサンプリングを使っていた:
 * 候補から毎回一様ランダムに1件選び、ratingに応じた確率(0.05/(1-rating)、rating=0で
 * 5%、rating=0.9で50%、rating→1でほぼ100%)で採用するかどうかを乱数判定し、棄却されたら
 * 別の候補を再度試す(最大50回)。この方式を移植する(LAN discovery優先・bootstrap
 * serverモード用cooldown・onion rating強制ブーストは対象外、DESIGN.md参照)。 */
#define CHOOSE_CANDIDATE_MAX_ATTEMPTS 50
#define CHOOSE_CANDIDATE_BASE_PROB 0.05
/* §11 2026-08-24: rating<0の候補向け再接続クールダウン。詳細はpeer_connector.hの
 * bm_peer_connector_choose_candidate_indexのdocコメント参照。 */
#define BM_PEER_LOW_RATING_COOLDOWN_SECONDS 1800

/* [0,1)の一様乱数(PyBitmessageのrandom.random()相当)。dandelion.cのexponential_randomと
 * 同じRAND_bytesベースの正規化手法を使う(暗号強度は不要、他のnonce生成箇所と手段を揃える) */
static double uniform_random(void)
{
    unsigned char buf[4];
    RAND_bytes(buf, sizeof(buf));
    uint32_t r;
    memcpy(&r, buf, sizeof(r));
    return (double)r / 4294967296.0; /* 2^32、[0,1)に収まる */
}

/*
 * candidates[0..candidate_count)から確率的に1件選ぶ。既に接続済みの相手(registry)は
 * 無条件で不採用として次のランダムな1件を試す。見つからなければ-1を返す
 * (呼び出し側は今回のサイクルでの接続をこれ以上試みない)。
 */
int bm_peer_connector_choose_candidate_index(const struct bm_peer_entry *candidates, int candidate_count,
                                              struct bm_peer_registry *registry, int max_attempts, int64_t now)
{
    if (candidate_count <= 0)
    {
        return -1;
    }
    for (int attempt = 0; attempt < max_attempts; attempt++)
    {
        unsigned char buf[4];
        RAND_bytes(buf, sizeof(buf));
        uint32_t r;
        memcpy(&r, buf, sizeof(r));
        int idx = (int)(r % (uint32_t)candidate_count);

        if (registry != NULL
            && bm_peer_registry_has_peer(registry, candidates[idx].ip_address, candidates[idx].port))
        {
            continue; /* 既に接続済みの相手には二重接続しない */
        }

        if (candidates[idx].rating < 0.0
            && now - candidates[idx].last_attempt < BM_PEER_LOW_RATING_COOLDOWN_SECONDS)
        {
            continue; /* §11 2026-08-24: 低rating peerの再接続クールダウン中は不採用 */
        }

        double rating = candidates[idx].rating;
        if (rating >= 1.0)
        {
            return idx; /* PyBitmessageのZeroDivisionError->即採用と同じ扱い */
        }
        double prob = CHOOSE_CANDIDATE_BASE_PROB / (1.0 - rating);
        if (prob > uniform_random())
        {
            return idx;
        }
    }
    return -1;
}

int bm_peer_connector_connect_initial(const struct bm_peer_connector_config *config)
{
    /* §11 peers.dbの低rating/古いノードのクリーンアップ。seed_bootstrapより前に呼ぶことで、
     * クリーンアップの結果hostsテーブルが完全に空になった場合でも同じ呼び出し内で
     * 既定シードが再投入される(bm_peer_manager_seed_bootstrapはテーブルが空の時のみ
     * 動作するため) */
    int cleaned = bm_peer_manager_cleanup(config->peers_db, (int64_t)time(NULL));
    if (cleaned > 0)
    {
        bm_log_info("[peer_connector] cleaned up %d stale/low-rating peer(s) from peers.db\n", cleaned);
    }

    bm_peer_manager_seed_bootstrap(config->peers_db, config->testnet, config->observed_nodes_path);

    /* §11 設定変更の動的リロード: 呼ばれるたびconfig.dbから読み直す(スナップショットを
     * 保持しない)ことで、setSocksProxy APIでの変更がdaemon再起動なしで次回呼び出し
     * (=次の再接続サイクル、既定30秒間隔)から反映されるようにする */
    struct bm_socks_proxy_config socks_proxy;
    memset(&socks_proxy, 0, sizeof(socks_proxy));
    if (config->config_db != NULL)
    {
        bm_config_store_get_socks_proxy(config->config_db, &socks_proxy);
    }

    size_t already_connected = config->registry != NULL ? bm_peer_registry_count(config->registry) : 0;
    if ((int)already_connected >= config->max_outbound)
    {
        return 0;
    }
    int want = config->max_outbound - (int)already_connected;

    struct bm_peer_entry candidates[MAX_CANDIDATES];
    int candidate_count = 0;
    if (bm_peer_manager_list_top(config->peers_db, 1, candidates, MAX_CANDIDATES, &candidate_count) != 0)
    {
        return -1;
    }

    int connected = 0;
    while (connected < want)
    {
        if (config->stop_flag != NULL && *config->stop_flag != 0)
        {
            break; /* §11 2026-08-23発覚のバグ修正: shutdown中は残り候補を試さず速やかに戻る */
        }

        int64_t now = (int64_t)time(NULL);
        int i = bm_peer_connector_choose_candidate_index(candidates, candidate_count, config->registry,
                                                          CHOOSE_CANDIDATE_MAX_ATTEMPTS, now);
        if (i < 0)
        {
            break; /* 今回のサイクルではこれ以上の候補が見つからない(PyBitmessageのValueError相当) */
        }

        /* §11 2026-08-24: DBへ永続化するだけでなくcandidates[i]のローカルコピーも
         * その場で更新する。list_topは呼び出し1回につき候補を1度しかfetchしないため、
         * これをしないと同一connect_initial呼び出し内(=同一want充足ループ)で低rating
         * candidateが即座に再選出されてしまい、クールダウンの意味が無くなる。 */
        candidates[i].last_attempt = now;
        bm_peer_manager_record_attempt(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, now);

        char addr_buf[80];
        bm_network_format_host_port(candidates[i].ip_address, candidates[i].port, addr_buf, sizeof(addr_buf));

        bm_log_debug("[peer_connector] connecting to %s%s...\n", addr_buf,
                socks_proxy.enabled ? " (via SOCKS5)" : "");
        int sock = open_peer_connection(candidates[i].ip_address, candidates[i].port, CONNECT_TIMEOUT_SEC,
                                         &socks_proxy);
        if (sock < 0)
        {
            bm_log_warn("[peer_connector] failed to connect to %s\n", addr_buf);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sock);
        if (conn == NULL)
        {
            bm_log_error("[peer_connector] bm_fd_data_new failed for %s\n", addr_buf);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }
        /* §11 2026-08-22発覚のバグ修正: SOCKS5(Tor)経由の場合、conn->peer_addr(getpeername)は
         * プロキシ自身のアドレスになりpeer_manager.cのrating更新に使えない。ここで選んだ
         * 本来の接続先(candidates[i])を明示的に控えておき、network.c/object_sync.cの
         * rating記録処理がこちらを優先して使うようにする(network.h参照)。 */
        strncpy(conn->logical_peer_ip, candidates[i].ip_address, sizeof(conn->logical_peer_ip) - 1);
        conn->logical_peer_port = candidates[i].port;

        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = conn;
        if (epoll_ctl(config->epfd, EPOLL_CTL_ADD, sock, &ev) != 0)
        {
            bm_log_warn("[peer_connector] epoll_ctl: %s\n", strerror(errno));
            bm_fd_data_free(conn);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }

        if (bm_post_version(sock, config->user_agent, 3, &conn->peer_addr, &conn->local_addr) != 0)
        {
            bm_log_warn("[peer_connector] failed to send version to %s\n", addr_buf);
            epoll_ctl(config->epfd, EPOLL_CTL_DEL, sock, NULL);
            bm_fd_data_free(conn);
            close(sock);
            bm_peer_manager_record_result(config->peers_db, candidates[i].ip_address, candidates[i].port, 1, 0);
            continue;
        }
        /* §11 2026-08-23 backlog項目5: bm_post_versionはfdだけを取りconnを持たないため、
         * ここで送信済みバイト数を積む(bm_version_message_sizeは実際に送った長さと
         * 同じ計算をするだけの副作用の無い関数、network.hのdoc参照)。 */
        conn->bytes_sent += (uint64_t)bm_version_message_size(config->user_agent);

        if (config->registry != NULL)
        {
            bm_peer_registry_add(config->registry, conn);
        }
        /* §11 2026-08-22発覚のバグ修正: ここではsuccessを記録しない。以前はTCP接続+自分の
         * version送信が成功しただけでrating+0.1していたが、これは相手が実際に応答したかとは
         * 無関係な「自分側の送信が成功した」という弱い基準で、「繋がるが直後に相手から切断
         * される」peerでも毎サイクル必ず成功扱いになってしまっていた。infra/network.cの
         * bm_network_epoll_threadが切断時にfailure(-0.1)を記録するようになった今、この
         * success(+0.1)が毎サイクル打ち消してしまい、ratingが永久に上限1.0へ張り付いたまま
         * 抜け出せないバグを引き起こしていた(実際に9700行超のログ中3474回、同じ死んだpeerに
         * 接続し続けていたのを確認済み)。successの記録はinfra/object_sync.cのversion/verack
         * 受信時点(=相手が実際に応答した確かな証拠が得られた時点)へ移した。 */

        bm_log_info("[peer_connector] connected to %s, version sent\n", addr_buf);
        connected++;
    }

    return connected;
}

#define RECONNECT_INTERVAL_SECONDS 30
#define STOP_POLL_INTERVAL_SECONDS 1

void *bm_peer_connector_thread(void *arg)
{
    struct bm_peer_connector_thread_args *args = arg;
    /* §11 2026-08-23発覚のバグ修正: connect_initial自身の候補ループにshutdown中断を
     * 効かせるため、自分のstop_flagをconfig側にも伝播しておく */
    args->config.stop_flag = args->stop_flag;

    while (*args->stop_flag == 0)
    {
        int connected = bm_peer_connector_connect_initial(&args->config);
        if (connected > 0)
        {
            bm_log_info("[peer_connector] %d new outbound connection(s) established\n", connected);
        }

        for (int waited = 0; waited < RECONNECT_INTERVAL_SECONDS && *args->stop_flag == 0; waited++)
        {
            /* §9 Dandelion++ Stage 2: 専用スレッドを新設せず、この既存の1秒間隔ポーリング
             * ループに相乗りさせる(DESIGN.md §9.2で「実装着手時に判断する」としていた点、
             * PyBitmessageのInvThread.expire()相当の頻度に合わせた)。registryが無ければ
             * (テスト等)何もしない。bm_dandelion_maybe_reshuffleは内部で10分間隔かどうかを
             * 判定するため、1秒ごとに呼んでも大半は即returnするだけで軽い。 */
            int64_t now = (int64_t)time(NULL);
            if (args->config.registry != NULL)
            {
                bm_dandelion_maybe_reshuffle(args->config.registry, now);
                bm_dandelion_expire_and_refluff(args->config.registry, now);
            }
            /* §11 2026-08-24 backlog項目6: onionpeer自己announceの定期再送も同じくこの
             * 1秒間隔ループに相乗りさせる。registryの有無とは無関係(§9のDandelion++とは
             * 独立した機能)のためif (args->config.registry != NULL)の外に置く。
             * bm_object_sync_maybe_reannounce_onion_peerは内部で2時間強の間隔かどうかを
             * 判定するため、1秒ごとに呼んでも大半は即returnするだけで軽い
             * (object_sync_ctxがNULLなら何もしない)。 */
            if (args->config.object_sync_ctx != NULL)
            {
                bm_object_sync_maybe_reannounce_onion_peer(args->config.object_sync_ctx,
                                                            args->config.self_onion_address,
                                                            args->config.self_onion_port, now);
            }
            sleep(STOP_POLL_INTERVAL_SECONDS);
        }
    }

    free(args);
    return NULL;
}
