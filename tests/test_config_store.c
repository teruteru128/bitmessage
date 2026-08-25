/*
 * core/config_store.c(SOCKS5プロキシ設定の永続化)、および
 * infra/peer_connector.cのSOCKS5経由outbound接続のテスト。
 * - config_store: onion/クリアネットそれぞれの既定値・set/get roundtrip・upsert(常に1行)の確認
 * - peer_connector: ローカルに立てたモックSOCKS5サーバーへ実際にCONNECTハンドシェイクを
 *   行い、bm_peer_connector_connect_initialが正しくプロキシ経由で接続を確立できることを確認
 * - §11 2026-08-26追加: onion peer(.onion宛)はSOCKS5経由、クリアネットIP宛は
 *   socks_proxy_clearnetが既定disabledのため直結される(=SOCKS5ハンドシェイクを経由せず
 *   平文のBitmessage versionメッセージがいきなり届く)ことを確認する。以前は単一の
 *   socks_proxy設定を全接続に適用しておりクリアネットIPまでTor出口ノード経由になって
 *   しまっていたバグの再発防止(DESIGN.md §11参照)。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/config_store.h"
#include "../src/core/peer_manager.h"
#include "../src/infra/peer_connector.h"
#include "../src/infra/peer_registry.h"

#define TEST_PEERS_DB "test_config_store_peers.db"
#define TEST_CONFIG_DB "test_config_store_config.db"
/* §11 2026-08-26: is_onion_host判定(peer_connector.c)に一致させ、onion proxy経由の
 * 接続経路をテストする。実在のonionアドレスである必要はない(モックSOCKS5サーバーは
 * CONNECT要求の宛先文字列を検証するだけで、実際にどこへも中継しない)。 */
#define MOCK_DEST_HOST "mock-dest.onion"
#define MOCK_DEST_PORT 12345
/* クリアネットIP宛は直結される(socks_proxy_clearnetが既定disabledのため)ことを
 * 検証する用。127.0.0.1のplain TCPサーバーへ実際にloopback接続させる。 */
#define MOCK_CLEARNET_HOST "127.0.0.1"

static int failures = 0;

/* §11 2026-08-24 backlog項目9(ASan/UBSan導入)で発覚: bm_peer_connector_connect_initialが
 * 実際に確立したbm_fd_data(と内部のrecvバッファ)は、registryへ登録されるだけで所有権を
 * registryへ移さない(close_connection/bm_fd_data_freeを呼ぶのは呼び出し元の責務、
 * peer_registry.h参照)。テストがbm_peer_registry_destroyで配列を解放するだけでは
 * 個々の接続自体はリークする(LeakSanitizerが検出)。 */
static void close_and_free_conn(struct bm_fd_data *conn, void *user_data)
{
    (void)user_data;
    close(conn->fd);
    bm_fd_data_free(conn);
}

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static sqlite3 *open_fresh_db(const char *path, int (*init_schema)(sqlite3 *))
{
    unlink(path);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", path);
        exit(EXIT_FAILURE);
    }
    return db;
}

struct mock_socks_server_args
{
    int listen_fd;
    int saw_correct_connect_request; /* out */
};

/* 最小のSOCKS5サーバー: no-auth greeting応答 -> CONNECT要求(ATYP=domain name)を検証 ->
 * 成功応答を返す。実際には別のホストへ中継しない(peer_connector側のハンドシェイク実装だけを
 * 検証すれば十分なため) */
static void *mock_socks_server_thread(void *arg)
{
    struct mock_socks_server_args *a = arg;
    a->saw_correct_connect_request = 0;

    int fd = accept(a->listen_fd, NULL, NULL);
    if (fd < 0)
    {
        return NULL;
    }

    unsigned char greeting[3];
    if (recv(fd, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting)
        || greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00)
    {
        close(fd);
        return NULL;
    }
    unsigned char method_resp[2] = {0x05, 0x00};
    send(fd, method_resp, sizeof(method_resp), 0);

    unsigned char header[5];
    if (recv(fd, header, sizeof(header), MSG_WAITALL) != (ssize_t)sizeof(header) || header[0] != 0x05
        || header[1] != 0x01 || header[2] != 0x00 || header[3] != 0x03)
    {
        close(fd);
        return NULL;
    }
    unsigned char domain_len = header[4];
    unsigned char domain[256];
    if (recv(fd, domain, domain_len, MSG_WAITALL) != (ssize_t)domain_len)
    {
        close(fd);
        return NULL;
    }
    domain[domain_len] = '\0';
    unsigned char port_bytes[2];
    if (recv(fd, port_bytes, sizeof(port_bytes), MSG_WAITALL) != (ssize_t)sizeof(port_bytes))
    {
        close(fd);
        return NULL;
    }
    int dest_port = (port_bytes[0] << 8) | port_bytes[1];

    a->saw_correct_connect_request =
        (strcmp((const char *)domain, MOCK_DEST_HOST) == 0 && dest_port == MOCK_DEST_PORT);

    unsigned char reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; /* succeeded, BND=0.0.0.0:0 */
    send(fd, reply, sizeof(reply), 0);

    /* peer_connectorはCONNECT成功後にversionメッセージを書き込んでくる。中身は検証せず
     * 読み捨てるだけでよい(何か受信することでclient側のwrite()がSIGPIPE等で失敗しないことを
     * 保証する意味もある) */
    unsigned char buf[512];
    recv(fd, buf, sizeof(buf), 0);

    close(fd);
    return NULL;
}

struct plain_tcp_server_args
{
    int listen_fd;
    int received;           /* out: 何か受信できたか */
    unsigned char first_byte; /* out: 受信した最初の1byte */
};

/*
 * §11 2026-08-26: クリアネットIP宛が直結されること(SOCKS5経由でないこと)を確認するための
 * plain TCPサーバー。SOCKS5経由ならSOCKS5グリーティングのVER(0x05)が最初に届くはずだが、
 * 直結の場合はBitmessageのversionメッセージがいきなり届くため、先頭バイトはtestnetの
 * magic bytesの最初のバイト(0xFB、protocol.h参照)になる。
 */
static void *plain_tcp_server_thread(void *arg)
{
    struct plain_tcp_server_args *a = arg;
    a->received = 0;
    a->first_byte = 0;

    int fd = accept(a->listen_fd, NULL, NULL);
    if (fd < 0)
    {
        return NULL;
    }

    unsigned char first_byte = 0;
    ssize_t n = recv(fd, &first_byte, sizeof(first_byte), MSG_WAITALL);
    if (n == (ssize_t)sizeof(first_byte))
    {
        a->received = 1;
        a->first_byte = first_byte;
    }

    close(fd);
    return NULL;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    sqlite3 *peers_db = open_fresh_db(TEST_PEERS_DB, bm_peer_manager_init_schema);
    sqlite3 *config_db = open_fresh_db(TEST_CONFIG_DB, bm_config_store_init_schema);

    /* --- 1. 既定値(onion用/クリアネット用ともにdisabled=直結) --- */
    struct bm_socks_proxy_config defaults;
    CHECK(bm_config_store_get_socks_proxy_onion(config_db, &defaults) == 0,
          "get default socks proxy config (onion)");
    CHECK(defaults.enabled == 0, "default should be disabled (onion)");
    CHECK(strcmp(defaults.host, "127.0.0.1") == 0, "default host should be 127.0.0.1 (onion)");
    CHECK(defaults.port == 9050, "default port should be 9050 (Tor既定SocksPort, onion)");

    struct bm_socks_proxy_config clearnet_defaults;
    CHECK(bm_config_store_get_socks_proxy_clearnet(config_db, &clearnet_defaults) == 0,
          "get default socks proxy config (clearnet)");
    CHECK(clearnet_defaults.enabled == 0, "default should be disabled (clearnet, 直結)");
    CHECK(strcmp(clearnet_defaults.host, "127.0.0.1") == 0, "default host should be 127.0.0.1 (clearnet)");
    CHECK(clearnet_defaults.port == 9050, "default port should be 9050 (clearnet)");

    /* --- 2. set/get roundtrip(onion用) --- */
    struct bm_socks_proxy_config to_set;
    memset(&to_set, 0, sizeof(to_set));
    to_set.enabled = 1;
    strncpy(to_set.host, "127.0.0.1", sizeof(to_set.host) - 1);
    to_set.port = 12345;
    CHECK(bm_config_store_set_socks_proxy_onion(config_db, &to_set) == 0, "set socks proxy config (onion)");

    struct bm_socks_proxy_config roundtrip;
    CHECK(bm_config_store_get_socks_proxy_onion(config_db, &roundtrip) == 0, "get after set (onion)");
    CHECK(roundtrip.enabled == 1, "roundtrip enabled (onion)");
    CHECK(strcmp(roundtrip.host, "127.0.0.1") == 0, "roundtrip host (onion)");
    CHECK(roundtrip.port == 12345, "roundtrip port (onion)");

    /* onion用を設定してもクリアネット用は既定のまま(=互いに独立)であることを確認 */
    struct bm_socks_proxy_config clearnet_unaffected;
    CHECK(bm_config_store_get_socks_proxy_clearnet(config_db, &clearnet_unaffected) == 0,
          "get clearnet config after setting onion");
    CHECK(clearnet_unaffected.enabled == 0, "clearnet should stay disabled after onion is enabled");

    /* --- 3. upsert: 2回目のsetでも1行のまま更新されること(onion用) --- */
    to_set.port = 54321;
    CHECK(bm_config_store_set_socks_proxy_onion(config_db, &to_set) == 0, "update socks proxy config (onion)");
    sqlite3_stmt *count_stmt = NULL;
    sqlite3_prepare_v2(config_db, "SELECT COUNT(*) FROM socks_proxy;", -1, &count_stmt, NULL);
    CHECK(sqlite3_step(count_stmt) == SQLITE_ROW, "count query should return a row (onion)");
    CHECK(sqlite3_column_int(count_stmt, 0) == 1, "socks_proxy table should always have exactly 1 row");
    sqlite3_finalize(count_stmt);

    /* --- 4. peer_connectorが実際にSOCKS5経由でCONNECTすること --- */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listen_fd >= 0, "mock socks server socket");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CHECK(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind mock socks server");
    socklen_t addr_len = sizeof(addr);
    CHECK(getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) == 0, "getsockname");
    int mock_port = ntohs(addr.sin_port);
    CHECK(listen(listen_fd, 1) == 0, "listen mock socks server");

    struct mock_socks_server_args mock_args;
    mock_args.listen_fd = listen_fd;
    mock_args.saw_correct_connect_request = 0;
    pthread_t mock_thread;
    CHECK(pthread_create(&mock_thread, NULL, mock_socks_server_thread, &mock_args) == 0,
          "start mock socks server thread");

    /* peers.dbへ"接続先"候補を1件登録する(実際には存在しないホストだが、モックプロキシは
     * CONNECT要求の中身を検証するだけで実際にはどこへも中継しないので問題ない) */
    struct bm_peer_entry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.ip_address, MOCK_DEST_HOST, sizeof(entry.ip_address) - 1);
    entry.port = MOCK_DEST_PORT;
    entry.stream = 1;
    entry.services = 1;
    entry.last_seen = (int64_t)time(NULL);
    entry.rating = 1.0;
    strncpy(entry.source, "test", sizeof(entry.source) - 1);
    CHECK(bm_peer_manager_upsert(peers_db, &entry) == 0, "seed test candidate into peers.db");

    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1");

    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);

    /* §11 設定変更の動的リロード: peer_connectorはstruct経由の固定スナップショットではなく、
     * config_dbを渡してconnect_initialが呼ばれるたび読み直す設計になったため、ここでも
     * config.dbへ永続化してから渡す(setSocksProxyOnion APIでの変更が反映される経路そのもの)。
     * §11 2026-08-26: MOCK_DEST_HOSTが.onionのため、onion用の設定だけ有効にする
     * (クリアネット用は既定disabledのまま、is_onion_hostがonion_proxyを選ぶことの確認)。 */
    struct bm_socks_proxy_config socks_proxy_onion_cfg;
    memset(&socks_proxy_onion_cfg, 0, sizeof(socks_proxy_onion_cfg));
    socks_proxy_onion_cfg.enabled = 1;
    strncpy(socks_proxy_onion_cfg.host, "127.0.0.1", sizeof(socks_proxy_onion_cfg.host) - 1);
    socks_proxy_onion_cfg.port = mock_port;
    CHECK(bm_config_store_set_socks_proxy_onion(config_db, &socks_proxy_onion_cfg) == 0,
          "persist socks proxy config (onion) for peer_connector to read");

    struct bm_peer_connector_config pc_config;
    memset(&pc_config, 0, sizeof(pc_config));
    pc_config.epfd = epfd;
    pc_config.peers_db = peers_db;
    pc_config.testnet = 1;
    pc_config.max_outbound = 1;
    pc_config.user_agent = "/bitmessage-c-test:0.1.0/";
    pc_config.registry = &registry;
    pc_config.config_db = config_db;

    int connected = bm_peer_connector_connect_initial(&pc_config);
    CHECK(connected == 1, "should connect exactly 1 peer via the socks proxy (onion)");

    pthread_join(mock_thread, NULL);
    CHECK(mock_args.saw_correct_connect_request,
          "mock socks server should observe a CONNECT request targeting mock-dest.onion:12345");

    bm_peer_registry_for_each(&registry, close_and_free_conn, NULL);
    bm_peer_registry_destroy(&registry);
    close(listen_fd);

    /* --- 5. クリアネットIP宛は直結されること(socks_proxy_clearnetが既定disabledのまま) ---
     * §11 2026-08-26: onion proxyだけ有効化した状態でも、クリアネットIP宛の接続には
     * onion_proxyが誤って使われない(=SOCKS5ハンドシェイクを経由しない)ことを確認する。
     * plain TCPサーバーを別途立て、SOCKS5グリーティング(0x05...)ではなくBitmessageの
     * versionメッセージ(magic bytes)がそのまま届くことを検証する。 */
    struct bm_peer_registry registry2;
    bm_peer_registry_init(&registry2);

    int plain_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(plain_listen_fd >= 0, "plain tcp server socket");
    struct sockaddr_in plain_addr;
    memset(&plain_addr, 0, sizeof(plain_addr));
    plain_addr.sin_family = AF_INET;
    plain_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    plain_addr.sin_port = 0;
    CHECK(bind(plain_listen_fd, (struct sockaddr *)&plain_addr, sizeof(plain_addr)) == 0,
          "bind plain tcp server");
    socklen_t plain_addr_len = sizeof(plain_addr);
    CHECK(getsockname(plain_listen_fd, (struct sockaddr *)&plain_addr, &plain_addr_len) == 0,
          "getsockname (plain tcp server)");
    int plain_port = ntohs(plain_addr.sin_port);
    CHECK(listen(plain_listen_fd, 1) == 0, "listen plain tcp server");

    struct plain_tcp_server_args plain_args;
    plain_args.listen_fd = plain_listen_fd;
    plain_args.received = 0;
    plain_args.first_byte = 0;
    pthread_t plain_thread;
    CHECK(pthread_create(&plain_thread, NULL, plain_tcp_server_thread, &plain_args) == 0,
          "start plain tcp server thread");

    struct bm_peer_entry clearnet_entry;
    memset(&clearnet_entry, 0, sizeof(clearnet_entry));
    strncpy(clearnet_entry.ip_address, MOCK_CLEARNET_HOST, sizeof(clearnet_entry.ip_address) - 1);
    clearnet_entry.port = plain_port;
    clearnet_entry.stream = 1;
    clearnet_entry.services = 1;
    clearnet_entry.last_seen = (int64_t)time(NULL);
    clearnet_entry.rating = 1.0;
    strncpy(clearnet_entry.source, "test", sizeof(clearnet_entry.source) - 1);
    /* peers.dbを空にしてから登録(onion向けcandidateが残っていると確率的選定で
     * 選ばれない可能性があるため、候補をこの1件だけにする) */
    sqlite3_exec(peers_db, "DELETE FROM hosts;", NULL, NULL, NULL);
    CHECK(bm_peer_manager_upsert(peers_db, &clearnet_entry) == 0, "seed clearnet candidate into peers.db");

    int epfd2 = epoll_create1(0);
    CHECK(epfd2 >= 0, "epoll_create1 (2)");
    pc_config.epfd = epfd2;
    pc_config.registry = &registry2;

    int connected2 = bm_peer_connector_connect_initial(&pc_config);
    CHECK(connected2 == 1, "should connect exactly 1 peer directly (clearnet)");

    pthread_join(plain_thread, NULL);
    CHECK(plain_args.received, "plain tcp server should receive the version message directly");
    /* §11 2026-08-26: bm_peer_connector_connect_initialはconfig->testnetをseed_bootstrap
     * にしか使わずbm_protocol_set_testnetは呼ばないため、実際に届くmagic bytesは
     * プロセスの既定(mainnet=0xE9)のまま。testnet/mainnetどちらでもSOCKS5のVER(0x05)とは
     * 一致しないので、それだけを直結の証拠として検証する(magic bytesの値そのものは
     * この関数のテストの過剰前提にしない)。 */
    CHECK(plain_args.first_byte != 0x05,
          "clearnet connection should NOT start with a SOCKS5 greeting (0x05) -- proves it was a "
          "direct connection, not via the onion proxy");

    bm_peer_registry_for_each(&registry2, close_and_free_conn, NULL);
    bm_peer_registry_destroy(&registry2);
    close(epfd);
    close(epfd2);
    close(plain_listen_fd);
    sqlite3_close(peers_db);
    sqlite3_close(config_db);
    unlink(TEST_PEERS_DB);
    unlink(TEST_CONFIG_DB);

    if (failures == 0)
    {
        printf("OK\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
