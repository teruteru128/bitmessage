/*
 * core/config_store.c(SOCKS5プロキシ設定の永続化)、および
 * infra/peer_connector.cのSOCKS5経由outbound接続のテスト。
 * - config_store: 既定値・set/get roundtrip・upsert(常に1行)の確認
 * - peer_connector: ローカルに立てたモックSOCKS5サーバーへ実際にCONNECTハンドシェイクを
 *   行い、bm_peer_connector_connect_initialが正しくプロキシ経由で接続を確立できることを確認
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
#include "../src/infra/peer_connector.h"
#include "../src/infra/peer_manager.h"
#include "../src/infra/peer_registry.h"

#define TEST_PEERS_DB "test_config_store_peers.db"
#define TEST_CONFIG_DB "test_config_store_config.db"
#define MOCK_DEST_HOST "mock-destination.example"
#define MOCK_DEST_PORT 12345

static int failures = 0;

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

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    sqlite3 *peers_db = open_fresh_db(TEST_PEERS_DB, bm_peer_manager_init_schema);
    sqlite3 *config_db = open_fresh_db(TEST_CONFIG_DB, bm_config_store_init_schema);

    /* --- 1. 既定値 --- */
    struct bm_socks_proxy_config defaults;
    CHECK(bm_config_store_get_socks_proxy(config_db, &defaults) == 0, "get default socks proxy config");
    CHECK(defaults.enabled == 0, "default should be disabled");
    CHECK(strcmp(defaults.host, "127.0.0.1") == 0, "default host should be 127.0.0.1");
    CHECK(defaults.port == 9050, "default port should be 9050 (Tor既定SocksPort)");

    /* --- 2. set/get roundtrip --- */
    struct bm_socks_proxy_config to_set;
    memset(&to_set, 0, sizeof(to_set));
    to_set.enabled = 1;
    strncpy(to_set.host, "127.0.0.1", sizeof(to_set.host) - 1);
    to_set.port = 12345;
    CHECK(bm_config_store_set_socks_proxy(config_db, &to_set) == 0, "set socks proxy config");

    struct bm_socks_proxy_config roundtrip;
    CHECK(bm_config_store_get_socks_proxy(config_db, &roundtrip) == 0, "get after set");
    CHECK(roundtrip.enabled == 1, "roundtrip enabled");
    CHECK(strcmp(roundtrip.host, "127.0.0.1") == 0, "roundtrip host");
    CHECK(roundtrip.port == 12345, "roundtrip port");

    /* --- 3. upsert: 2回目のsetでも1行のまま更新されること --- */
    to_set.port = 54321;
    CHECK(bm_config_store_set_socks_proxy(config_db, &to_set) == 0, "update socks proxy config");
    sqlite3_stmt *count_stmt = NULL;
    sqlite3_prepare_v2(config_db, "SELECT COUNT(*) FROM socks_proxy;", -1, &count_stmt, NULL);
    CHECK(sqlite3_step(count_stmt) == SQLITE_ROW, "count query should return a row");
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

    struct bm_socks_proxy_config socks_proxy;
    memset(&socks_proxy, 0, sizeof(socks_proxy));
    socks_proxy.enabled = 1;
    strncpy(socks_proxy.host, "127.0.0.1", sizeof(socks_proxy.host) - 1);
    socks_proxy.port = mock_port;

    struct bm_peer_connector_config pc_config;
    memset(&pc_config, 0, sizeof(pc_config));
    pc_config.epfd = epfd;
    pc_config.peers_db = peers_db;
    pc_config.testnet = 1;
    pc_config.max_outbound = 1;
    pc_config.user_agent = "/bitmessage-c-test:0.1.0/";
    pc_config.registry = &registry;
    pc_config.socks_proxy = &socks_proxy;

    int connected = bm_peer_connector_connect_initial(&pc_config);
    CHECK(connected == 1, "should connect exactly 1 peer via the socks proxy");

    pthread_join(mock_thread, NULL);
    CHECK(mock_args.saw_correct_connect_request, "mock socks server should observe a CONNECT request "
                                                   "targeting mock-destination.example:12345");

    bm_peer_registry_destroy(&registry);
    close(epfd);
    close(listen_fd);
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
