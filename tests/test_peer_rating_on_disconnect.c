/*
 * §11 2026-08-22発覚のバグ修正のテスト。
 *
 * 実際のbootstrap daemonのログで、特定の1peerへの接続が9700行超のログ中3474回にわたって
 * 繰り返されていることが見つかった。原因は2段階:
 *
 * 1回目の修正(bm_network_epoll_threadが切断時にfailureを記録するようにした)だけでは
 * 実は不十分だった。peer_connector.cが「TCP接続+自分のversion送信が成功」した時点で
 * 無条件にsuccess(+0.1)を記録していたため、「繋がるが相手からは一切応答が無いまま
 * 切断される」peerでも毎サイクル必ずsuccessが記録され、切断時のfailure(-0.1)を
 * 毎回打ち消してratingが上限1.0に張り付いたまま抜け出せなかった(success/failureが
 * ちょうど1回ずつ、同じサイクル内で相殺し合っていたため)。
 *
 * 2回目の修正でsuccessの記録場所をpeer_connector.cから infra/object_sync.c の
 * version/verack受信時点(=相手が実際に応答した確かな証拠が得られた時点)へ移した。
 * これにより「応答が一切無いまま切断される」peerは二度とsuccessを得られず、
 * failureだけが積み重なってratingが実際に下がっていくようになった。
 *
 * --- シナリオ1: 応答なしで切断 ---
 * bm_network_epoll_threadの実スレッドを起動し、実TCP接続(BM_FD_CLIENT_SOCKET、outbound
 * 接続を模す)が(versionへの応答を一切受け取らないまま)peer切断(EOF)で終了した際に、
 * peers.dbの該当行のratingが実際に-0.1されることを確認する。
 *
 * --- シナリオ2: 相手が実際にverackで応答する ---
 * bm_object_sync_dispatchへ実際にverackメッセージを渡した場合、BM_FD_CLIENT_SOCKET
 * (outbound、こちらが選んだ相手)ではratingが+0.1される一方、BM_FD_SERVER_SOCKET
 * (inbound、相手が繋いできた側)では記録されないことを確認する。
 *
 * どちらもtests/test_inbound.cと同じ「実ソケット+実スレッドで決定的に検証する」方針。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/peer_manager.h"
#include "../src/infra/network.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"

#define TEST_PEERS_DB "test_peer_rating_peers.db"
#define TEST_OBJECT_POOL_DB "test_peer_rating_pool.db"
#define TEST_IDENTITY_DB "test_peer_rating_identity.db"
#define TEST_MESSAGES_DB "test_peer_rating_messages.db"

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
    unlink(TEST_PEERS_DB);
    sqlite3 *peers_db = NULL;
    if (sqlite3_open(TEST_PEERS_DB, &peers_db) != SQLITE_OK || bm_peer_manager_init_schema(peers_db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", TEST_PEERS_DB);
        return EXIT_FAILURE;
    }

    /* --- 1. "偽peer"役のリスナーを立てる(以後こちらからconnect()し、切断を模す側) --- */
    int fake_peer_listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(fake_peer_listen_fd >= 0, "bm_network_listen should succeed for the fake-peer listener");
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    getsockname(fake_peer_listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len);
    int fake_peer_port = ntohs(listen_addr.sin_port);

    /* --- 2. peers.dbへ、この"偽peer"のratingを0.5として先に登録しておく --- */
    struct bm_peer_entry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.ip_address, "127.0.0.1", sizeof(entry.ip_address) - 1);
    entry.port = fake_peer_port;
    entry.stream = 1;
    entry.rating = 0.5;
    strncpy(entry.source, "test", sizeof(entry.source) - 1);
    CHECK(bm_peer_manager_upsert(peers_db, &entry) == 0, "seeding the peers.db row should succeed");

    /* --- 3. こちらから"偽peer"へoutbound接続する(=peer_connector.cが接続した状況を模す。
     * BM_FD_CLIENT_SOCKETとして登録する) --- */
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client_fd >= 0, "create client socket");
    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = htons((uint16_t)fake_peer_port);
    inet_pton(AF_INET, "127.0.0.1", &connect_addr.sin_addr);
    CHECK(connect(client_fd, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) == 0,
          "outbound connect to the fake peer should succeed");

    int accepted_fd = accept(fake_peer_listen_fd, NULL, NULL);
    CHECK(accepted_fd >= 0, "fake peer should accept the connection");

    struct bm_fd_data *client_conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, client_fd);
    CHECK(client_conn != NULL, "bm_fd_data_new should succeed for the outbound client socket");

    /* --- 4. epollを組み立て、bm_network_epoll_threadを実際に起動する。peers_dbを渡すのが
     * 今回のバグ修正の要(渡さなければrating更新はスキップされる、network.h参照) --- */
    int epfd = epoll_create1(0);
    CHECK(epfd >= 0, "epoll_create1 should succeed");
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client_conn;
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) == 0, "epoll_ctl ADD should succeed");

    struct bm_epoll_thread_args *args = malloc(sizeof(*args));
    args->epfd = epfd;
    args->handler = NULL; /* default_dispatchでよい。versionを送らないのでhandlerには到達しない */
    args->user_data = NULL;
    args->registry = NULL;
    args->peers_db = peers_db;
    bm_inbound_rate_limiter_init(&args->inbound_rate_limiter);

    pthread_t epoll_thread;
    CHECK(pthread_create(&epoll_thread, NULL, bm_network_epoll_thread, args) == 0,
          "pthread_create for bm_network_epoll_thread should succeed");
    /* bm_network_epoll_threadはグレースフルシャットダウン機構を持たない(DESIGN.md既知の
     * 制約)ため、joinはせずプロセス終了時に道連れで終わらせる(main.cの既存方針と同じ) */

    /* --- 5. "偽peer"側が即座に接続を切断する(EOF)。これがbm_network_handle_readableに
     * rc=1("peer closed")を返させ、epollスレッド側のrc!=0分岐(切断処理)を発火させる --- */
    close(accepted_fd);
    close(fake_peer_listen_fd);

    /* epollスレッドが切断を検知しrating更新するまで少し待つ(ポーリング、最大2秒) */
    double final_rating = 0.5;
    int found = 0;
    for (int i = 0; i < 40; i++)
    {
        struct bm_peer_entry results[1];
        int count = 0;
        if (bm_peer_manager_list_top(peers_db, 1, results, 1, &count) == 0 && count == 1)
        {
            found = 1;
            final_rating = results[0].rating;
            if (final_rating < 0.5 - 1e-9)
            {
                break;
            }
        }
        struct timespec ts = {0, 50L * 1000L * 1000L}; /* 50ms */
        nanosleep(&ts, NULL);
    }

    CHECK(found, "the seeded peer row should still exist in peers.db");
    CHECK(final_rating < 0.5 - 1e-9,
          "rating should have decreased below 0.5 after the outbound connection was disconnected");
    CHECK(final_rating > 0.4 - 1e-9 && final_rating < 0.4 + 1e-9,
          "rating should have decreased by exactly 0.1 (0.5 -> 0.4)");

    /* --- シナリオ2: verack受信でsuccessが記録されること(outboundのみ、inboundは対象外) --- */
    {
        sqlite3 *object_pool_db = NULL;
        sqlite3 *identity_db = NULL;
        sqlite3 *messages_db = NULL;
        unlink(TEST_OBJECT_POOL_DB);
        unlink(TEST_IDENTITY_DB);
        unlink(TEST_MESSAGES_DB);
        sqlite3_open(TEST_OBJECT_POOL_DB, &object_pool_db);
        bm_object_store_init_schema(object_pool_db);
        sqlite3_open(TEST_IDENTITY_DB, &identity_db);
        bm_identity_store_init_schema(identity_db);
        sqlite3_open(TEST_MESSAGES_DB, &messages_db);
        bm_messages_store_init_schema(messages_db);

        bm_keyring_t kr;
        bm_keyring_init(&kr);

        struct bm_object_sync_ctx ctx;
        bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, peers_db, &kr, NULL, NULL);

        /* 2b-1: outbound(BM_FD_CLIENT_SOCKET)でverackを受け取るとsuccessが記録される */
        struct bm_peer_entry entry2;
        memset(&entry2, 0, sizeof(entry2));
        strncpy(entry2.ip_address, "127.0.0.1", sizeof(entry2.ip_address) - 1);
        entry2.port = 55501;
        entry2.stream = 1;
        entry2.rating = 0.3;
        strncpy(entry2.source, "test", sizeof(entry2.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &entry2) == 0, "seeding the scenario2 outbound peer row");

        struct sockaddr_storage fake_outbound_peer_addr;
        memset(&fake_outbound_peer_addr, 0, sizeof(fake_outbound_peer_addr));
        struct sockaddr_in *sin_out = (struct sockaddr_in *)&fake_outbound_peer_addr;
        sin_out->sin_family = AF_INET;
        sin_out->sin_port = htons(55501);
        inet_pton(AF_INET, "127.0.0.1", &sin_out->sin_addr);

        struct bm_fd_data outbound_conn;
        memset(&outbound_conn, 0, sizeof(outbound_conn));
        outbound_conn.type = BM_FD_CLIENT_SOCKET;
        outbound_conn.fd = -1; /* verack受信処理自体はfdへ書き込まない(bm_reply_verack等を
                                 * 呼ぶのはversion分岐のみ)ためこのテストでは未接続のままでよい */
        outbound_conn.peer_addr = fake_outbound_peer_addr;

        struct bm_message verack_msg;
        memset(&verack_msg, 0, sizeof(verack_msg));
        memcpy(verack_msg.command, "verack", 6);
        bm_object_sync_dispatch(&outbound_conn, &verack_msg, &ctx);

        struct bm_peer_entry after_outbound[16];
        int count_out = 0;
        CHECK(bm_peer_manager_list_top(peers_db, 1, after_outbound, 16, &count_out) == 0 && count_out >= 1,
              "scenario2 outbound peer row lookup should succeed");
        int found_out = 0;
        for (int i = 0; i < count_out; i++)
        {
            if (after_outbound[i].port == 55501)
            {
                found_out = 1;
                CHECK(after_outbound[i].rating > 0.4 - 1e-9 && after_outbound[i].rating < 0.4 + 1e-9,
                      "outbound verack should credit success: rating should become 0.4 (0.3 + 0.1)");
            }
        }
        CHECK(found_out, "scenario2 outbound peer row should be found");

        /* 2b-2: inbound(BM_FD_SERVER_SOCKET)でverackを受け取ってもsuccessは記録されない
         * (こちらが選んだ相手ではないため、network.cの切断時failure記録と対称) */
        struct bm_peer_entry entry3;
        memset(&entry3, 0, sizeof(entry3));
        strncpy(entry3.ip_address, "127.0.0.1", sizeof(entry3.ip_address) - 1);
        entry3.port = 55502;
        entry3.stream = 1;
        entry3.rating = 0.3;
        strncpy(entry3.source, "test", sizeof(entry3.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &entry3) == 0, "seeding the scenario2 inbound peer row");

        struct sockaddr_storage fake_inbound_peer_addr;
        memset(&fake_inbound_peer_addr, 0, sizeof(fake_inbound_peer_addr));
        struct sockaddr_in *sin_in = (struct sockaddr_in *)&fake_inbound_peer_addr;
        sin_in->sin_family = AF_INET;
        sin_in->sin_port = htons(55502);
        inet_pton(AF_INET, "127.0.0.1", &sin_in->sin_addr);

        struct bm_fd_data inbound_conn;
        memset(&inbound_conn, 0, sizeof(inbound_conn));
        inbound_conn.type = BM_FD_SERVER_SOCKET;
        inbound_conn.fd = -1;
        inbound_conn.peer_addr = fake_inbound_peer_addr;

        bm_object_sync_dispatch(&inbound_conn, &verack_msg, &ctx);

        struct bm_peer_entry after_inbound[16];
        int count_in = 0;
        CHECK(bm_peer_manager_list_top(peers_db, 1, after_inbound, 16, &count_in) == 0 && count_in >= 1,
              "scenario2 inbound peer row lookup should succeed");
        int found_in = 0;
        for (int i = 0; i < count_in; i++)
        {
            if (after_inbound[i].port == 55502)
            {
                found_in = 1;
                CHECK(after_inbound[i].rating > 0.3 - 1e-9 && after_inbound[i].rating < 0.3 + 1e-9,
                      "inbound verack should NOT credit success: rating should stay 0.3");
            }
        }
        CHECK(found_in, "scenario2 inbound peer row should be found");

        /* --- シナリオ3: SOCKS5(Tor)プロキシ越しの接続。conn->peer_addr(getpeername)は
         * プロキシ自身のアドレス(127.0.0.1:9060、実在しないダミーだが実際の
         * "127.0.0.1:9050"問題と同じ形)を指すが、conn->logical_peer_ipには
         * peer_connector.cが設定するはずの「本来の接続先」(203.0.113.9:8444、
         * TEST-NET-3の予約アドレスなので実在せずテストとして安全)を入れておく。
         * bm_network_resolve_peer_ip_portがlogical_peer_ipを優先することで、
         * プロキシのアドレスではなく本来の接続先のratingが正しく更新されることを
         * 確認する(2026-08-22発覚のバグそのものの再現+修正確認)。 --- */
        struct bm_peer_entry entry4;
        memset(&entry4, 0, sizeof(entry4));
        strncpy(entry4.ip_address, "203.0.113.9", sizeof(entry4.ip_address) - 1);
        entry4.port = 8444;
        entry4.stream = 1;
        entry4.rating = 0.3;
        strncpy(entry4.source, "test", sizeof(entry4.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &entry4) == 0, "seeding the scenario3 proxied peer row");

        struct sockaddr_storage fake_proxy_addr;
        memset(&fake_proxy_addr, 0, sizeof(fake_proxy_addr));
        struct sockaddr_in *sin_proxy = (struct sockaddr_in *)&fake_proxy_addr;
        sin_proxy->sin_family = AF_INET;
        sin_proxy->sin_port = htons(9060);
        inet_pton(AF_INET, "127.0.0.1", &sin_proxy->sin_addr);

        struct bm_fd_data proxied_conn;
        memset(&proxied_conn, 0, sizeof(proxied_conn));
        proxied_conn.type = BM_FD_CLIENT_SOCKET;
        proxied_conn.fd = -1;
        proxied_conn.peer_addr = fake_proxy_addr; /* OSレベルではプロキシに繋がっている */
        strncpy(proxied_conn.logical_peer_ip, "203.0.113.9", sizeof(proxied_conn.logical_peer_ip) - 1);
        proxied_conn.logical_peer_port = 8444; /* peer_connector.cが設定するのと同じ形 */

        bm_object_sync_dispatch(&proxied_conn, &verack_msg, &ctx);

        struct bm_peer_entry after_proxied[16];
        int count_proxied = 0;
        CHECK(bm_peer_manager_list_top(peers_db, 1, after_proxied, 16, &count_proxied) == 0
                  && count_proxied >= 1,
              "scenario3 peer row lookup should succeed");
        int found_proxied = 0;
        for (int i = 0; i < count_proxied; i++)
        {
            if (strcmp(after_proxied[i].ip_address, "203.0.113.9") == 0 && after_proxied[i].port == 8444)
            {
                found_proxied = 1;
                CHECK(after_proxied[i].rating > 0.4 - 1e-9 && after_proxied[i].rating < 0.4 + 1e-9,
                      "proxied outbound verack should credit the REAL target (logical_peer_ip), not the "
                      "proxy's address: rating should become 0.4 (0.3 + 0.1)");
            }
            /* プロキシのアドレス(127.0.0.1:9060)が誤って登録されていないことも確認する */
            CHECK(!(strcmp(after_proxied[i].ip_address, "127.0.0.1") == 0 && after_proxied[i].port == 9060),
                  "the proxy's own address should never be recorded into peers.db");
        }
        CHECK(found_proxied, "scenario3 peer row should be found");

        /* --- シナリオ4: §11 2026-08-23発覚のバグ修正確認。logical_peer_ipにv3 onion
         * アドレス(56文字base32+".onion"=62文字)を入れた場合でも、途中で切り捨てられず
         * peers.dbの実際の行(同じくフルの62文字)と一致してratingが更新されることを確認する。
         * 以前はlogical_peer_ip[46]がINET6_ADDRSTRLEN相当のサイズしか無く、62文字の
         * onionアドレスがstrncpyで45文字+NULへ黙って切り捨てられ、peers.db上のフルの
         * 行と一致しなくなり0行ヒットのままrating/last_seen更新が静かに失敗していた --- */
        const char *onion_peer = "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion";
        CHECK(strlen(onion_peer) == 62, "sanity check: v3 onion address string should be 62 chars");

        struct bm_peer_entry entry5;
        memset(&entry5, 0, sizeof(entry5));
        strncpy(entry5.ip_address, onion_peer, sizeof(entry5.ip_address) - 1);
        entry5.port = 8444;
        entry5.stream = 1;
        entry5.rating = 0.3;
        strncpy(entry5.source, "test", sizeof(entry5.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &entry5) == 0, "seeding the scenario4 onion peer row");

        struct bm_fd_data onion_conn;
        memset(&onion_conn, 0, sizeof(onion_conn));
        onion_conn.type = BM_FD_CLIENT_SOCKET;
        onion_conn.fd = -1;
        strncpy(onion_conn.logical_peer_ip, onion_peer, sizeof(onion_conn.logical_peer_ip) - 1);
        CHECK(strcmp(onion_conn.logical_peer_ip, onion_peer) == 0,
              "logical_peer_ip should hold the full 62-char onion address without truncation");
        onion_conn.logical_peer_port = 8444;

        bm_object_sync_dispatch(&onion_conn, &verack_msg, &ctx);

        struct bm_peer_entry after_onion[16];
        int count_onion = 0;
        CHECK(bm_peer_manager_list_top(peers_db, 1, after_onion, 16, &count_onion) == 0 && count_onion >= 1,
              "scenario4 peer row lookup should succeed");
        int found_onion = 0;
        for (int i = 0; i < count_onion; i++)
        {
            if (strcmp(after_onion[i].ip_address, onion_peer) == 0 && after_onion[i].port == 8444)
            {
                found_onion = 1;
                CHECK(after_onion[i].rating > 0.4 - 1e-9 && after_onion[i].rating < 0.4 + 1e-9,
                      "verack from an onion peer should credit the full-length onion address's row: "
                      "rating should become 0.4 (0.3 + 0.1)");
            }
        }
        CHECK(found_onion, "scenario4 onion peer row should be found (not silently missed due to truncation)");

        bm_keyring_destroy(&kr);
        sqlite3_close(object_pool_db);
        sqlite3_close(identity_db);
        sqlite3_close(messages_db);
        unlink(TEST_OBJECT_POOL_DB);
        unlink(TEST_IDENTITY_DB);
        unlink(TEST_MESSAGES_DB);
    }

    sqlite3_close(peers_db);
    unlink(TEST_PEERS_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
