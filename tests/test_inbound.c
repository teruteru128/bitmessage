/*
 * §11 inbound接続(Tor hidden service)対応のテスト。
 * - bm_network_listenが実際にTCP接続を受け付けられること
 * - accept()されたソケットに対しbm_fd_data_new(BM_FD_SERVER_SOCKET, ...)が正しく動作すること
 *   (listenソケット自体はgetpeername()できないが、accept()された側のソケットはできる。
 *   §11で修正した「listenソケットはgetpeername()をスキップする」ロジックとは別の経路)
 * - inbound接続がversionを受信した際、verackに加えて自分自身のversionも送り返すこと
 *   (outboundは接続直後に自分から送信済みなので送り返さない。object_sync.c参照)
 *
 * epollスレッド自体(無限ループ)は起動せず、bm_network_listen/accept/
 * bm_object_sync_dispatchを直接呼ぶことで、実ソケットを使いつつ決定的にテストする
 * (tests/test_object_sync.cのsocketpair直接呼び出しパターンと同じ考え方)。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/infra/network.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"

#define TEST_IDENTITY_DB "test_inbound_identity.db"
#define TEST_MESSAGES_DB "test_inbound_messages.db"
#define TEST_OBJECT_POOL_DB "test_inbound_pool.db"
#define TEST_USER_AGENT "/bitmessage-c-test:0.1.0/"

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                        \
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

/* fdから1個のP2Pメッセージを読み込む(ブロッキング前提の小さいメッセージのみ) */
static struct bm_message *read_one_message(int fd)
{
    unsigned char buf[65536];
    size_t total = 0;
    for (;;)
    {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total);
        if (n <= 0)
        {
            return NULL;
        }
        total += (size_t)n;

        struct bm_message *msg = NULL;
        size_t consumed = 0;
        if (bm_parse_message(buf, total, &msg, &consumed) == BM_PARSE_OK)
        {
            return msg;
        }
    }
}

/*
 * read_one_messageは呼び出しごとにバッファを使い捨てるため、1回のread()に
 * 複数メッセージ(例: verack+version)が同時に届くと2個目以降のバイト列を
 * 静かに捨ててしまい、次の呼び出しが永久にブロックする。
 * このreaderはバッファとoffsetをfd単位で呼び出しをまたいで保持することで、
 * 1回の受信に複数メッセージが含まれていても取りこぼさずに1個ずつ返す。
 */
struct msg_reader
{
    unsigned char buf[65536];
    size_t total;  /* buf内の有効データ長 */
    size_t offset; /* 消費済み(パース済み)位置 */
};

static struct bm_message *reader_next_message(int fd, struct msg_reader *r)
{
    for (;;)
    {
        if (r->total > r->offset)
        {
            struct bm_message *msg = NULL;
            size_t consumed = 0;
            enum bm_parse_result pr =
                bm_parse_message(r->buf + r->offset, r->total - r->offset, &msg, &consumed);
            if (pr == BM_PARSE_OK)
            {
                r->offset += consumed;
                return msg;
            }
        }

        if (r->offset > 0)
        {
            memmove(r->buf, r->buf + r->offset, r->total - r->offset);
            r->total -= r->offset;
            r->offset = 0;
        }

        ssize_t n = read(fd, r->buf + r->total, sizeof(r->buf) - r->total);
        if (n <= 0)
        {
            return NULL;
        }
        r->total += (size_t)n;
    }
}

int main(void)
{
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, NULL, &kr, NULL, TEST_USER_AGENT);

    /* --- 1. bm_network_listen: ポート0でOSに割り当てさせ、getsocknameで実際のポートを知る --- */
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    CHECK(listen_fd >= 0, "bm_network_listen should succeed on 127.0.0.1:0 (OS-assigned port)");
    if (listen_fd < 0)
    {
        return EXIT_FAILURE;
    }

    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    CHECK(getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len) == 0, "getsockname on listener");
    int listen_port = ntohs(listen_addr.sin_port);

    /* --- 2. クライアント役がconnect()し、bm_post_versionで実際にversionを送る --- */
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client_fd >= 0, "create client socket");
    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = htons((uint16_t)listen_port);
    inet_pton(AF_INET, "127.0.0.1", &connect_addr.sin_addr);
    CHECK(connect(client_fd, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) == 0,
          "client connects to the inbound listener");

    struct sockaddr_storage client_local, client_peer;
    socklen_t client_local_len = sizeof(client_local);
    socklen_t client_peer_len = sizeof(client_peer);
    getsockname(client_fd, (struct sockaddr *)&client_local, &client_local_len);
    getpeername(client_fd, (struct sockaddr *)&client_peer, &client_peer_len);
    CHECK(bm_post_version(client_fd, "/bitmessage-c-test-client:0.1.0/", 3, &client_peer, &client_local) == 0,
          "client sends version");

    /* --- 3. サーバー側: accept()し、BM_FD_SERVER_SOCKETとしてbm_fd_data_newできることを
     * 確認する(§11の「listenソケットはgetpeername()をスキップする」修正が、accept()された
     * 側のソケット[peerが実在する]まで壊していないことの確認でもある) --- */
    int accepted_fd = accept(listen_fd, NULL, NULL);
    CHECK(accepted_fd >= 0, "server accepts the inbound connection");
    struct bm_fd_data *server_conn = bm_fd_data_new(BM_FD_SERVER_SOCKET, accepted_fd);
    CHECK(server_conn != NULL, "bm_fd_data_new should succeed for an accepted inbound socket");

    if (server_conn != NULL)
    {
        /* --- 4. サーバー側がクライアントのversionを受信し、verack + 自分自身のversionを
         * 送り返すことを確認する(inbound固有の挙動、object_sync.c参照) --- */
        struct bm_message *client_version_msg = read_one_message(accepted_fd);
        CHECK(client_version_msg != NULL && strncmp(client_version_msg->command, "version", 12) == 0,
              "server should receive the client's version message");
        if (client_version_msg != NULL)
        {
            bm_object_sync_dispatch(server_conn, client_version_msg, &ctx);
            bm_free_message(client_version_msg);
        }

        /* クライアント側で受信を確認: verackとversionの両方が届くはず(順序は問わない)。
         * 両方が同じread()にまとまって届く可能性があるため、read_one_messageではなく
         * fdをまたいで状態を保持するreader_next_messageを使う */
        int saw_verack = 0;
        int saw_version = 0;
        struct msg_reader client_reader = {{0}, 0, 0};
        for (int i = 0; i < 2; i++)
        {
            struct bm_message *reply = reader_next_message(client_fd, &client_reader);
            CHECK(reply != NULL, "client should receive a reply from the server");
            if (reply == NULL)
            {
                break;
            }
            if (strncmp(reply->command, "verack", 12) == 0)
            {
                saw_verack = 1;
            }
            else if (strncmp(reply->command, "version", 12) == 0)
            {
                saw_version = 1;
                struct bm_version_message ver;
                bm_parse_version_message(reply->payload, reply->length, &ver);
                CHECK(ver.user_agent != NULL && strcmp(ver.user_agent, TEST_USER_AGENT) == 0,
                      "server's own version should carry our configured user agent");
                bm_free_version_message(&ver);
            }
            bm_free_message(reply);
        }
        CHECK(saw_verack, "inbound handshake: server should reply with verack");
        CHECK(saw_version,
              "inbound handshake: server should also send its own version (outbound would not, since it "
              "already sent one at connect time)");

        bm_fd_data_free(server_conn);
    }

    close(client_fd);
    close(listen_fd);
    bm_keyring_destroy(&kr);
    sqlite3_close(object_pool_db);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    unlink(TEST_OBJECT_POOL_DB);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
