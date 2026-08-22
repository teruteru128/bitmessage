/*
 * §9 Dandelion++ Stage 1(配線のみ、実際のstem/fluff状態機械は未実装)のテスト。
 * DESIGN.md §9.2で決めたv1時点の挙動:
 * - dinvコマンドはinvと完全に同一のワイヤーフォーマットで、stem状態を一切保持せず
 *   inv受信と全く同じ処理経路(handle_inv、未所持hashへgetdataを送り返す)に流す
 * - bm_decide_propagationがobject_sync_thread(実際にはpeer_registry.cの
 *   bm_peer_registry_broadcast_inv)のinv送信判断を必ず経由する(v1は常にFLUFFを
 *   返すダミーなので、broadcast_inv自体の挙動は変わらない。既存のtest_object_sync.cの
 *   broadcast検証が引き続き通っていることでも実質的に確認済み)
 * - BM_SERVICE_NODE_DANDELION(=8)のservicesビットで対応ピアを識別する定数が
 *   protocol.hに存在すること
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/infra/network.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"

#define TEST_IDENTITY_DB "test_dandelion_identity.db"
#define TEST_MESSAGES_DB "test_dandelion_messages.db"
#define TEST_OBJECT_POOL_DB "test_dandelion_pool.db"

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

int main(void)
{
    /* --- 1. BM_SERVICE_NODE_DANDELIONがDESIGN.md §9.1通りの値であること --- */
    CHECK(BM_SERVICE_NODE_DANDELION == 8, "BM_SERVICE_NODE_DANDELION should be 8");

    /* --- 2. bm_decide_propagationはv1では常にFLUFFを返すこと --- */
    unsigned char dummy_hash[32];
    memset(dummy_hash, 0x42, sizeof(dummy_hash));
    CHECK(bm_decide_propagation(dummy_hash, NULL) == BM_PROPAGATE_FLUFF,
          "bm_decide_propagation should always return FLUFF in v1 (Stage 1 stub)");

    /* --- 3. dinv受信がinv受信と全く同じ処理経路(未所持hashへgetdataを送り返す)に
     * 流れること --- */
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, NULL, &kr, NULL, NULL);

    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
    CHECK(conn != NULL, "bm_fd_data_new");

    unsigned char unknown_hashes[2][32];
    memset(unknown_hashes[0], 0x11, 32);
    memset(unknown_hashes[1], 0x22, 32);

    size_t dinv_len = 0;
    unsigned char *dinv_packet = bm_create_inventory_message("dinv", unknown_hashes, 2, &dinv_len);
    struct bm_message *dinv_msg = NULL;
    size_t dinv_consumed = 0;
    CHECK(bm_parse_message(dinv_packet, dinv_len, &dinv_msg, &dinv_consumed) == BM_PARSE_OK,
          "parse dinv packet");
    free(dinv_packet);

    bm_object_sync_dispatch(conn, dinv_msg, &ctx);
    bm_free_message(dinv_msg);

    struct bm_message *getdata_reply = read_one_message(fds[1]);
    CHECK(getdata_reply != NULL, "should receive a getdata reply for unknown dinv items (same as inv)");
    if (getdata_reply != NULL)
    {
        CHECK(strncmp(getdata_reply->command, "getdata", 12) == 0, "reply command should be getdata");
        struct bm_inventory_message parsed_getdata;
        CHECK(bm_parse_inventory_message(getdata_reply->payload, getdata_reply->length, &parsed_getdata) == 0,
              "parse getdata reply payload");
        CHECK(parsed_getdata.count == 2, "getdata should request both unknown hashes from the dinv");
        bm_free_inventory_message(&parsed_getdata);
        bm_free_message(getdata_reply);
    }

    close(fds[0]);
    close(fds[1]);
    bm_fd_data_free(conn);
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
