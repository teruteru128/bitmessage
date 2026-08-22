/*
 * §9.5 Dandelion++ Stage 3(inv/dinvの来歴を区別し、通常inv経由で知ったobjectはstemせず
 * 即座にfluffする)のテスト。
 *
 * - bm_dandelion_note_source(hash, is_dinv=0, ...)を呼んだ後にbm_dandelion_decideを
 *   呼ぶと、stem successorが存在しても常にFLUFFになること(既に他ノードがfluff済みの
 *   objectをそれ以上stemしても意味が無いため)
 * - bm_dandelion_note_source(hash, is_dinv=1, ...)を呼んだ後は、note_sourceを一切
 *   呼ばなかった場合(自分発object)と同じく通常のstem→タイムアウトfluff経路を通ること
 * - infra/object_sync.cのhandle_inv経由で実際に"inv"コマンドを受信させた場合、そのhashに
 *   ついて後でbm_decide_propagationを呼ぶと(stem successorがあっても)FLUFFになること
 *   ("dinv"コマンドで受信した場合はSTEM/SKIPになりうることとの対比)
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/infra/dandelion.h"
#include "../src/infra/network.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"

#define TEST_IDENTITY_DB "test_dandelion3_identity.db"
#define TEST_MESSAGES_DB "test_dandelion3_messages.db"
#define TEST_OBJECT_POOL_DB "test_dandelion3_pool.db"

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

static struct bm_fd_data *make_test_conn(enum bm_fd_type type, uint64_t services, int *out_local_fd,
                                          int *out_remote_fd)
{
    int listen_fd = bm_network_listen("127.0.0.1", 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len);
    int port = ntohs(addr.sin_port);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in connect_addr;
    memset(&connect_addr, 0, sizeof(connect_addr));
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &connect_addr.sin_addr);
    (void)connect(client_fd, (struct sockaddr *)&connect_addr, sizeof(connect_addr));

    int accepted_fd = accept(listen_fd, NULL, NULL);
    close(listen_fd);

    struct bm_fd_data *conn = bm_fd_data_new(type, accepted_fd);
    conn->services = services;
    *out_local_fd = accepted_fd;
    *out_remote_fd = client_fd;
    return conn;
}

int main(void)
{
    /* --- 1. note_source(is_dinv=0)後は、stem successorがあっても常にFLUFF --- */
    {
        bm_dandelion_module_init();

        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);
        int fds_a[2];
        struct bm_fd_data *conn_a =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_a[0], &fds_a[1]);
        bm_peer_registry_add(&reg, conn_a);

        int64_t t0 = 3000000000;
        bm_dandelion_maybe_reshuffle(&reg, t0); /* conn_aが候補は1つだけなので必ず選ばれる */

        unsigned char hash_plain[32];
        memset(hash_plain, 0x11, sizeof(hash_plain));
        bm_dandelion_note_source(hash_plain, 0 /* is_dinv */, t0);

        CHECK(bm_dandelion_decide(hash_plain, conn_a, t0) == BM_PROPAGATE_FLUFF,
              "a hash learned via plain inv should FLUFF immediately even with a stem successor available");
        /* 一度FLUFFと確定した後は、別の接続に対して聞いても常にFLUFFのまま */
        CHECK(bm_dandelion_decide(hash_plain, NULL, t0) == BM_PROPAGATE_FLUFF,
              "once fluffed via plain-inv provenance, later queries should stay FLUFF");

        bm_peer_registry_remove(&reg, conn_a);
        bm_fd_data_free(conn_a);
        close(fds_a[1]);
        bm_peer_registry_destroy(&reg);
    }

    /* --- 2. note_source(is_dinv=1)後は、note_sourceを呼ばなかった場合と同じくSTEM/SKIPに
     * なりうる(dinv経由は「stemを継続してよい」という既定動作を変えない) --- */
    {
        bm_dandelion_module_init();

        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);
        int fds_a[2];
        struct bm_fd_data *conn_a =
            make_test_conn(BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_a[0], &fds_a[1]);
        bm_peer_registry_add(&reg, conn_a);

        int64_t t0 = 3000000000;
        bm_dandelion_maybe_reshuffle(&reg, t0);

        unsigned char hash_dinv[32];
        memset(hash_dinv, 0x22, sizeof(hash_dinv));
        bm_dandelion_note_source(hash_dinv, 1 /* is_dinv */, t0);

        enum bm_propagation_mode mode = bm_dandelion_decide(hash_dinv, conn_a, t0);
        CHECK(mode == BM_PROPAGATE_STEM,
              "a hash learned via dinv, queried against the (only) stem successor, should be STEM");

        bm_peer_registry_remove(&reg, conn_a);
        bm_fd_data_free(conn_a);
        close(fds_a[1]);
        bm_peer_registry_destroy(&reg);
    }

    /* --- 3. object_sync.cのhandle_inv経由: 実際に"inv"コマンドで学んだhashは
     * bm_decide_propagationが常にFLUFFを返すこと(stem successorがあっても) --- */
    {
        bm_dandelion_module_init();

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

        struct bm_peer_registry reg;
        bm_peer_registry_init(&reg);

        struct bm_object_sync_ctx ctx;
        bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, NULL, &kr, &reg, NULL);

        int fds_sender[2], fds_stem_candidate[2];
        struct bm_fd_data *sender_conn = make_test_conn(BM_FD_CLIENT_SOCKET, 0, &fds_sender[0], &fds_sender[1]);
        struct bm_fd_data *stem_candidate_conn = make_test_conn(
            BM_FD_CLIENT_SOCKET, BM_SERVICE_NODE_DANDELION, &fds_stem_candidate[0], &fds_stem_candidate[1]);
        bm_peer_registry_add(&reg, sender_conn);
        bm_peer_registry_add(&reg, stem_candidate_conn);

        bm_dandelion_maybe_reshuffle(&reg, (int64_t)time(NULL));

        unsigned char hash_via_inv[32];
        memset(hash_via_inv, 0x33, sizeof(hash_via_inv));

        size_t inv_len = 0;
        unsigned char *inv_packet = bm_create_inventory_message("inv", &hash_via_inv, 1, &inv_len);
        struct bm_message *inv_msg = NULL;
        size_t inv_consumed = 0;
        bm_parse_message(inv_packet, inv_len, &inv_msg, &inv_consumed);
        free(inv_packet);

        /* sender_conn経由で"inv"を受信させる(handle_invがbm_dandelion_note_source(is_dinv=0)
         * を呼ぶはず)。getdata送信自体はこのテストの関心事ではないので結果は読み捨てる */
        bm_object_sync_dispatch(sender_conn, inv_msg, &ctx);
        bm_free_message(inv_msg);

        CHECK(bm_decide_propagation(hash_via_inv, stem_candidate_conn) == BM_PROPAGATE_FLUFF,
              "a hash learned via a real 'inv' message dispatch should FLUFF immediately, even though a "
              "stem successor is available");

        bm_peer_registry_remove(&reg, sender_conn);
        bm_peer_registry_remove(&reg, stem_candidate_conn);
        bm_fd_data_free(sender_conn);
        bm_fd_data_free(stem_candidate_conn);
        close(fds_sender[1]);
        close(fds_stem_candidate[1]);
        bm_peer_registry_destroy(&reg);
        bm_keyring_destroy(&kr);
        sqlite3_close(object_pool_db);
        sqlite3_close(identity_db);
        sqlite3_close(messages_db);
        unlink(TEST_OBJECT_POOL_DB);
        unlink(TEST_IDENTITY_DB);
        unlink(TEST_MESSAGES_DB);
    }

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
