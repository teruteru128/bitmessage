/*
 * §11 2026-11-19 項目64: 本家(PyBitmessage)のピアへのgetdataを、接続から
 * BM_PYBITMESSAGE_GETDATA_DELAY_SECONDS秒経つまで遅らせることのテスト。
 *
 * 経緯: 本家(dcbcc4a2)はintersection attack対策として、TCP接続の時点から
 * ceil(log20(knownNodes+2))*5.2秒(既定の設定で最大20.8秒)の間に届いたgetdataを、記録もせずに
 * 捨てる(network/tcp.pyのantiIntersectionDelay、network/bmproto.pyのbm_command_getdata)。
 * 本家のbig invはまさにこの時間帯に届くので、こちらがすぐ応えたgetdataは返ってこない。運用ログで、
 * 接続から15秒以内に送った要求がその接続から返らないことを確かめた(DESIGN.md §11項目64)。
 *
 * 検証観点:
 *   (1) 本家のピアには、接続直後のinvに対するgetdataを送らず溜める(持っているhashは溜めない)
 *   (2) 送ってよい時刻の1秒前にflushしても送らない
 *   (3) 送ってよい時刻になったら、溜めた順で1回のgetdataとして送り、溜めたものを空にする。
 *       待っている間に他のピアから受け取ったhashは要求しない
 *   (4) 送ってよい時刻を過ぎた後に届いたinvには、すぐgetdataを送る
 *   (5) 本家以外のuser agent、およびversionをまだ受け取っていない接続(user agentがNULL)には
 *       遅らせずにすぐ送る
 *   (6) 溜める件数はBM_DEFERRED_GETDATA_MAXまでで、超えた分は捨てる。上限まで溜めた分は
 *       1回のgetdataで送れる
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "../src/infra/protocol.h"

#define TEST_OBJECT_POOL_DB "test_getdata_defer_pool.db"
#define TEST_IDENTITY_DB "test_getdata_defer_identity.db"
#define TEST_MESSAGES_DB "test_getdata_defer_messages.db"
#define TEST_PEERS_DB "test_getdata_defer_peers.db"

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

/* 先頭2バイトにiを入れた固定パターンのhash */
static void make_hash(unsigned char out[32], unsigned char tag, unsigned int i)
{
    memset(out, tag, 32);
    out[0] = (unsigned char)(i >> 8);
    out[1] = (unsigned char)i;
}

/* hashes[0..n)を載せたinvを、相手から受け取ったものとしてdispatchする */
static void receive_inv(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn, unsigned char (*hashes)[32],
                        size_t n)
{
    size_t len = 0;
    unsigned char *packet = bm_create_inventory_message("inv", hashes, n, &len);
    struct bm_message *msg = NULL;
    size_t consumed = 0;
    if (packet == NULL || bm_parse_message(packet, len, &msg, &consumed) != BM_PARSE_OK)
    {
        fprintf(stderr, "FATAL: could not build inv\n");
        exit(EXIT_FAILURE);
    }
    free(packet);
    bm_object_sync_dispatch(conn, msg, ctx);
    bm_free_message(msg);
}

/* 相手側のソケットに届いたgetdataをすべて読み、要求されたhashをout(呼び出し側がfree)へ連結して
 * 返す。getdata以外のメッセージが混ざっていたら*bad=1。こちらの送信キューに残りがあれば
 * flushしながら読む。 */
static size_t read_getdata(int fd, struct bm_fd_data *conn, int64_t now, unsigned char (**out)[32], int *messages,
                           int *bad)
{
    unsigned char *buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    unsigned char tmp[65536];
    for (int guard = 0; guard < 100000; guard++)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), MSG_DONTWAIT);
        if (n > 0)
        {
            if (len + (size_t)n > cap)
            {
                cap = (len + (size_t)n) * 2;
                buf = realloc(buf, cap);
            }
            memcpy(buf + len, tmp, (size_t)n);
            len += (size_t)n;
            continue;
        }
        if (bm_network_queued_bytes(conn) == 0)
        {
            break;
        }
        bm_network_flush(conn, now);
    }

    *out = NULL;
    *messages = 0;
    size_t total = 0;
    size_t off = 0;
    while (off < len)
    {
        struct bm_message *msg = NULL;
        size_t used = 0;
        if (bm_parse_message(buf + off, len - off, &msg, &used) != BM_PARSE_OK)
        {
            bm_free_message(msg);
            *bad = 1;
            break;
        }
        struct bm_inventory_message inv;
        if (strncmp(msg->command, "getdata", 12) != 0 || bm_parse_inventory_message(msg->payload, msg->length, &inv) != 0)
        {
            *bad = 1;
        }
        else
        {
            *out = realloc(*out, (total + inv.count) * 32);
            memcpy((*out)[total], inv.items, inv.count * 32);
            total += inv.count;
            bm_free_inventory_message(&inv);
        }
        (*messages)++;
        off += used;
        bm_free_message(msg);
    }
    free(buf);
    return total;
}

struct peer
{
    struct bm_fd_data *conn;
    int remote;
};

static struct peer open_peer(const char *user_agent, int64_t connected_at)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        fprintf(stderr, "FATAL: socketpair\n");
        exit(EXIT_FAILURE);
    }
    int sz = 4 * 1024 * 1024;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    struct peer p = {bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]), sv[1]};
    p.conn->handshake_complete = 1;
    p.conn->user_agent = user_agent != NULL ? strdup(user_agent) : NULL;
    p.conn->connected_at = connected_at;
    return p;
}

static void close_peer(struct peer *p)
{
    int fd = p->conn->fd;
    bm_fd_data_free(p->conn);
    close(fd);
    close(p->remote);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    sqlite3 *peers_db = open_fresh_db(TEST_PEERS_DB, bm_peer_manager_init_schema);
    bm_keyring_t kr;
    bm_keyring_init(&kr);
    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, peers_db, &kr, NULL, NULL);

    /* handle_invは受信時刻を壁時計から取るので、接続時刻も壁時計に合わせる。テストが
     * 25秒もかかることは無いので、接続直後のinvは必ず遅延の時間帯に入る。
     * flushは時刻を引数で渡すので、境界は壁時計を待たずに確かめられる。 */
    const int64_t wall = (int64_t)time(NULL);
    const char *pybm = "/PyBitmessage:0.6.3.2/";

    unsigned char known[32];
    make_hash(known, 0x11, 0);
    unsigned char dummy[8] = {0};
    CHECK(bm_object_store_insert(object_pool_db, known, 2, 1, dummy, sizeof(dummy), wall + 3600, wall) == 0,
          "insert known object");

    /* (1)〜(3) */
    {
        struct peer p = open_peer(pybm, wall);
        unsigned char inv[4][32];
        make_hash(inv[0], 0x22, 1);
        memcpy(inv[1], known, 32);
        make_hash(inv[2], 0x22, 2);
        make_hash(inv[3], 0x22, 3);
        receive_inv(&ctx, p.conn, inv, 4);

        unsigned char(*got)[32] = NULL;
        int messages = 0;
        int bad = 0;
        size_t n = read_getdata(p.remote, p.conn, wall, &got, &messages, &bad);
        CHECK(n == 0 && messages == 0, "(1) no getdata may be sent to a PyBitmessage peer right after connecting");
        CHECK(p.conn->deferred_getdata_count == 3, "(1) the three missing hashes must be deferred, the known one not");
        free(got);

        const int64_t not_before = wall + BM_PYBITMESSAGE_GETDATA_DELAY_SECONDS;
        bm_object_sync_flush_deferred_getdata(&ctx, p.conn, not_before - 1);
        n = read_getdata(p.remote, p.conn, not_before - 1, &got, &messages, &bad);
        CHECK(n == 0 && messages == 0, "(2) nothing may be sent one second before the delay ends");
        CHECK(p.conn->deferred_getdata_count == 3, "(2) the deferred hashes must still be kept");
        free(got);

        /* 待っている間に、inv[2]を他のピアから受け取ったことにする */
        CHECK(bm_object_store_insert(object_pool_db, inv[2], 2, 1, dummy, sizeof(dummy), wall + 3600, wall) == 0,
              "insert object obtained elsewhere");
        bm_object_sync_flush_deferred_getdata(&ctx, p.conn, not_before);
        n = read_getdata(p.remote, p.conn, not_before, &got, &messages, &bad);
        CHECK(!bad && messages == 1 && n == 2, "(3) one getdata with the two still-missing hashes must be sent");
        CHECK(n == 2 && memcmp(got[0], inv[0], 32) == 0 && memcmp(got[1], inv[3], 32) == 0,
              "(3) the hashes must be requested in the order they were deferred");
        CHECK(p.conn->deferred_getdata_count == 0 && p.conn->deferred_getdata == NULL,
              "(3) the deferred list must be emptied");
        free(got);

        bm_object_sync_flush_deferred_getdata(&ctx, p.conn, not_before + 1);
        n = read_getdata(p.remote, p.conn, not_before + 1, &got, &messages, &bad);
        CHECK(n == 0 && messages == 0, "(3) a second flush must not send anything again");
        free(got);
        close_peer(&p);
    }

    /* (4) 送ってよい時刻を過ぎた本家のピア */
    {
        struct peer p = open_peer(pybm, wall - BM_PYBITMESSAGE_GETDATA_DELAY_SECONDS - 1);
        unsigned char inv[1][32];
        make_hash(inv[0], 0x33, 1);
        receive_inv(&ctx, p.conn, inv, 1);
        unsigned char(*got)[32] = NULL;
        int messages = 0;
        int bad = 0;
        size_t n = read_getdata(p.remote, p.conn, wall, &got, &messages, &bad);
        CHECK(!bad && messages == 1 && n == 1, "(4) after the delay a getdata must be sent at once");
        CHECK(p.conn->deferred_getdata_count == 0, "(4) nothing may be deferred after the delay");
        free(got);
        close_peer(&p);
    }

    /* (5) 本家以外のuser agentと、versionを受け取っていない接続 */
    const char *others[] = {"/MiNodeRefined:0.3.1/", NULL};
    for (size_t k = 0; k < 2; k++)
    {
        struct peer p = open_peer(others[k], wall);
        unsigned char inv[1][32];
        make_hash(inv[0], 0x44, (unsigned int)k);
        receive_inv(&ctx, p.conn, inv, 1);
        unsigned char(*got)[32] = NULL;
        int messages = 0;
        int bad = 0;
        size_t n = read_getdata(p.remote, p.conn, wall, &got, &messages, &bad);
        CHECK(!bad && messages == 1 && n == 1, "(5) other peers must get the getdata at once");
        CHECK(p.conn->deferred_getdata_count == 0, "(5) nothing may be deferred for other peers");
        free(got);
        close_peer(&p);
    }

    /* (6) 上限 */
    {
        struct peer p = open_peer(pybm, wall);
        unsigned char(*many)[32] = malloc((size_t)BM_DEFERRED_GETDATA_MAX * 32);
        for (unsigned int i = 0; i < BM_DEFERRED_GETDATA_MAX; i++)
        {
            make_hash(many[i], 0x55, i);
            many[i][2] = (unsigned char)(i >> 16);
        }
        receive_inv(&ctx, p.conn, many, BM_DEFERRED_GETDATA_MAX);
        unsigned char extra[2][32];
        make_hash(extra[0], 0x66, 1);
        make_hash(extra[1], 0x66, 2);
        receive_inv(&ctx, p.conn, extra, 2);
        CHECK(p.conn->deferred_getdata_count == BM_DEFERRED_GETDATA_MAX,
              "(6) no more than BM_DEFERRED_GETDATA_MAX hashes may be deferred");

        const int64_t not_before = wall + BM_PYBITMESSAGE_GETDATA_DELAY_SECONDS;
        bm_object_sync_flush_deferred_getdata(&ctx, p.conn, not_before);
        unsigned char(*got)[32] = NULL;
        int messages = 0;
        int bad = 0;
        size_t n = read_getdata(p.remote, p.conn, not_before, &got, &messages, &bad);
        CHECK(!bad && messages == 1 && n == BM_DEFERRED_GETDATA_MAX,
              "(6) the deferred hashes up to the limit must go out in one getdata");
        CHECK(n == BM_DEFERRED_GETDATA_MAX && memcmp(got[n - 1], many[n - 1], 32) == 0,
              "(6) the hashes over the limit must be the ones dropped");
        free(got);
        free(many);
        close_peer(&p);
    }

    bm_keyring_destroy(&kr);
    sqlite3_close(object_pool_db);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(peers_db);
    unlink(TEST_OBJECT_POOL_DB);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_PEERS_DB);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
