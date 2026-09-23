/*
 * §11 2026-09-24 項目43: getdataへの応答を補充方式(handle_getdataは要求hashを保留へ積むだけ、
 * bm_object_sync_refill_uploadsが送信キューの空きに合わせて少しずつobjectを積む)にしたことの
 * テスト。
 *
 * 経緯: 以前のhandle_getdataは要求された全objectをその場で同期的に書いており、受信側が2秒
 * 読まないだけで「書き込み失敗」として接続を切っていた。運用ログでは、初期同期中で数百件単位の
 * getdataを送ってくる生きているPyBitmessage peerを、応答の途中で繰り返し切っていた
 * (DESIGN.md §11項目43)。PyBitmessage本家(network/bmproto.pyのbm_command_getdata、
 * network/uploadthread.py)と同じく、保留+2MBしきい値+10件ずつの補充に置き換えた。
 *
 * 検証観点:
 *   (1) しきい値を大きく超える量(約6MB)のgetdataを受けても、相手が読むまでの間、送信キューは
 *       BM_UPLOAD_REFILL_THRESHOLD_BYTES+object1個分を超えない(残りは保留に残る)
 *   (2) 相手がしばらく読まなくても接続を切らない(pending_evictionが立たない)
 *   (3) 相手が読み進めるのに合わせて補充され、最終的に要求した順で全objectが壊れずに届く
 *   (4) 持っていないhashは飛ばされ、他の送信を妨げない
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/peer_manager.h"
#include "../src/infra/network.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"

#define TEST_OBJECT_POOL_DB "test_getdata_upload_pool.db"
#define TEST_IDENTITY_DB "test_getdata_upload_identity.db"
#define TEST_MESSAGES_DB "test_getdata_upload_messages.db"
#define TEST_PEERS_DB "test_getdata_upload_peers.db"

#define OBJECT_COUNT 150
#define OBJECT_PAYLOAD_LEN 40000
#define MISSING_COUNT 3

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

struct recv_buf
{
    unsigned char *data;
    size_t len;
    size_t cap;
};

static void drain(int fd, struct recv_buf *rb)
{
    unsigned char tmp[8192];
    for (;;)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), MSG_DONTWAIT);
        if (n <= 0)
        {
            return;
        }
        if (rb->len + (size_t)n > rb->cap)
        {
            rb->cap = (rb->len + (size_t)n) * 2;
            rb->data = realloc(rb->data, rb->cap);
        }
        memcpy(rb->data + rb->len, tmp, (size_t)n);
        rb->len += (size_t)n;
    }
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

    const int64_t now = 2000000000;

    /* object i: hashは先頭2バイトにiを入れた固定パターン、payload先頭4バイトにiを入れる。
     * 送信側は保存済みのbyte列をそのまま返すだけなので、PoWの正しさは関係しない */
    unsigned char hashes[OBJECT_COUNT + MISSING_COUNT][32];
    size_t h = 0;
    unsigned char *payload = malloc(OBJECT_PAYLOAD_LEN);
    for (int i = 0; i < OBJECT_COUNT; i++)
    {
        memset(hashes[h], 0xA0, 32);
        hashes[h][0] = (unsigned char)(i >> 8);
        hashes[h][1] = (unsigned char)i;
        memset(payload, (unsigned char)i, OBJECT_PAYLOAD_LEN);
        payload[0] = (unsigned char)(i >> 24);
        payload[1] = (unsigned char)(i >> 16);
        payload[2] = (unsigned char)(i >> 8);
        payload[3] = (unsigned char)i;
        CHECK(bm_object_store_insert(object_pool_db, hashes[h], 2, 1, payload, OBJECT_PAYLOAD_LEN, now + 3600, now)
                      == 0,
              "insert test object");
        h++;
        /* 持っていないhashを途中に混ぜる(4) */
        if (i == 10 || i == 70 || i == 140)
        {
            memset(hashes[h], 0xEE, 32);
            hashes[h][0] = (unsigned char)i;
            h++;
        }
    }
    free(payload);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    int sz = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    conn->handshake_complete = 1;

    size_t getdata_len = 0;
    unsigned char *getdata_packet = bm_create_inventory_message("getdata", hashes, h, &getdata_len);
    struct bm_message *getdata = NULL;
    size_t consumed = 0;
    CHECK(bm_parse_message(getdata_packet, getdata_len, &getdata, &consumed) == BM_PARSE_OK, "parse getdata");
    free(getdata_packet);

    bm_object_sync_dispatch(conn, getdata, &ctx);
    bm_free_message(getdata);

    const size_t max_queue = BM_UPLOAD_REFILL_THRESHOLD_BYTES + OBJECT_PAYLOAD_LEN + BM_MESSAGE_HEADER_SIZE;
    CHECK(bm_network_queued_bytes(conn) <= max_queue,
          "(1) the send queue must not exceed the refill threshold plus one object");
    CHECK(conn->upload_pending_count > 0, "(1) the rest must stay pending until the peer reads");
    CHECK(conn->pending_eviction == 0, "(2) a peer that has not read yet must not be evicted");

    struct recv_buf rb = {0};
    int over_limit = 0;
    for (int guard = 0; guard < 1000000 && (conn->upload_pending_count > 0 || bm_network_queued_bytes(conn) > 0);
         guard++)
    {
        drain(sv[1], &rb);
        bm_network_flush(conn, now + 1);
        bm_object_sync_refill_uploads(conn, now + 1, &ctx);
        if (bm_network_queued_bytes(conn) > max_queue)
        {
            over_limit = 1;
        }
    }
    drain(sv[1], &rb);
    CHECK(!over_limit, "(1) the send queue must stay bounded while refilling");
    CHECK(conn->pending_eviction == 0, "(2) a slow but reading peer must never be evicted");
    CHECK(conn->upload_pending_count == 0 && bm_network_queued_bytes(conn) == 0, "(3) everything must be sent");

    /* (3)(4) 要求順に全objectが届き、持っていないhashは飛ばされていること */
    size_t off = 0;
    int next = 0;
    int bad = 0;
    while (off < rb.len)
    {
        struct bm_message *msg = NULL;
        size_t used = 0;
        if (bm_parse_message(rb.data + off, rb.len - off, &msg, &used) != BM_PARSE_OK)
        {
            bm_free_message(msg);
            bad = 1;
            break;
        }
        int seq = ((int)msg->payload[0] << 24) | ((int)msg->payload[1] << 16) | ((int)msg->payload[2] << 8)
                  | msg->payload[3];
        if (strncmp(msg->command, "object", 12) != 0 || msg->length != OBJECT_PAYLOAD_LEN || seq != next
            || msg->payload[OBJECT_PAYLOAD_LEN - 1] != (unsigned char)next)
        {
            bad = 1;
        }
        next++;
        off += used;
        bm_free_message(msg);
    }
    CHECK(!bad, "(3) objects must arrive intact and in the requested order");
    CHECK(next == OBJECT_COUNT, "(3)(4) every stored object must arrive, and missing hashes must be skipped");

    free(rb.data);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
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
