/*
 * §11 2026-09-24 項目43: 接続ごとの送信キュー(bm_network_send/bm_network_flush/
 * bm_network_epoll_register、network.hのdoc参照)のテスト。
 *
 * 経緯: 以前は各所がbm_network_write_allで同期的に書いており、受信側が2秒読むのを止める
 * だけで「書き込み失敗」として接続を切っていた。運用ログでは、初期同期中で受信が追いつか
 * ないだけの生きているPyBitmessage peerを、getdata応答の途中で繰り返し切っていた
 * (DESIGN.md §11項目43)。また別スレッドが同じソケットへ並行して書くため、部分書き込みの
 * 途中に割り込むとメッセージが混ざりうる構造だった。送信をキュー+ノンブロッキング送信+
 * EPOLLOUTに置き換え、切断判定を「送るものがあるのにBM_SEND_STALL_TIMEOUT_SECONDS書けない」
 * に変えた。
 *
 * 検証観点:
 *   (1) 空いていれば積んだその場で送られる(既存の「handlerを呼んで応答を読む」テストが
 *       そのまま動く前提)
 *   (2) 送信バッファを小さくして部分書き込みを起こしても、受信側で全メッセージが順序
 *       どおり・checksumも正しく復元できる
 *   (3) 複数スレッドから並行して積んでも、受信側で壊れたメッセージが1つも出ない
 *   (4) 相手がゆっくりでも読んでいれば切られず、全く進まなければ停滞判定で切られる
 *   (5) 残りがある間だけEPOLLOUTが登録され、送り切ると外れる
 *   (6) キューの上限を超えて積もうとすると-1になりpending_evictionが立つ
 * 時刻は全てnowを明示的に渡し、壁時計待ちはしない(プロジェクトの慣習)。
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/infra/network.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"

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

/* 送信側sv[0]・受信側sv[1]のバッファを小さくして、部分書き込みとEAGAINを起こしやすくする */
static void make_pair(int sv[2], int small_buffers)
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }
    if (small_buffers)
    {
        int sz = 4096;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }
}

/* payload先頭4バイトに送り手id、次の4バイトに連番、残りを(id+seq)の下位8bitで埋めた"object"パケット */
static unsigned char *make_packet(uint32_t id, uint32_t seq, size_t payload_len, size_t *out_len)
{
    unsigned char *payload = malloc(payload_len);
    for (size_t i = 0; i < payload_len; i++)
    {
        payload[i] = (unsigned char)(id + seq);
    }
    for (int i = 0; i < 4; i++)
    {
        payload[i] = (unsigned char)(id >> (24 - 8 * i));
        payload[4 + i] = (unsigned char)(seq >> (24 - 8 * i));
    }
    unsigned char *packet = bm_create_packet("object", payload, payload_len, out_len);
    free(payload);
    return packet;
}

struct recv_buf
{
    unsigned char *data;
    size_t len;
    size_t cap;
};

/* 読めるだけノンブロッキングで読む(max_bytes>0ならその量まで)。読めたバイト数を返す */
static size_t drain(int fd, struct recv_buf *rb, size_t max_bytes)
{
    size_t total = 0;
    unsigned char tmp[8192];
    for (;;)
    {
        size_t want = sizeof(tmp);
        if (max_bytes > 0 && max_bytes - total < want)
        {
            want = max_bytes - total;
        }
        if (want == 0)
        {
            break;
        }
        ssize_t n = recv(fd, tmp, want, MSG_DONTWAIT);
        if (n <= 0)
        {
            break;
        }
        if (rb->len + (size_t)n > rb->cap)
        {
            rb->cap = (rb->len + (size_t)n) * 2;
            rb->data = realloc(rb->data, rb->cap);
        }
        memcpy(rb->data + rb->len, tmp, (size_t)n);
        rb->len += (size_t)n;
        total += (size_t)n;
    }
    return total;
}

/* 受信済みバイト列を先頭からパースし、壊れたメッセージが無いか・送り手ごとの連番が
 * 0から順に並んでいるかを確かめる。正しく読めたメッセージ数を返す(壊れていれば-1) */
static int verify_stream(const struct recv_buf *rb, int senders, size_t payload_len)
{
    uint32_t next_seq[8] = {0};
    size_t off = 0;
    int count = 0;
    while (off < rb->len)
    {
        struct bm_message *msg = NULL;
        size_t consumed = 0;
        enum bm_parse_result r = bm_parse_message(rb->data + off, rb->len - off, &msg, &consumed);
        if (r != BM_PARSE_OK)
        {
            fprintf(stderr, "  parse result %d at offset %zu\n", (int)r, off);
            bm_free_message(msg);
            return -1;
        }
        if (msg->length != payload_len)
        {
            bm_free_message(msg);
            return -1;
        }
        uint32_t id = ((uint32_t)msg->payload[0] << 24) | ((uint32_t)msg->payload[1] << 16)
                      | ((uint32_t)msg->payload[2] << 8) | msg->payload[3];
        uint32_t seq = ((uint32_t)msg->payload[4] << 24) | ((uint32_t)msg->payload[5] << 16)
                       | ((uint32_t)msg->payload[6] << 8) | msg->payload[7];
        if (id >= (uint32_t)senders || seq != next_seq[id] || msg->payload[payload_len - 1] != (unsigned char)(id + seq))
        {
            fprintf(stderr, "  unexpected id=%u seq=%u\n", id, seq);
            bm_free_message(msg);
            return -1;
        }
        next_seq[id]++;
        count++;
        off += consumed;
        bm_free_message(msg);
    }
    return count;
}

static void test_immediate_send(void)
{
    int sv[2];
    make_pair(sv, 0);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    size_t len = 0;
    unsigned char *packet = make_packet(0, 0, 100, &len);
    CHECK(bm_network_send(conn, packet, len, 1000) == 0, "(1) send to an idle socket must succeed");
    CHECK(bm_network_queued_bytes(conn) == 0, "(1) an idle socket must be written immediately, nothing left queued");
    CHECK(conn->bytes_sent == len, "(1) bytes_sent must count what was actually written");
    struct recv_buf rb = {0};
    drain(sv[1], &rb, 0);
    CHECK(rb.len == len, "(1) the receiver must get the whole packet right away");
    CHECK(verify_stream(&rb, 1, 100) == 1, "(1) the packet must parse intact");
    free(rb.data);
    free(packet);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
}

static void test_partial_writes_keep_order(void)
{
    int sv[2];
    make_pair(sv, 1);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    const int n = 40;
    const size_t payload_len = 20000;
    for (int i = 0; i < n; i++)
    {
        size_t len = 0;
        unsigned char *packet = make_packet(0, (uint32_t)i, payload_len, &len);
        CHECK(bm_network_send(conn, packet, len, 1000) == 0, "(2) send must succeed while under the limit");
        free(packet);
    }
    CHECK(bm_network_queued_bytes(conn) > 0, "(2) with tiny buffers, part of the data must still be queued");

    struct recv_buf rb = {0};
    for (int guard = 0; guard < 100000; guard++)
    {
        drain(sv[1], &rb, 0);
        CHECK(bm_network_flush(conn, 1001) == 0, "(2) flush must not fail on a healthy socket");
        if (bm_network_queued_bytes(conn) == 0)
        {
            drain(sv[1], &rb, 0);
            break;
        }
    }
    CHECK(bm_network_queued_bytes(conn) == 0, "(2) the queue must drain completely once the receiver reads");
    CHECK(verify_stream(&rb, 1, payload_len) == n, "(2) all packets must arrive intact and in order");
    free(rb.data);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
}

struct writer_args
{
    struct bm_fd_data *conn;
    uint32_t id;
    int count;
    size_t payload_len;
};

static void *writer_thread(void *arg)
{
    struct writer_args *w = arg;
    for (int i = 0; i < w->count; i++)
    {
        size_t len = 0;
        unsigned char *packet = make_packet(w->id, (uint32_t)i, w->payload_len, &len);
        if (bm_network_send(w->conn, packet, len, 1000) != 0)
        {
            fprintf(stderr, "FAIL: (3) writer %u: send %d failed\n", w->id, i);
            failures++;
        }
        free(packet);
    }
    return NULL;
}

static void test_concurrent_senders_do_not_interleave(void)
{
    int sv[2];
    make_pair(sv, 1);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    const int per_thread = 200;
    const size_t payload_len = 3000;
    struct writer_args wa[2] = {{conn, 0, per_thread, payload_len}, {conn, 1, per_thread, payload_len}};
    pthread_t th[2];
    pthread_create(&th[0], NULL, writer_thread, &wa[0]);
    pthread_create(&th[1], NULL, writer_thread, &wa[1]);

    /* 書き手が動いている間も、読み手はこのスレッドで読みながらflushを回す
     * (network_epoll_threadがEPOLLOUTで続きを送るのと同じ並行性) */
    struct recv_buf rb = {0};
    for (int guard = 0; guard < 2000; guard++)
    {
        drain(sv[1], &rb, 0);
        bm_network_flush(conn, 1001);
    }
    pthread_join(th[0], NULL);
    pthread_join(th[1], NULL);
    for (int guard = 0; guard < 100000 && bm_network_queued_bytes(conn) > 0; guard++)
    {
        drain(sv[1], &rb, 0);
        bm_network_flush(conn, 1002);
    }
    drain(sv[1], &rb, 0);
    CHECK(bm_network_queued_bytes(conn) == 0, "(3) the queue must drain completely");
    CHECK(verify_stream(&rb, 2, payload_len) == 2 * per_thread,
          "(3) messages from concurrent senders must never be interleaved or corrupted");
    free(rb.data);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
}

static void test_stall_eviction_and_epollout(void)
{
    int sv[2];
    make_pair(sv, 1);
    int epfd = epoll_create1(0);
    struct bm_peer_registry reg;
    bm_peer_registry_init(&reg);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    const int64_t base = 1000000;
    conn->handshake_complete = 1;
    conn->last_activity = base; /* アイドルping(300秒)に掛からないように */
    CHECK(bm_network_epoll_register(epfd, conn) == 0, "(5) epoll registration must succeed");
    bm_peer_registry_add(&reg, conn);
    CHECK(conn->send_out_armed == 0, "(5) EPOLLOUT must not be armed while nothing is queued");

    for (int i = 0; i < 10; i++)
    {
        size_t len = 0;
        unsigned char *packet = make_packet(0, (uint32_t)i, 20000, &len);
        bm_network_send(conn, packet, len, base);
        free(packet);
    }
    CHECK(bm_network_queued_bytes(conn) > 0, "(4) the peer is not reading, so data must remain queued");
    CHECK(conn->send_out_armed == 1, "(5) EPOLLOUT must be armed while data remains queued");

    struct bm_epoll_thread_args args;
    memset(&args, 0, sizeof(args));
    args.epfd = epfd;
    args.registry = &reg;

    /* 境界ちょうどでは切らない(> で判定) */
    bm_network_idle_sweep(&args, base + BM_SEND_STALL_TIMEOUT_SECONDS);
    CHECK(bm_peer_registry_count(&reg) == 1, "(4) must not evict at exactly the stall timeout");

    /* ゆっくりでも読んでいれば進捗が更新され、切られない。ソケットに溜まっている分だけ読む
     * (キュー側にはまだ大量に残る)。AF_UNIXは送信側に一定の空きができるまで書き込み可能に
     * ならないため、少量だけ読むのではEPOLLOUTが上がらないことがある */
    struct recv_buf rb = {0};
    drain(sv[1], &rb, 0);
    struct epoll_event ev;
    int nev = epoll_wait(epfd, &ev, 1, 0);
    CHECK(nev == 1 && (ev.events & EPOLLOUT) && ev.data.ptr == conn,
          "(5) once the peer reads, EPOLLOUT must be reported for this connection");
    bm_network_flush(conn, base + 100);
    CHECK(bm_network_queued_bytes(conn) > 0, "(4) still data left after reading only a little");
    bm_network_idle_sweep(&args, base + BM_SEND_STALL_TIMEOUT_SECONDS + 50);
    CHECK(bm_peer_registry_count(&reg) == 1, "(4) a slow but progressing peer must not be evicted");

    /* その後まったく進まなければ切られる(connはここでfreeされ、sv[0]もcloseされる) */
    bm_network_idle_sweep(&args, base + 100 + BM_SEND_STALL_TIMEOUT_SECONDS + 1);
    CHECK(bm_peer_registry_count(&reg) == 0, "(4) a peer with no send progress must be evicted after the timeout");

    free(rb.data);
    bm_peer_registry_destroy(&reg);
    close(sv[1]);
    close(epfd);
}

static void test_epollout_disarmed_after_drain(void)
{
    int sv[2];
    make_pair(sv, 1);
    int epfd = epoll_create1(0);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    bm_network_epoll_register(epfd, conn);
    for (int i = 0; i < 5; i++)
    {
        size_t len = 0;
        unsigned char *packet = make_packet(0, (uint32_t)i, 20000, &len);
        bm_network_send(conn, packet, len, 1000);
        free(packet);
    }
    CHECK(conn->send_out_armed == 1, "(5) EPOLLOUT must be armed while data remains");
    struct recv_buf rb = {0};
    for (int guard = 0; guard < 100000 && bm_network_queued_bytes(conn) > 0; guard++)
    {
        drain(sv[1], &rb, 0);
        bm_network_flush(conn, 1001);
    }
    CHECK(conn->send_out_armed == 0, "(5) EPOLLOUT must be disarmed once the queue is empty");
    struct epoll_event ev;
    CHECK(epoll_wait(epfd, &ev, 1, 0) == 0, "(5) no events once drained and nothing to read");
    free(rb.data);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
    close(epfd);
}

static void test_hard_limit(void)
{
    int sv[2];
    make_pair(sv, 1);
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, sv[0]);
    const size_t chunk = 1024 * 1024;
    unsigned char *data = calloc(1, chunk);
    int rc = 0;
    int sends = 0;
    while (rc == 0 && sends < 64)
    {
        rc = bm_network_send(conn, data, chunk, 1000);
        sends++;
    }
    CHECK(rc == -1, "(6) sending beyond the queue limit must fail");
    CHECK(conn->pending_eviction == 1, "(6) exceeding the queue limit must mark the connection for eviction");
    CHECK(bm_network_queued_bytes(conn) <= BM_SEND_QUEUE_HARD_LIMIT_BYTES, "(6) the queue must never exceed the limit");
    free(data);
    bm_fd_data_free(conn);
    close(sv[0]);
    close(sv[1]);
}

int main(void)
{
    test_immediate_send();
    test_partial_writes_keep_order();
    test_concurrent_senders_do_not_interleave();
    test_stall_eviction_and_epollout();
    test_epollout_disarmed_after_drain();
    test_hard_limit();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
