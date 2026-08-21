/*
 * infra/protocol.c のtestnet切り替え・infra/peer_manager.cのブートストラップ投入のテスト。
 * 実ネットワークへの接続は非決定的(外部ノードの生死に依存)なためCIには含めず、
 * ここでは決定的に検証できる部分(magic bytes切り替え、不正magicの拒否、シード投入)のみを扱う。
 * 実機での実testnetノードとのハンドシェイク確認は手動で実施済み(DESIGN.md参照)。
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/peer_manager.h"
#include "../src/infra/network.h"
#include "../src/infra/protocol.h"

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

static void test_magic_bytes_switch(void)
{
    bm_protocol_set_testnet(0);
    CHECK(bm_protocol_is_testnet() == 0, "mainnet mode flag");
    unsigned char mainnet_magic[4];
    memcpy(mainnet_magic, bm_magicbytes, 4);
    CHECK(memcmp(mainnet_magic, "\xe9\xbe\xb4\xd9", 4) == 0, "mainnet magic bytes value");

    bm_protocol_set_testnet(1);
    CHECK(bm_protocol_is_testnet() == 1, "testnet mode flag");
    CHECK(memcmp(bm_magicbytes, "\xfb\x11\x09\x07", 4) == 0, "testnet magic bytes value");
    CHECK(memcmp(bm_magicbytes, mainnet_magic, 4) != 0, "testnet magic differs from mainnet");

    bm_protocol_set_testnet(0); /* 後続テストへの影響を避けるため既定へ戻す */

    printf("OK: magic bytes switch(mainnet/testnet)\n");
}

static void test_bad_magic_rejected(void)
{
    bm_protocol_set_testnet(0); /* mainnetモード */

    /* testnetのmagic bytesで組み立てたヘッダはmainnetモードでは拒否されるはず */
    unsigned char data[24] = {0};
    memcpy(data, "\xfb\x11\x09\x07", 4); /* testnet magic */
    memcpy(data + 4, "verack", 6);
    /* length=0, checksum=empty_payload_checksum */
    memcpy(data + 20, bm_empty_payload_checksum, 4);

    struct bm_message *msg = NULL;
    size_t consumed = 0;
    enum bm_parse_result result = bm_parse_message(data, sizeof(data), &msg, &consumed);
    CHECK(result == BM_PARSE_BAD_MAGIC, "wrong-network magic bytes rejected");
    CHECK(consumed == 1, "bad magic consumes exactly 1 byte for resync");

    /* 正しいmagic bytesなら通ること(対照実験) */
    memcpy(data, bm_magicbytes, 4);
    result = bm_parse_message(data, sizeof(data), &msg, &consumed);
    CHECK(result == BM_PARSE_OK, "correct magic bytes accepted");
    if (result == BM_PARSE_OK)
    {
        bm_free_message(msg);
    }

    printf("OK: magic byte validation in bm_parse_message\n");
}

static void test_oversized_length_rejected(void)
{
    bm_protocol_set_testnet(0); /* mainnetモード */

    /* §11 DoS上限の見直し: lengthフィールドがBM_MAX_MESSAGE_LENGTHを超える申告は、
     * 実データが揃うのを待たず(=ヘッダ24byteだけ届いた時点で)即座に拒否されるはず */
    unsigned char header[BM_MESSAGE_HEADER_SIZE] = {0};
    memcpy(header, bm_magicbytes, 4);
    memcpy(header + 4, "object", 6);
    uint32_t huge_length = BM_MAX_MESSAGE_LENGTH + 1;
    header[16] = (unsigned char)((huge_length >> 24) & 0xff);
    header[17] = (unsigned char)((huge_length >> 16) & 0xff);
    header[18] = (unsigned char)((huge_length >> 8) & 0xff);
    header[19] = (unsigned char)(huge_length & 0xff);
    /* checksumは検証されない(lengthチェックの方が先に走るはず)ので適当な値のままでよい */

    struct bm_message *msg = NULL;
    size_t consumed = 0;
    enum bm_parse_result result = bm_parse_message(header, sizeof(header), &msg, &consumed);
    CHECK(result == BM_PARSE_MESSAGE_TOO_LARGE,
          "a declared length exceeding BM_MAX_MESSAGE_LENGTH should be rejected immediately, "
          "even though only the 24-byte header (no payload) has arrived");

    /* 対照実験: ちょうど上限ならINCOMPLETE(データ不足)として正常に扱われる(拒否されない) */
    uint32_t max_length = BM_MAX_MESSAGE_LENGTH;
    header[16] = (unsigned char)((max_length >> 24) & 0xff);
    header[17] = (unsigned char)((max_length >> 16) & 0xff);
    header[18] = (unsigned char)((max_length >> 8) & 0xff);
    header[19] = (unsigned char)(max_length & 0xff);
    result = bm_parse_message(header, sizeof(header), &msg, &consumed);
    CHECK(result == BM_PARSE_INCOMPLETE, "a declared length exactly at the limit should not be rejected");

    printf("OK: oversized declared message length rejected before buffering payload data\n");
}

struct drain_thread_args
{
    int fd;
    unsigned char *received; /* 呼び出し側でmalloc、受信データを書き込む */
    size_t expected_len;
    size_t received_len; /* out */
};

/* 受信側を模す: 少しずつ・間隔を空けて読むことで、送信側(bm_network_write_all)が
 * 複数回のEAGAINを経て初めて送り切れる状況を作る */
static void *drain_thread_fn(void *arg)
{
    struct drain_thread_args *a = arg;
    while (a->received_len < a->expected_len)
    {
        size_t chunk = 4096;
        if (chunk > a->expected_len - a->received_len)
        {
            chunk = a->expected_len - a->received_len;
        }
        ssize_t n = read(a->fd, a->received + a->received_len, chunk);
        if (n <= 0)
        {
            break;
        }
        a->received_len += (size_t)n;
        usleep(2000); /* 送信側に複数回EAGAINを経験させるため、読み取りペースを意図的に落とす */
    }
    return NULL;
}

static void test_network_write_all(void)
{
    /* §11 部分書き込み対策: bm_network_write_allが非blockingソケットへの
     * 短い書き込み/EAGAINを正しくループして処理し、最終的にペイロード全体を
     * バイト単位で欠落なく送り切れることを確認する */
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair for write_all test");

    int flags = fcntl(fds[0], F_GETFL, 0);
    fcntl(fds[0], F_SETFL, flags | O_NONBLOCK); /* peer_connector.cが接続後もO_NONBLOCKのまま
                                                   * epollへ渡す実運用と同じ状態を再現する */

    const size_t payload_len = 1024 * 1024; /* 1MiB。ソケットバッファより確実に大きくし、
                                              * 1回のwrite()では絶対に送り切れないようにする */
    unsigned char *payload = malloc(payload_len);
    for (size_t i = 0; i < payload_len; i++)
    {
        payload[i] = (unsigned char)(i % 256); /* 欠落・順序入れ替わりを検出しやすいパターン */
    }

    struct drain_thread_args drain_args;
    drain_args.fd = fds[1];
    drain_args.received = malloc(payload_len);
    drain_args.expected_len = payload_len;
    drain_args.received_len = 0;
    pthread_t drain_thread;
    CHECK(pthread_create(&drain_thread, NULL, drain_thread_fn, &drain_args) == 0, "start drain thread");

    int rc = bm_network_write_all(fds[0], payload, payload_len, 30);
    CHECK(rc == 0, "bm_network_write_all should eventually send the entire 1MiB payload");

    pthread_join(drain_thread, NULL);
    CHECK(drain_args.received_len == payload_len, "receiver should have gotten every byte");
    CHECK(memcmp(payload, drain_args.received, payload_len) == 0,
          "received payload should exactly match what was sent (no corruption/reordering across "
          "the multiple partial writes)");

    free(payload);
    free(drain_args.received);
    close(fds[0]);
    close(fds[1]);

    /* 対照実験: 受信側が全く読まない(相手が詰まっている)場合、短いタイムアウトで
     * ちゃんと諦めて-1を返すこと(無限に待ち続けない) */
    int fds2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2) == 0, "socketpair for timeout test");
    int flags2 = fcntl(fds2[0], F_GETFL, 0);
    fcntl(fds2[0], F_SETFL, flags2 | O_NONBLOCK);
    unsigned char big_payload[1024 * 1024];
    memset(big_payload, 0, sizeof(big_payload));
    int rc2 = bm_network_write_all(fds2[0], big_payload, sizeof(big_payload), 1);
    CHECK(rc2 != 0, "bm_network_write_all should give up (not hang forever) when the peer never reads");
    close(fds2[0]);
    close(fds2[1]);

    printf("OK: bm_network_write_all handles partial writes/EAGAIN correctly and times out when stuck\n");
}

static void test_bootstrap_seeding(void)
{
    const char *db_path = "test_network_testnet_peers.db";
    unlink(db_path);
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK || bm_peer_manager_init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", db_path);
        exit(EXIT_FAILURE);
    }

    CHECK(bm_peer_manager_seed_bootstrap(db, 1) == 0, "seed testnet bootstrap nodes");

    struct bm_peer_entry results[32];
    int count = 0;
    CHECK(bm_peer_manager_list_top(db, 1, results, 32, &count) == 0, "list seeded peers");
    CHECK(count == 2, "testnet seed count should be 2");

    int found_578 = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(results[i].ip_address, "5.78.198.100") == 0 && results[i].port == 8444)
        {
            found_578 = 1;
        }
    }
    CHECK(found_578, "known testnet seed node 5.78.198.100:8444 present");

    /* 既にデータがある状態で呼んでも増えない(上書きしない) */
    CHECK(bm_peer_manager_seed_bootstrap(db, 1) == 0, "seed again is a no-op");
    count = 0;
    bm_peer_manager_list_top(db, 1, results, 32, &count);
    CHECK(count == 2, "seeding again does not duplicate entries");

    sqlite3_close(db);
    unlink(db_path);

    printf("OK: bootstrap seed node insertion\n");
}

static void test_observed_nodes_file(void)
{
    /* §11「開発者が確認した身元不明のつながる可能性のあるノード」リスト
     * (seeds/observed_nodes.txt)の読み込み確認。#コメント・空行・不正な行は無視し、
     * 有効な行だけをsource='observed_seed'で登録することを確認する */
    const char *db_path = "test_network_testnet_observed_peers.db";
    unlink(db_path);
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK || bm_peer_manager_init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", db_path);
        exit(EXIT_FAILURE);
    }

    /* ファイル無しの場合は0を返すだけでエラーにならないこと */
    CHECK(bm_peer_manager_load_observed_nodes(db, "test_observed_nodes_does_not_exist.txt") == 0,
          "loading a nonexistent observed-nodes file should be a harmless no-op");

    const char *list_path = "test_observed_nodes.txt";
    FILE *f = fopen(list_path, "w");
    CHECK(f != NULL, "create temporary observed-nodes file");
    if (f != NULL)
    {
        fprintf(f, "# comment line, should be ignored\n");
        fprintf(f, "\n"); /* 空行 */
        fprintf(f, "203.0.113.10 8444\n");
        fprintf(f, "  203.0.113.11 8445\n"); /* 先頭の空白も許容 */
        fprintf(f, "not-a-valid-line\n");     /* portが無い不正な行 */
        fprintf(f, "203.0.113.12 0\n");       /* port範囲外 */
        fprintf(f, "203.0.113.13 8446\n");
        fclose(f);
    }

    int loaded = bm_peer_manager_load_observed_nodes(db, list_path);
    CHECK(loaded == 3, "should load exactly the 3 well-formed lines");

    struct bm_peer_entry results[32];
    int count = 0;
    CHECK(bm_peer_manager_list_top(db, 1, results, 32, &count) == 0, "list observed peers");
    CHECK(count == 3, "3 peers should be registered from the observed-nodes file");
    for (int i = 0; i < count; i++)
    {
        CHECK(strcmp(results[i].source, "observed_seed") == 0,
              "observed-nodes entries should use the 'observed_seed' source label");
    }

    unlink(list_path);
    sqlite3_close(db);
    unlink(db_path);

    printf("OK: observed-nodes file loading\n");
}

static void seed_cleanup_test_peer(sqlite3 *db, const char *ip, int64_t last_seen, double rating)
{
    struct bm_peer_entry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.ip_address, ip, sizeof(entry.ip_address) - 1);
    entry.port = 8444;
    entry.stream = 1;
    entry.services = 1;
    entry.last_seen = last_seen;
    entry.rating = rating;
    strncpy(entry.source, "test", sizeof(entry.source) - 1);
    CHECK(bm_peer_manager_upsert(db, &entry) == 0, "seed test peer for cleanup test");
}

static void test_peer_cleanup(void)
{
    const char *db_path = "test_network_testnet_cleanup_peers.db";
    unlink(db_path);
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK || bm_peer_manager_init_schema(db) != 0)
    {
        fprintf(stderr, "FATAL: could not open/init %s\n", db_path);
        exit(EXIT_FAILURE);
    }

    /* §11 PyBitmessage(network/knownnodes.pyのcleanupKnownNodes)準拠の2条件:
     * (1) 28日以上経過はratingを問わず削除、(2) 3時間以上経過かつrating<=-0.5を削除 */
    int64_t now = 2000000000; /* 固定基準時刻(テストの決定性のため実時刻に依存しない) */
    seed_cleanup_test_peer(db, "203.0.113.1", now - (29 * 24 * 60 * 60), 1.0);  /* 28日超、rating高 -> 削除 */
    seed_cleanup_test_peer(db, "203.0.113.2", now - (4 * 60 * 60), -0.5);       /* 3時間超、rating<=-0.5 -> 削除 */
    seed_cleanup_test_peer(db, "203.0.113.3", now - (4 * 60 * 60), -0.4);       /* 3時間超だがrating閾値内 -> 残る */
    seed_cleanup_test_peer(db, "203.0.113.4", now - (2 * 60 * 60), -1.0);       /* rating低いがまだ3時間未満 -> 残る */
    seed_cleanup_test_peer(db, "203.0.113.5", now - (1 * 60 * 60), 1.0);        /* 新しくrating高 -> 残る */

    int deleted = bm_peer_manager_cleanup(db, now);
    CHECK(deleted == 2, "cleanup should remove exactly the 2 stale/low-rating peers");

    struct bm_peer_entry results[32];
    int count = 0;
    CHECK(bm_peer_manager_list_top(db, 1, results, 32, &count) == 0, "list peers after cleanup");
    CHECK(count == 3, "3 peers should remain after cleanup");

    int found1 = 0, found2 = 0, found3 = 0, found4 = 0, found5 = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(results[i].ip_address, "203.0.113.1") == 0) found1 = 1;
        if (strcmp(results[i].ip_address, "203.0.113.2") == 0) found2 = 1;
        if (strcmp(results[i].ip_address, "203.0.113.3") == 0) found3 = 1;
        if (strcmp(results[i].ip_address, "203.0.113.4") == 0) found4 = 1;
        if (strcmp(results[i].ip_address, "203.0.113.5") == 0) found5 = 1;
    }
    CHECK(!found1, "28-day-old peer should have been deleted regardless of its high rating");
    CHECK(!found2, "3-hour-old peer at the forget-rating threshold should have been deleted");
    CHECK(found3, "3-hour-old peer just above the forget-rating threshold should survive");
    CHECK(found4, "low-rating peer younger than 3 hours should survive");
    CHECK(found5, "fresh high-rating peer should survive");

    sqlite3_close(db);
    unlink(db_path);

    printf("OK: peers.db cleanup of stale/low-rating peers\n");
}

int main(void)
{
    test_magic_bytes_switch();
    test_bad_magic_rejected();
    test_oversized_length_rejected();
    test_network_write_all();
    test_bootstrap_seeding();
    test_observed_nodes_file();
    test_peer_cleanup();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
