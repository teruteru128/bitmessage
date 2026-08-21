/*
 * infra/protocol.c のtestnet切り替え・infra/peer_manager.cのブートストラップ投入のテスト。
 * 実ネットワークへの接続は非決定的(外部ノードの生死に依存)なためCIには含めず、
 * ここでは決定的に検証できる部分(magic bytes切り替え、不正magicの拒否、シード投入)のみを扱う。
 * 実機での実testnetノードとのハンドシェイク確認は手動で実施済み(DESIGN.md参照)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/infra/peer_manager.h"
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
    test_bootstrap_seeding();
    test_peer_cleanup();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
