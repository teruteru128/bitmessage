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

int main(void)
{
    test_magic_bytes_switch();
    test_bad_magic_rejected();
    test_bootstrap_seeding();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
