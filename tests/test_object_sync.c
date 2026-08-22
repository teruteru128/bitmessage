/*
 * infra/object_sync.c のテスト。
 * - inv受信 -> 未所持hashについてgetdataを送り返す
 * - object受信 -> object_pool.dbへ保存、重複排除
 * - getdata受信 -> object_pool.dbにあれば同じ接続へobjectを返す
 * - ack往復: send_pipeline.cで実際にmsgを組み立てて受信させ、trial_decrypt->inbox保存と
 *   埋め込みack(fullAckPayload)のobject_pool.dbへの取り込みを確認。さらにそのack自体を
 *   "object"として受信させ、sent.statusがackreceivedへ遷移することを確認する
 * - 期限切れobjectのGC
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/message_builder.h"
#include "../src/core/messages_store.h"
#include "../src/core/send_pipeline.h"
#include "../src/common/varint.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/core/peer_manager.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"

#define TEST_OBJECT_POOL_DB "test_object_sync_pool.db"
#define TEST_IDENTITY_DB "test_object_sync_identity.db"
#define TEST_MESSAGES_DB "test_object_sync_messages.db"
#define TEST_PEERS_DB "test_object_sync_peers.db"

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

/* 適当なgetpubkeyオブジェクトを実PoW付きで1個作る(inv/getdata/dedupテスト用)。
 * §11のPoW検証(受信側)はexpires_time-nowからttlを再計算するため、expires_timeは
 * 固定の遠い未来ではなくnow+ttlにし、PoW計算時のttlと一致させる必要がある。
 * 難易度はネットワーク既定の最低値(1000,1000、object_pow_is_valid参照)を満たす必要がある */
static unsigned char *build_test_object(size_t *out_len)
{
    unsigned char ripe[20];
    memset(ripe, 0x42, sizeof(ripe));
    uint64_t ttl = 3600;
    uint64_t expires_time = (uint64_t)time(NULL) + ttl;
    size_t payload_len = 0;
    unsigned char *payload = bm_build_getpubkey(4, 1, ripe, expires_time, &payload_len);
    uint64_t target = bm_pow_get_target(payload_len, ttl, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);

    *out_len = object_len;
    return object;
}

/* fdから1個のP2Pメッセージを読み込む(テスト用、ブロッキング前提の小さいメッセージのみ) */
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
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    sqlite3 *peers_db = open_fresh_db(TEST_PEERS_DB, bm_peer_manager_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);

    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, peers_db, &kr, &registry, NULL);

    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
    CHECK(conn != NULL, "bm_fd_data_new");
    bm_peer_registry_add(&registry, conn);

    /* 接続レジストリ経由のinv broadcastを検証するための2本目の"peer" */
    int fds2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2) == 0, "socketpair for second peer");
    struct bm_fd_data *conn2 = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds2[0]);
    CHECK(conn2 != NULL, "bm_fd_data_new for second peer");
    bm_peer_registry_add(&registry, conn2);

    /* --- 1. inv受信 -> 未所持hashについてgetdataを送り返す --- */
    unsigned char unknown_hashes[2][32];
    memset(unknown_hashes[0], 0x11, 32);
    memset(unknown_hashes[1], 0x22, 32);

    size_t inv_len = 0;
    unsigned char *inv_packet = bm_create_inventory_message("inv", unknown_hashes, 2, &inv_len);
    struct bm_message *inv_msg = NULL;
    size_t inv_consumed = 0;
    CHECK(bm_parse_message(inv_packet, inv_len, &inv_msg, &inv_consumed) == BM_PARSE_OK, "parse inv packet");
    free(inv_packet);

    bm_object_sync_dispatch(conn, inv_msg, &ctx);
    bm_free_message(inv_msg);

    struct bm_message *getdata_reply = read_one_message(fds[1]);
    CHECK(getdata_reply != NULL, "should receive a getdata reply for unknown inv items");
    if (getdata_reply != NULL)
    {
        CHECK(strncmp(getdata_reply->command, "getdata", 12) == 0, "reply command should be getdata");
        struct bm_inventory_message parsed_getdata;
        CHECK(bm_parse_inventory_message(getdata_reply->payload, getdata_reply->length, &parsed_getdata) == 0,
              "parse getdata reply payload");
        CHECK(parsed_getdata.count == 2, "getdata should request both unknown hashes");
        if (parsed_getdata.count == 2)
        {
            CHECK((memcmp(parsed_getdata.items[0], unknown_hashes[0], 32) == 0
                   && memcmp(parsed_getdata.items[1], unknown_hashes[1], 32) == 0)
                      || (memcmp(parsed_getdata.items[0], unknown_hashes[1], 32) == 0
                          && memcmp(parsed_getdata.items[1], unknown_hashes[0], 32) == 0),
                  "getdata items should exactly match the requested hash bytes (order-independent)");
        }
        bm_free_inventory_message(&parsed_getdata);
        bm_free_message(getdata_reply);
    }

    /* --- 1b. §11: ネットワーク既定の最低難易度(1000,1000)を満たさないobjectは拒否される --- */
    {
        unsigned char weak_ripe[20];
        memset(weak_ripe, 0x99, sizeof(weak_ripe));
        uint64_t weak_ttl = 3600;
        size_t weak_payload_len = 0;
        unsigned char *weak_payload =
            bm_build_getpubkey(4, 1, weak_ripe, (uint64_t)time(NULL) + weak_ttl, &weak_payload_len);
        /* わざと最低難易度未満(50,50)でPoWする */
        uint64_t weak_target = bm_pow_get_target(weak_payload_len, weak_ttl, 50, 50);
        uint64_t weak_nonce = bm_pow_run(weak_payload, weak_payload_len, weak_target);
        size_t weak_object_len = 8 + weak_payload_len;
        unsigned char *weak_object = malloc(weak_object_len);
        for (int i = 0; i < 8; i++)
        {
            weak_object[i] = (unsigned char)((weak_nonce >> (56 - 8 * i)) & 0xff);
        }
        memcpy(weak_object + 8, weak_payload, weak_payload_len);
        free(weak_payload);

        struct bm_message weak_msg;
        memset(&weak_msg, 0, sizeof(weak_msg));
        memcpy(weak_msg.command, "object", 6);
        weak_msg.length = (uint32_t)weak_object_len;
        weak_msg.payload = weak_object;
        bm_object_sync_dispatch(conn, &weak_msg, &ctx);
        free(weak_object);

        sqlite3_stmt *weak_count_stmt = NULL;
        sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects;", -1, &weak_count_stmt, NULL);
        sqlite3_step(weak_count_stmt);
        int weak_count = sqlite3_column_int(weak_count_stmt, 0);
        sqlite3_finalize(weak_count_stmt);
        CHECK(weak_count == 0, "object with insufficient PoW should be rejected, not stored");
    }

    /* --- 2. object受信 -> object_pool.dbへ保存、重複排除 --- */
    size_t object_len = 0;
    unsigned char *object = build_test_object(&object_len);
    {
        struct bm_object_header hdr;
        CHECK(bm_object_parse_header(object, object_len, &hdr) == 0, "parse test object header");
    }

    struct bm_message object_msg;
    memset(&object_msg, 0, sizeof(object_msg));
    memcpy(object_msg.command, "object", 6);
    object_msg.length = (uint32_t)object_len;
    object_msg.payload = object;

    bm_object_sync_dispatch(conn, &object_msg, &ctx);

    /* --- 2a. 接続レジストリ経由のinv broadcast: conn(受信元)以外のpeer(conn2)へだけ届く --- */
    unsigned char expected_hash[32];
    bm_inventory_hash(object, object_len, expected_hash);

    struct bm_message *broadcast_inv = read_one_message(fds2[1]);
    CHECK(broadcast_inv != NULL, "conn2 should receive an inv broadcast for the newly received object");
    if (broadcast_inv != NULL)
    {
        CHECK(strncmp(broadcast_inv->command, "inv", 12) == 0, "broadcast command should be inv");
        struct bm_inventory_message parsed_broadcast;
        CHECK(bm_parse_inventory_message(broadcast_inv->payload, broadcast_inv->length, &parsed_broadcast) == 0,
              "parse broadcast inv payload");
        CHECK(parsed_broadcast.count == 1, "broadcast inv should announce exactly the new object");
        if (parsed_broadcast.count == 1)
        {
            CHECK(memcmp(parsed_broadcast.items[0], expected_hash, 32) == 0,
                  "broadcast inv hash should match the received object's inventory hash");
        }
        bm_free_inventory_message(&parsed_broadcast);
        bm_free_message(broadcast_inv);
    }

    /* object_store経由の重複排除確認: 同じobjectをもう一度dispatchしても2重に保存されない
     * (=常に1件)ことをCOUNT(*)で見る */
    sqlite3_stmt *count_stmt = NULL;
    sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects;", -1, &count_stmt, NULL);
    sqlite3_step(count_stmt);
    int obj_count_1 = sqlite3_column_int(count_stmt, 0);
    sqlite3_finalize(count_stmt);
    CHECK(obj_count_1 == 1, "object should be stored exactly once after first receipt");

    /* 重複受信 */
    bm_object_sync_dispatch(conn, &object_msg, &ctx);
    sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects;", -1, &count_stmt, NULL);
    sqlite3_step(count_stmt);
    int obj_count_2 = sqlite3_column_int(count_stmt, 0);
    sqlite3_finalize(count_stmt);
    CHECK(obj_count_2 == 1, "duplicate object receipt should not create a second row");

    /* --- 3. getdata受信 -> 保有しているobjectを返す --- */
    unsigned char hash_of_test_object[32];
    sqlite3_stmt *hash_stmt = NULL;
    sqlite3_prepare_v2(object_pool_db, "SELECT hash FROM objects LIMIT 1;", -1, &hash_stmt, NULL);
    CHECK(sqlite3_step(hash_stmt) == SQLITE_ROW, "fetch stored object hash");
    memcpy(hash_of_test_object, sqlite3_column_blob(hash_stmt, 0), 32);
    sqlite3_finalize(hash_stmt);

    size_t getdata_req_len = 0;
    unsigned char req_hashes[1][32];
    memcpy(req_hashes[0], hash_of_test_object, 32);
    unsigned char *getdata_req_packet = bm_create_inventory_message("getdata", req_hashes, 1, &getdata_req_len);
    struct bm_message *getdata_req_msg = NULL;
    size_t getdata_req_consumed = 0;
    CHECK(bm_parse_message(getdata_req_packet, getdata_req_len, &getdata_req_msg, &getdata_req_consumed) == BM_PARSE_OK,
          "parse getdata request packet");
    free(getdata_req_packet);

    bm_object_sync_dispatch(conn, getdata_req_msg, &ctx);
    bm_free_message(getdata_req_msg);

    struct bm_message *object_reply = read_one_message(fds[1]);
    CHECK(object_reply != NULL, "should receive an object reply for getdata");
    if (object_reply != NULL)
    {
        CHECK(strncmp(object_reply->command, "object", 12) == 0, "reply command should be object");
        CHECK(object_reply->length == object_len, "replied object length matches stored object");
        CHECK(memcmp(object_reply->payload, object, object_len) == 0, "replied object content matches stored object");
        bm_free_message(object_reply);
    }
    free(object);

    /* --- 4. ack往復: 実際にsend_pipelineでmsgを組み立てて受信させる --- */
    struct bm_generated_address sender_gen;
    CHECK(bm_address_generate_deterministic("object_sync test sender", 1, &sender_gen) == 0, "gen sender addr");
    char *sender_address = bm_address_encode(4, 1, sender_gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(identity_db, sender_address, "sender", 4, 1,
                                      sender_gen.pub_signing, sender_gen.pub_encryption,
                                      sender_gen.priv_signing, sender_gen.priv_encryption,
                                      "sender pass", 1000, 1000) == 0,
          "create sender identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, sender_address, "sender pass") == 0, "unlock sender");

    struct bm_generated_address recv_gen;
    CHECK(bm_address_generate_deterministic("object_sync test receiver", 1, &recv_gen) == 0, "gen receiver addr");
    char *recv_address = bm_address_encode(4, 1, recv_gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(identity_db, recv_address, "receiver", 4, 1,
                                      recv_gen.pub_signing, recv_gen.pub_encryption,
                                      recv_gen.priv_signing, recv_gen.priv_encryption,
                                      "receiver pass", 1000, 1000) == 0,
          "create receiver identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, recv_address, "receiver pass") == 0, "unlock receiver");

    unsigned char *msg_object = NULL;
    size_t msg_object_len = 0;
    CHECK(bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                         recv_gen.pub_encryption, "ack test subject", "ack test body",
                                         3600, 1, NULL, (int64_t)time(NULL) + BM_RESEND_INITIAL_INTERVAL_SECONDS,
                                         &msg_object, &msg_object_len) == 0,
          "send_pipeline_send_message for ack round-trip test");

    struct bm_message incoming_msg;
    memset(&incoming_msg, 0, sizeof(incoming_msg));
    memcpy(incoming_msg.command, "object", 6);
    incoming_msg.length = (uint32_t)msg_object_len;
    incoming_msg.payload = msg_object;

    bm_object_sync_dispatch(conn, &incoming_msg, &ctx);
    free(msg_object);

    /* 4a. 復号されinboxへ保存されているはず */
    struct bm_inbox_message *inbox_list = NULL;
    size_t inbox_count = 0;
    CHECK(bm_messages_store_list_inbox(messages_db, NULL, &inbox_list, &inbox_count) == 0, "list inbox");
    CHECK(inbox_count == 1, "inbox should have exactly 1 message after receiving msg object");
    if (inbox_count == 1)
    {
        CHECK(strcmp(inbox_list[0].to_address, recv_address) == 0, "inbox message to_address");
        CHECK(strcmp(inbox_list[0].from_address, sender_address) == 0, "inbox message from_address");
    }
    bm_inbox_message_list_free(inbox_list, inbox_count);

    /* 4b. 埋め込まれていたfullAckPayloadがobject_pool.dbへ取り込まれているはず(sent.ack_dataと一致) */
    sqlite3_stmt *ack_stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT ack_data, status FROM sent WHERE to_address = ?1;", -1, &ack_stmt, NULL);
    sqlite3_bind_text(ack_stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(ack_stmt) == SQLITE_ROW, "fetch sent row for ack test");
    unsigned char ack_data[4096];
    int ack_data_len = sqlite3_column_bytes(ack_stmt, 0);
    CHECK(ack_data_len > 0 && (size_t)ack_data_len <= sizeof(ack_data), "ack_data length sane");
    memcpy(ack_data, sqlite3_column_blob(ack_stmt, 0), (size_t)ack_data_len);
    const char *status_before = (const char *)sqlite3_column_text(ack_stmt, 1);
    CHECK(strcmp(status_before, "sent") == 0, "status should still be 'sent' before ack arrives");
    sqlite3_finalize(ack_stmt);

    /* object_storeにack_dataそのもの(nonce込みobject)が保存されているはず */
    sqlite3_stmt *ack_pool_stmt = NULL;
    sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects WHERE payload = ?1;", -1, &ack_pool_stmt, NULL);
    sqlite3_bind_blob(ack_pool_stmt, 1, ack_data, ack_data_len, SQLITE_TRANSIENT);
    sqlite3_step(ack_pool_stmt);
    int ack_in_pool = sqlite3_column_int(ack_pool_stmt, 0);
    sqlite3_finalize(ack_pool_stmt);
    CHECK(ack_in_pool == 1, "receiver's object_pool should now contain the ack object");

    /* 4c. そのack自体を"object"としてsenderが受信した体で流すと、sent.statusがackreceivedになる */
    size_t ack_packet_len = 0;
    unsigned char *ack_packet = bm_create_packet("object", ack_data, (size_t)ack_data_len, &ack_packet_len);
    struct bm_message *ack_wire_msg = NULL;
    size_t ack_wire_consumed = 0;
    CHECK(bm_parse_message(ack_packet, ack_packet_len, &ack_wire_msg, &ack_wire_consumed) == BM_PARSE_OK,
          "parse ack object wire packet");
    free(ack_packet);

    bm_object_sync_dispatch(conn, ack_wire_msg, &ctx);
    bm_free_message(ack_wire_msg);

    sqlite3_prepare_v2(messages_db, "SELECT status FROM sent WHERE to_address = ?1;", -1, &ack_stmt, NULL);
    sqlite3_bind_text(ack_stmt, 1, recv_address, -1, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(ack_stmt) == SQLITE_ROW, "fetch sent row after ack delivery");
    const char *status_after = (const char *)sqlite3_column_text(ack_stmt, 0);
    CHECK(status_after != NULL && strcmp(status_after, "ackreceived") == 0,
          "status should become 'ackreceived' after the ack object is received");
    sqlite3_finalize(ack_stmt);

    free(sender_address);
    free(recv_address);

    /* --- 5. 期限切れobjectのGC --- */
    unsigned char expired_hash[32];
    memset(expired_hash, 0x99, 32);
    unsigned char dummy_payload[4] = {0, 0, 0, 0};
    CHECK(bm_object_store_insert(object_pool_db, expired_hash, 0, 1, dummy_payload, sizeof(dummy_payload),
                                  /*expires_time=*/1, /*received_time=*/1) == 0,
          "insert already-expired dummy object");
    int deleted = bm_object_sync_gc(&ctx, /*now=*/1000000000);
    CHECK(deleted >= 1, "gc should remove at least the expired dummy object");
    CHECK(bm_object_store_has(object_pool_db, expired_hash) == 0, "expired object should be gone after gc");

    /* --- 6. addr受信 -> peers.dbへ登録(§11)。ルーティング可能なホストは登録され、
     * private/loopback等はフィルタリングされて登録されないことを確認する --- */
    {
        /* entryを1件分組み立てるヘルパー相当(ローカル配列に直接書き込む) */
        unsigned char ipv4_routable[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 42};
        unsigned char ipv4_private[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1};
        /* §11 2026-08-23: 素のIPv6(非IPv4-mapped)は一律filterするようにした。ここでは
         * loopback/ULA/link-local/multicastのいずれにも該当しない「一見ルーティング可能に
         * 見えるグローバルユニキャスト範囲」のIPv6を用意し、そのような値でも登録されない
         * ことを確認する(実際にpeers.dbへ混入していたgarbageな値もこの範囲を運良く
         * すり抜けていた)。 */
        unsigned char ipv6_global_unicast[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88};
        unsigned char entries[3][38];
        const unsigned char *ips[3] = {ipv4_routable, ipv4_private, ipv6_global_unicast};
        uint64_t addr_time = (uint64_t)time(NULL);
        for (int e = 0; e < 3; e++)
        {
            unsigned char *p = entries[e];
            for (int i = 0; i < 8; i++)
            {
                p[i] = (unsigned char)((addr_time >> (56 - 8 * i)) & 0xff);
            }
            p += 8;
            uint32_t stream = 1;
            for (int i = 0; i < 4; i++)
            {
                p[i] = (unsigned char)((stream >> (24 - 8 * i)) & 0xff);
            }
            p += 4;
            uint64_t services = 1;
            for (int i = 0; i < 8; i++)
            {
                p[i] = (unsigned char)((services >> (56 - 8 * i)) & 0xff);
            }
            p += 8;
            memcpy(p, ips[e], 16);
            p += 16;
            uint16_t port = htons(8444);
            memcpy(p, &port, 2);
        }

        unsigned char addr_payload[1 + sizeof(entries)];
        bm_varint_encode(addr_payload, 3);
        memcpy(addr_payload + bm_varint_size(3), entries, sizeof(entries));
        size_t addr_payload_len = bm_varint_size(3) + sizeof(entries);

        size_t addr_packet_len = 0;
        unsigned char *addr_packet = bm_create_packet("addr", addr_payload, addr_payload_len, &addr_packet_len);
        struct bm_message *addr_wire_msg = NULL;
        size_t addr_consumed = 0;
        CHECK(bm_parse_message(addr_packet, addr_packet_len, &addr_wire_msg, &addr_consumed) == BM_PARSE_OK,
              "parse addr wire packet");
        free(addr_packet);

        bm_object_sync_dispatch(conn, addr_wire_msg, &ctx);
        bm_free_message(addr_wire_msg);

        sqlite3_stmt *addr_stmt = NULL;
        sqlite3_prepare_v2(peers_db,
                            "SELECT port, source FROM hosts WHERE ip_address = '203.0.113.42';", -1,
                            &addr_stmt, NULL);
        CHECK(sqlite3_step(addr_stmt) == SQLITE_ROW, "routable addr entry should be registered into peers.db");
        CHECK(sqlite3_column_int(addr_stmt, 0) == 8444, "registered port should match addr entry");
        const char *addr_source = (const char *)sqlite3_column_text(addr_stmt, 1);
        CHECK(addr_source != NULL && strcmp(addr_source, "addr_msg") == 0,
              "registered source should be 'addr_msg'");
        sqlite3_finalize(addr_stmt);

        sqlite3_stmt *private_stmt = NULL;
        sqlite3_prepare_v2(peers_db, "SELECT COUNT(*) FROM hosts WHERE ip_address = '192.168.1.1';", -1,
                            &private_stmt, NULL);
        CHECK(sqlite3_step(private_stmt) == SQLITE_ROW, "private addr count query should return a row");
        CHECK(sqlite3_column_int(private_stmt, 0) == 0,
              "private (192.168.0.0/16) addr entry should be filtered out, not registered");
        sqlite3_finalize(private_stmt);

        sqlite3_stmt *ipv6_stmt = NULL;
        sqlite3_prepare_v2(peers_db, "SELECT COUNT(*) FROM hosts WHERE ip_address = '2001:4860:4860::8888';",
                            -1, &ipv6_stmt, NULL);
        CHECK(sqlite3_step(ipv6_stmt) == SQLITE_ROW, "ipv6 addr count query should return a row");
        CHECK(sqlite3_column_int(ipv6_stmt, 0) == 0,
              "raw (non-IPv4-mapped) IPv6 addr entry should always be filtered out, even if it looks like "
              "a routable global unicast address");
        sqlite3_finalize(ipv6_stmt);
    }

    /* --- 7. onionpeer object(BM_OBJECT_ONIONPEER)受信 -> v3 onionピアをpeers.dbへ登録(§11)
     * PyBitmessageの実ワイヤーフォーマット(class_singleWorker.pyのsendOnionPeerObj)に合わせ、
     * varint(port) || 0xfd87d87eeb43(OnionCat prefix) || 35byteのed25519鍵バイト列、という
     * payloadを持つobjectを実PoW付きで組み立てて受信させる --- */
    {
        /* RFC4648 base32(小文字、大文字小文字を区別しない)デコード。実際に流通していた
         * v3 onionアドレス文字列(56文字)を、ワイヤー上の生バイト列(35byte)へ変換するための
         * テスト専用ヘルパー(本体側はbase32_encode_lowerのみ持つ、逆方向はテストにしか要らない) */
        const char *onion_b32 = "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id";
        unsigned char onion_key[35];
        memset(onion_key, 0, sizeof(onion_key));
        {
            uint64_t buffer = 0;
            int bits = 0;
            size_t out_pos = 0;
            for (size_t i = 0; onion_b32[i] != '\0'; i++)
            {
                char c = onion_b32[i];
                int val = (c >= 'a' && c <= 'z') ? (c - 'a') : (c >= '2' && c <= '7') ? (c - '2' + 26) : -1;
                CHECK(val >= 0, "test onion address should be valid lowercase base32");
                buffer = (buffer << 5) | (unsigned)val;
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    onion_key[out_pos++] = (unsigned char)((buffer >> bits) & 0xff);
                }
            }
            CHECK(out_pos == sizeof(onion_key), "decoded onion key should be exactly 35 bytes");
        }

        unsigned char onion_payload_body[bm_varint_size(8444) + 6 + 35];
        unsigned char *p = onion_payload_body;
        bm_varint_encode(p, 8444); /* port */
        p += bm_varint_size(8444);
        static const unsigned char ONIONCAT_PREFIX[6] = {0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43};
        memcpy(p, ONIONCAT_PREFIX, sizeof(ONIONCAT_PREFIX));
        p += sizeof(ONIONCAT_PREFIX);
        memcpy(p, onion_key, sizeof(onion_key));
        p += sizeof(onion_key);
        size_t onion_payload_body_len = (size_t)(p - onion_payload_body);

        uint64_t onion_ttl = 3600;
        uint64_t onion_expires = (uint64_t)time(NULL) + onion_ttl;
        unsigned char onion_prefix[8 + 4 + bm_varint_size(3) + bm_varint_size(1)];
        unsigned char *op = onion_prefix;
        for (int i = 0; i < 8; i++)
        {
            op[i] = (unsigned char)((onion_expires >> (56 - 8 * i)) & 0xff);
        }
        op += 8;
        uint32_t onion_type = BM_OBJECT_ONIONPEER;
        for (int i = 0; i < 4; i++)
        {
            op[i] = (unsigned char)((onion_type >> (24 - 8 * i)) & 0xff);
        }
        op += 4;
        bm_varint_encode(op, 3); /* object version = 3 (v3 onion, PyBitmessage準拠) */
        op += bm_varint_size(3);
        bm_varint_encode(op, 1); /* stream */
        op += bm_varint_size(1);
        size_t onion_prefix_len = (size_t)(op - onion_prefix);

        size_t onion_full_payload_len = onion_prefix_len + onion_payload_body_len;
        unsigned char *onion_full_payload = malloc(onion_full_payload_len);
        memcpy(onion_full_payload, onion_prefix, onion_prefix_len);
        memcpy(onion_full_payload + onion_prefix_len, onion_payload_body, onion_payload_body_len);

        uint64_t onion_target = bm_pow_get_target(onion_full_payload_len, onion_ttl, 1000, 1000);
        uint64_t onion_nonce = bm_pow_run(onion_full_payload, onion_full_payload_len, onion_target);

        size_t onion_object_len = 8 + onion_full_payload_len;
        unsigned char *onion_object = malloc(onion_object_len);
        for (int i = 0; i < 8; i++)
        {
            onion_object[i] = (unsigned char)((onion_nonce >> (56 - 8 * i)) & 0xff);
        }
        memcpy(onion_object + 8, onion_full_payload, onion_full_payload_len);
        free(onion_full_payload);

        struct bm_message onion_msg;
        memset(&onion_msg, 0, sizeof(onion_msg));
        memcpy(onion_msg.command, "object", 6);
        onion_msg.length = (uint32_t)onion_object_len;
        onion_msg.payload = onion_object;
        bm_object_sync_dispatch(conn, &onion_msg, &ctx);
        free(onion_object);

        sqlite3_stmt *onion_stmt = NULL;
        sqlite3_prepare_v2(peers_db,
                            "SELECT port, source FROM hosts WHERE ip_address = "
                            "'f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion';",
                            -1, &onion_stmt, NULL);
        CHECK(sqlite3_step(onion_stmt) == SQLITE_ROW,
              "v3 onion peer from onionpeer object should be registered into peers.db");
        CHECK(sqlite3_column_int(onion_stmt, 0) == 8444, "registered onion peer port should match");
        const char *onion_source = (const char *)sqlite3_column_text(onion_stmt, 1);
        CHECK(onion_source != NULL && strcmp(onion_source, "onionpeer_obj") == 0,
              "registered onion peer source should be 'onionpeer_obj'");
        sqlite3_finalize(onion_stmt);
    }

    /* --- 8. onionpeer object送信側(bm_build_onionpeer/bm_object_sync_announce_onion_peer, §11)
     * 上のテスト(7)と同じonionアドレス文字列を使い、bm_build_onionpeerが生成するペイロードが
     * (7)の受信側テストが手組みしたワイヤーフォーマット(varint(port)||OnionCat prefix||
     * 35byte鍵)と完全に一致すること(=受信側decodeとの相互運用性)を確認する。加えて
     * bm_object_sync_announce_onion_peerがobject_pool.dbへ実際に登録することも確認する --- */
    {
        const char *send_onion = "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion";

        /* (7)と同じbase32デコード(テスト専用ヘルパー、期待値算出のため) */
        unsigned char expected_key[35];
        {
            uint64_t buffer = 0;
            int bits = 0;
            size_t out_pos = 0;
            for (size_t i = 0; send_onion[i] != '.'; i++)
            {
                char c = send_onion[i];
                int val = (c >= 'a' && c <= 'z') ? (c - 'a') : (c >= '2' && c <= '7') ? (c - '2' + 26) : -1;
                buffer = (buffer << 5) | (unsigned)val;
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    expected_key[out_pos++] = (unsigned char)((buffer >> bits) & 0xff);
                }
            }
            CHECK(out_pos == sizeof(expected_key), "expected onion key should be exactly 35 bytes");
        }

        size_t built_len = 0;
        unsigned char *built = bm_build_onionpeer(send_onion, 9999, 1, (uint64_t)time(NULL) + 3600, &built_len);
        CHECK(built != NULL, "bm_build_onionpeer should succeed for a valid v3 onion address");
        if (built != NULL)
        {
            size_t header_len = 8 + 4 + bm_varint_size(1) + bm_varint_size(1);
            CHECK(built_len > header_len, "built onionpeer payload should have a body");
            const unsigned char *body = built + header_len;
            size_t body_len = built_len - header_len;

            uint64_t decoded_port = 0;
            size_t port_len = bm_varint_decode(body, body_len, &decoded_port);
            CHECK(port_len > 0 && decoded_port == 9999, "built onionpeer body should encode the given port");

            static const unsigned char ONIONCAT_PREFIX[6] = {0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43};
            CHECK(port_len + sizeof(ONIONCAT_PREFIX) + sizeof(expected_key) == body_len,
                  "built onionpeer body length should match varint(port)+prefix+35byte key exactly");
            CHECK(memcmp(body + port_len, ONIONCAT_PREFIX, sizeof(ONIONCAT_PREFIX)) == 0,
                  "built onionpeer body should carry the OnionCat prefix");
            CHECK(memcmp(body + port_len + sizeof(ONIONCAT_PREFIX), expected_key, sizeof(expected_key)) == 0,
                  "built onionpeer body should carry the exact same key bytes the receive side would decode "
                  "back to the original onion address");
            free(built);
        }

        CHECK(bm_build_onionpeer("not-a-valid-onion-address", 8444, 1, (uint64_t)time(NULL) + 3600, &built_len)
                  == NULL,
              "bm_build_onionpeer should reject a malformed onion address");

        int announce_rc = bm_object_sync_announce_onion_peer(&ctx, send_onion, 7777);
        CHECK(announce_rc == 0, "bm_object_sync_announce_onion_peer should succeed");

        sqlite3_stmt *count_stmt = NULL;
        sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1,
                            &count_stmt, NULL);
        sqlite3_bind_int(count_stmt, 1, (int)BM_OBJECT_ONIONPEER);
        CHECK(sqlite3_step(count_stmt) == SQLITE_ROW && sqlite3_column_int(count_stmt, 0) >= 1,
              "an onionpeer object should be stored in object_pool.db after announcing");
        sqlite3_finalize(count_stmt);
    }

    /* --- 9. errorメッセージの受信(§11 2026-08-22調査): fatal(varint) || banTime(varint) ||
     * vector(varstr) || errorText(varstr)をパースしてログに出す。これまで中身を一切見ずに
     * "unhandled command"として捨てていたため、rating調査中に頻発していたにも関わらず
     * 原因が分からなかった。ここではクラッシュしない(特に手書きのbounds check、
     * データ不足時のsize_t引き算アンダーフローが無い)ことを主眼に確認する
     * (stderrへ出力される内容自体はテストの枠組みでは検証しない) --- */
    {
        /* 9a. 正常な形式: fatal=2, banTime=3600, vector="", errorText="too many connections" */
        const char *error_text = "too many connections";
        size_t text_len = strlen(error_text);
        unsigned char error_payload[64];
        unsigned char *ep = error_payload;
        bm_varint_encode(ep, 2);
        ep += bm_varint_size(2);
        bm_varint_encode(ep, 3600);
        ep += bm_varint_size(3600);
        bm_varint_encode(ep, 0); /* vector長=0(空) */
        ep += bm_varint_size(0);
        bm_varint_encode(ep, text_len);
        ep += bm_varint_size(text_len);
        memcpy(ep, error_text, text_len);
        ep += text_len;
        size_t error_payload_len = (size_t)(ep - error_payload);

        struct bm_message error_msg;
        memset(&error_msg, 0, sizeof(error_msg));
        memcpy(error_msg.command, "error", 5);
        error_msg.length = (uint32_t)error_payload_len;
        error_msg.payload = error_payload;
        bm_object_sync_dispatch(conn, &error_msg, &ctx);
        CHECK(1, "well-formed error message should be parsed without crashing");

        /* 9b. 空/極端に短いペイロード(データ不足)。手書きbounds checkの
         * アンダーフロー(size_t引き算)が無いことの確認が主目的 */
        struct bm_message empty_error_msg;
        memset(&empty_error_msg, 0, sizeof(empty_error_msg));
        memcpy(empty_error_msg.command, "error", 5);
        empty_error_msg.length = 0;
        empty_error_msg.payload = NULL;
        bm_object_sync_dispatch(conn, &empty_error_msg, &ctx);
        CHECK(1, "empty/truncated error message should be ignored without crashing");

        unsigned char one_byte_payload[1] = {0x02};
        struct bm_message truncated_error_msg;
        memset(&truncated_error_msg, 0, sizeof(truncated_error_msg));
        memcpy(truncated_error_msg.command, "error", 5);
        truncated_error_msg.length = 1;
        truncated_error_msg.payload = one_byte_payload;
        bm_object_sync_dispatch(conn, &truncated_error_msg, &ctx);
        CHECK(1, "error message truncated right after 'fatal' should be ignored without crashing");
    }

    close(fds[0]);
    close(fds[1]);
    bm_fd_data_free(conn);
    close(fds2[0]);
    close(fds2[1]);
    bm_fd_data_free(conn2);
    bm_peer_registry_destroy(&registry);
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
