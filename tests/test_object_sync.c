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
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/infra/dandelion.h"
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

/*
 * §11 2026-08-23 backlog項目4のテスト用: bm_new_version_messageは常にtime(NULL)を
 * timestampに使うため、時計ズレを意図的に再現するにはこのヘルパーで一度組み立ててから
 * timestampフィールド(offset 4+8=12から8byte、bm_create_version_payloadのレイアウト参照)
 * だけ上書きする。完成メッセージ(24byteヘッダ込み、malloc済み、呼び出し側でfree)を返す。
 */
static unsigned char *build_version_packet_with_timestamp(const char *user_agent_str, int version,
                                                            const struct sockaddr_storage *peer_addr,
                                                            const struct sockaddr_storage *local_addr,
                                                            uint64_t timestamp, size_t *out_len)
{
    size_t payload_len = bm_version_payload_size(user_agent_str);
    unsigned char *payload = malloc(payload_len);
    bm_create_version_payload(payload, user_agent_str, version, peer_addr, local_addr);
    uint64_t be_timestamp = htobe64(timestamp);
    memcpy(payload + 12, &be_timestamp, sizeof(be_timestamp));
    unsigned char *packet = bm_create_packet("version", payload, payload_len, out_len);
    free(payload);
    return packet;
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
        /* §11 2026-08-23: last_seen(peer申告のtime)が未来の値のentryは一律filterするように
         * した。実際にpeers.dbで2^31を超えるlast_seenが70件見つかり、bm_peer_manager_cleanup
         * の年齢判定(now - last_seen)が常に負になって永久にクリーンアップされなくなる問題が
         * 発覚したため。 */
        unsigned char ipv4_future[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 99};
        unsigned char entries[4][38];
        const unsigned char *ips[4] = {ipv4_routable, ipv4_private, ipv6_global_unicast, ipv4_future};
        uint64_t addr_time = (uint64_t)time(NULL);
        for (int e = 0; e < 4; e++)
        {
            unsigned char *p = entries[e];
            /* entry 3(ipv4_future)だけ未来の値(現在時刻+1年)にする */
            uint64_t this_entry_time = (e == 3) ? addr_time + 365ULL * 24 * 60 * 60 : addr_time;
            for (int i = 0; i < 8; i++)
            {
                p[i] = (unsigned char)((this_entry_time >> (56 - 8 * i)) & 0xff);
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
        bm_varint_encode(addr_payload, 4);
        memcpy(addr_payload + bm_varint_size(4), entries, sizeof(entries));
        size_t addr_payload_len = bm_varint_size(4) + sizeof(entries);

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

        sqlite3_stmt *future_stmt = NULL;
        sqlite3_prepare_v2(peers_db, "SELECT COUNT(*) FROM hosts WHERE ip_address = '203.0.113.99';", -1,
                            &future_stmt, NULL);
        CHECK(sqlite3_step(future_stmt) == SQLITE_ROW, "future-timestamped addr count query should return a row");
        CHECK(sqlite3_column_int(future_stmt, 0) == 0,
              "addr entry claiming a last_seen time in the future should be filtered out, not registered");
        sqlite3_finalize(future_stmt);
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

        int announce_rc = bm_object_sync_announce_onion_peer(&ctx, send_onion, 7777, (int64_t)time(NULL));
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

        /* 9c. §11 2026-08-23発覚のバグ修正: fatal>=1のerrorを受信したら、ratingへ追加の
         * ペナルティ(-0.1)を与えることを確認する。verack受信時の成功クレジット(+0.1)と
         * 切断時の失敗クレジット(-0.1)がほぼ相殺し、"Server full"等で明確に拒否している
         * peerへ毎サイクル再接続し続けてしまっていた問題への対策。専用のsocketpair/peers.db
         * 行を使う(他シナリオのconnはUNIXソケットでlogical_peer_ipが無く、この検証には
         * 使えないため) */
        int fds9c[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds9c) == 0, "socketpair for error-penalty scenario");
        struct bm_fd_data *conn9c = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds9c[0]);
        CHECK(conn9c != NULL, "bm_fd_data_new for error-penalty scenario");
        strncpy(conn9c->logical_peer_ip, "203.0.113.55", sizeof(conn9c->logical_peer_ip) - 1);
        conn9c->logical_peer_port = 8444;

        struct bm_peer_entry rejecting_peer;
        memset(&rejecting_peer, 0, sizeof(rejecting_peer));
        strncpy(rejecting_peer.ip_address, "203.0.113.55", sizeof(rejecting_peer.ip_address) - 1);
        rejecting_peer.port = 8444;
        rejecting_peer.stream = 1;
        rejecting_peer.services = 1;
        rejecting_peer.last_seen = (int64_t)time(NULL);
        rejecting_peer.rating = 0.9; /* verack成功クレジットの積み重ねを模擬した高いrating */
        strncpy(rejecting_peer.source, "test", sizeof(rejecting_peer.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &rejecting_peer) == 0, "seed the rejecting peer");

        struct bm_message fatal_error_msg;
        memset(&fatal_error_msg, 0, sizeof(fatal_error_msg));
        memcpy(fatal_error_msg.command, "error", 5);
        fatal_error_msg.length = (uint32_t)error_payload_len; /* 9aと同じfatal=2ペイロードを再利用 */
        fatal_error_msg.payload = error_payload;
        bm_object_sync_dispatch(conn9c, &fatal_error_msg, &ctx);

        sqlite3_stmt *penalty_stmt = NULL;
        sqlite3_prepare_v2(peers_db, "SELECT rating FROM hosts WHERE ip_address = '203.0.113.55' AND port = 8444;",
                            -1, &penalty_stmt, NULL);
        CHECK(sqlite3_step(penalty_stmt) == SQLITE_ROW, "the seeded peer row should still exist");
        double rating_after = sqlite3_column_double(penalty_stmt, 0);
        CHECK(rating_after < 0.9 - 1e-9,
              "receiving a fatal error message should decrease the peer's rating, not leave it unchanged");
        sqlite3_finalize(penalty_stmt);

        close(fds9c[0]);
        close(fds9c[1]);
        bm_fd_data_free(conn9c);
    }

    /* --- 10. addr送信(§11 2026-08-23): verack受信時に、自分が知っているshareableなpeerを
     * addrメッセージとして返す。rating<0・last_seenが3時間以上前・onionアドレスの候補は
     * 除外され、条件を満たす1件だけが含まれることを確認する。専用のsocketpairを使う
     * (既存のfds/connは(1)〜(9)のシナリオで送受信済みのバイト列が残っている可能性があり、
     * 使い回すとstaleなバイト列を誤って読んでしまうため)。peers_dbも(6)で登録済みの行が
     * 残っているため、事前にクリアしてこのシナリオ専用の候補だけにする --- */
    {
        sqlite3_exec(peers_db, "DELETE FROM hosts;", NULL, NULL, NULL);

        int fds10[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds10) == 0, "socketpair for addr-send scenario");
        struct bm_fd_data *conn10 = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds10[0]);
        CHECK(conn10 != NULL, "bm_fd_data_new for addr-send scenario");

        struct bm_peer_entry shareable, low_rating, onion, stale;

        memset(&shareable, 0, sizeof(shareable));
        strncpy(shareable.ip_address, "198.51.100.7", sizeof(shareable.ip_address) - 1);
        shareable.port = 8444;
        shareable.stream = 1;
        shareable.services = 1;
        shareable.last_seen = (int64_t)time(NULL);
        shareable.rating = 0.5;
        strncpy(shareable.source, "test", sizeof(shareable.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &shareable) == 0, "seed shareable candidate");

        memset(&low_rating, 0, sizeof(low_rating));
        strncpy(low_rating.ip_address, "198.51.100.8", sizeof(low_rating.ip_address) - 1);
        low_rating.port = 8444;
        low_rating.stream = 1;
        low_rating.services = 1;
        low_rating.last_seen = (int64_t)time(NULL);
        low_rating.rating = -0.3;
        strncpy(low_rating.source, "test", sizeof(low_rating.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &low_rating) == 0, "seed negative-rating candidate");

        memset(&onion, 0, sizeof(onion));
        strncpy(onion.ip_address, "exampleonionaddressabcdefghijklmnopqrstuvwxyz234567.onion",
                sizeof(onion.ip_address) - 1);
        onion.port = 8444;
        onion.stream = 1;
        onion.services = 1;
        onion.last_seen = (int64_t)time(NULL);
        onion.rating = 0.5;
        strncpy(onion.source, "test", sizeof(onion.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &onion) == 0, "seed onion candidate");

        memset(&stale, 0, sizeof(stale));
        strncpy(stale.ip_address, "198.51.100.9", sizeof(stale.ip_address) - 1);
        stale.port = 8444;
        stale.stream = 1;
        stale.services = 1;
        stale.last_seen = (int64_t)time(NULL) - 4 * 60 * 60;
        stale.rating = 0.5;
        strncpy(stale.source, "test", sizeof(stale.source) - 1);
        CHECK(bm_peer_manager_upsert(peers_db, &stale) == 0, "seed stale (>3h) candidate");

        struct bm_message verack_msg;
        memset(&verack_msg, 0, sizeof(verack_msg));
        memcpy(verack_msg.command, "verack", 6);
        verack_msg.length = 0;
        verack_msg.payload = NULL;
        bm_object_sync_dispatch(conn10, &verack_msg, &ctx);

        unsigned char addr_buf[65536];
        size_t addr_total = 0;
        struct bm_message *addr_reply = NULL;
        size_t addr_consumed = 0;
        for (;;)
        {
            ssize_t n = read(fds10[1], addr_buf + addr_total, sizeof(addr_buf) - addr_total);
            if (n <= 0)
            {
                break;
            }
            addr_total += (size_t)n;
            if (bm_parse_message(addr_buf, addr_total, &addr_reply, &addr_consumed) == BM_PARSE_OK)
            {
                break;
            }
        }
        CHECK(addr_reply != NULL, "an addr message should have been sent back after verack");
        if (addr_reply != NULL)
        {
            CHECK(strncmp(addr_reply->command, "addr", 12) == 0, "the reply command should be 'addr'");

            struct bm_addr_message parsed;
            memset(&parsed, 0, sizeof(parsed));
            int parse_rc = bm_parse_addr_message(addr_reply->payload, addr_reply->length, &parsed);
            CHECK(parse_rc == 0, "the sent addr payload should parse back successfully");
            if (parse_rc == 0)
            {
                CHECK(parsed.count == 1, "only the single shareable candidate should be included");
                if (parsed.count == 1)
                {
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET, parsed.addresses[0].ip + 12, ip_str, sizeof(ip_str));
                    CHECK(strcmp(ip_str, "198.51.100.7") == 0,
                          "the included candidate should be the shareable one, not any of the excluded ones");
                    CHECK(parsed.addresses[0].port == 8444, "the included candidate's port should match");
                }
                bm_free_addr_message(&parsed);
            }
            bm_free_message(addr_reply);
        }

        close(fds10[0]);
        close(fds10[1]);
        bm_fd_data_free(conn10);
    }

    /* --- 11. プロトコルバージョン互換性チェック(§11 2026-08-23 backlog項目3、
     * PyBitmessage network/bmproto.pyのpeerValidityChecks相当)。BM_MIN_PROTOCOL_VERSION
     * (=3)未満のversionを名乗る相手にはverackを送らず、fatal=2のerrorメッセージだけ送って
     * conn->should_disconnectを立てることを確認する。3以上なら従来通りverackが返ることも
     * 併せて確認する(専用のsocketpairを使う、他シナリオとの取り違え防止のため) --- */
    {
        /* 11a. version=2(閾値未満) */
        int fds11a[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds11a) == 0, "socketpair for old-protocol-version scenario");
        struct bm_fd_data *conn11a = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds11a[0]);
        CHECK(conn11a != NULL, "bm_fd_data_new for old-protocol-version scenario");

        size_t old_ver_len = 0;
        unsigned char *old_ver_packet = bm_new_version_message("/bitmessage-c-test:0.1.0/", 2, &conn11a->peer_addr,
                                                                 &conn11a->local_addr, &old_ver_len);
        CHECK(old_ver_packet != NULL, "bm_new_version_message should build a version=2 packet");

        struct bm_message *old_ver_msg = NULL;
        size_t old_ver_consumed = 0;
        CHECK(bm_parse_message(old_ver_packet, old_ver_len, &old_ver_msg, &old_ver_consumed) == BM_PARSE_OK,
              "the constructed version=2 packet should parse back successfully");
        if (old_ver_msg != NULL)
        {
            bm_object_sync_dispatch(conn11a, old_ver_msg, &ctx);
            bm_free_message(old_ver_msg);
        }
        CHECK(conn11a->should_disconnect == 1,
              "a peer announcing a protocol version below BM_MIN_PROTOCOL_VERSION should be marked for disconnect");

        unsigned char reply_buf[512];
        size_t reply_total = 0;
        struct bm_message *reply_msg = NULL;
        size_t reply_consumed = 0;
        for (;;)
        {
            ssize_t n = read(fds11a[1], reply_buf + reply_total, sizeof(reply_buf) - reply_total);
            if (n <= 0)
            {
                break;
            }
            reply_total += (size_t)n;
            if (bm_parse_message(reply_buf, reply_total, &reply_msg, &reply_consumed) == BM_PARSE_OK)
            {
                break;
            }
        }
        CHECK(reply_msg != NULL, "an error message should have been sent back for the too-old protocol version");
        if (reply_msg != NULL)
        {
            CHECK(strncmp(reply_msg->command, "error", 12) == 0,
                  "the reply command should be 'error', not 'verack'");
            uint64_t fatal = 0;
            size_t consumed = bm_varint_decode(reply_msg->payload, reply_msg->length, &fatal);
            CHECK(consumed > 0 && fatal == 2, "the error message's fatal field should be 2 (Fatal)");
            bm_free_message(reply_msg);
        }
        /* 相手に届いた分がerrorメッセージだけ(verackは送られていない)であることも確認する */
        CHECK(reply_total == reply_consumed,
              "no extra bytes (e.g. a verack) should follow the error message");

        free(old_ver_packet);
        close(fds11a[0]);
        close(fds11a[1]);
        bm_fd_data_free(conn11a);

        /* 11b. version=BM_MIN_PROTOCOL_VERSION(閾値以上)なら従来通りverackが返る(回帰確認) */
        int fds11b[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds11b) == 0, "socketpair for min-protocol-version scenario");
        struct bm_fd_data *conn11b = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds11b[0]);
        CHECK(conn11b != NULL, "bm_fd_data_new for min-protocol-version scenario");

        size_t ok_ver_len = 0;
        unsigned char *ok_ver_packet =
                bm_new_version_message("/bitmessage-c-test:0.1.0/", BM_MIN_PROTOCOL_VERSION, &conn11b->peer_addr,
                                        &conn11b->local_addr, &ok_ver_len);
        CHECK(ok_ver_packet != NULL, "bm_new_version_message should build a version=BM_MIN_PROTOCOL_VERSION packet");

        struct bm_message *ok_ver_msg = NULL;
        size_t ok_ver_consumed = 0;
        CHECK(bm_parse_message(ok_ver_packet, ok_ver_len, &ok_ver_msg, &ok_ver_consumed) == BM_PARSE_OK,
              "the constructed minimum-version packet should parse back successfully");
        if (ok_ver_msg != NULL)
        {
            bm_object_sync_dispatch(conn11b, ok_ver_msg, &ctx);
            bm_free_message(ok_ver_msg);
        }
        CHECK(conn11b->should_disconnect == 0,
              "a peer at exactly BM_MIN_PROTOCOL_VERSION should not be marked for disconnect");

        unsigned char reply_buf2[512];
        size_t reply2_total = 0;
        struct bm_message *reply_msg2 = NULL;
        size_t reply2_consumed = 0;
        for (;;)
        {
            ssize_t n = read(fds11b[1], reply_buf2 + reply2_total, sizeof(reply_buf2) - reply2_total);
            if (n <= 0)
            {
                break;
            }
            reply2_total += (size_t)n;
            if (bm_parse_message(reply_buf2, reply2_total, &reply_msg2, &reply2_consumed) == BM_PARSE_OK)
            {
                break;
            }
        }
        CHECK(reply_msg2 != NULL, "a reply should have been sent back for an acceptable protocol version");
        if (reply_msg2 != NULL)
        {
            CHECK(strncmp(reply_msg2->command, "verack", 12) == 0,
                  "the reply command should be 'verack' when the protocol version is acceptable");
            bm_free_message(reply_msg2);
        }

        free(ok_ver_packet);
        close(fds11b[0]);
        close(fds11b[1]);
        bm_fd_data_free(conn11b);
    }

    /* --- 12. version messageのtimestamp検証(§11 2026-08-23 backlog項目4、
     * PyBitmessage network/bmproto.pyのpeerValidityChecks、timeOffsetチェック相当)。
     * 自分の時計とBM_MAX_TIME_OFFSET_SECONDS(1時間)を超えてずれたtimestampを送ってくる
     * 相手はverackを送らずfatal=2のerrorで切断されることを、未来方向・過去方向の両方で
     * 確認する。境界値(ちょうどBM_MAX_TIME_OFFSET_SECONDS)は許容されることも確認する --- */
    {
        /* 12a. 未来方向に大きくズレている */
        int fds12a[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds12a) == 0, "socketpair for future-timestamp scenario");
        struct bm_fd_data *conn12a = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds12a[0]);
        CHECK(conn12a != NULL, "bm_fd_data_new for future-timestamp scenario");

        uint64_t future_ts = (uint64_t)time(NULL) + BM_MAX_TIME_OFFSET_SECONDS + 60;
        size_t future_len = 0;
        unsigned char *future_packet = build_version_packet_with_timestamp(
                "/bitmessage-c-test:0.1.0/", BM_MIN_PROTOCOL_VERSION, &conn12a->peer_addr, &conn12a->local_addr,
                future_ts, &future_len);
        CHECK(future_packet != NULL, "build_version_packet_with_timestamp should build a future-timestamp packet");

        struct bm_message *future_msg = NULL;
        size_t future_consumed = 0;
        CHECK(bm_parse_message(future_packet, future_len, &future_msg, &future_consumed) == BM_PARSE_OK,
              "the constructed future-timestamp packet should parse back successfully");
        if (future_msg != NULL)
        {
            bm_object_sync_dispatch(conn12a, future_msg, &ctx);
            bm_free_message(future_msg);
        }
        CHECK(conn12a->should_disconnect == 1,
              "a peer whose version timestamp is too far in the future should be marked for disconnect");

        struct bm_message *future_reply = read_one_message(fds12a[1]);
        CHECK(future_reply != NULL, "an error message should have been sent back for the future timestamp");
        if (future_reply != NULL)
        {
            CHECK(strncmp(future_reply->command, "error", 12) == 0,
                  "the reply command should be 'error', not 'verack'");
            bm_free_message(future_reply);
        }

        free(future_packet);
        close(fds12a[0]);
        close(fds12a[1]);
        bm_fd_data_free(conn12a);

        /* 12b. 過去方向に大きくズレている */
        int fds12b[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds12b) == 0, "socketpair for past-timestamp scenario");
        struct bm_fd_data *conn12b = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds12b[0]);
        CHECK(conn12b != NULL, "bm_fd_data_new for past-timestamp scenario");

        uint64_t past_ts = (uint64_t)time(NULL) - BM_MAX_TIME_OFFSET_SECONDS - 60;
        size_t past_len = 0;
        unsigned char *past_packet = build_version_packet_with_timestamp(
                "/bitmessage-c-test:0.1.0/", BM_MIN_PROTOCOL_VERSION, &conn12b->peer_addr, &conn12b->local_addr,
                past_ts, &past_len);
        CHECK(past_packet != NULL, "build_version_packet_with_timestamp should build a past-timestamp packet");

        struct bm_message *past_msg = NULL;
        size_t past_consumed = 0;
        CHECK(bm_parse_message(past_packet, past_len, &past_msg, &past_consumed) == BM_PARSE_OK,
              "the constructed past-timestamp packet should parse back successfully");
        if (past_msg != NULL)
        {
            bm_object_sync_dispatch(conn12b, past_msg, &ctx);
            bm_free_message(past_msg);
        }
        CHECK(conn12b->should_disconnect == 1,
              "a peer whose version timestamp is too far in the past should be marked for disconnect");

        struct bm_message *past_reply = read_one_message(fds12b[1]);
        CHECK(past_reply != NULL, "an error message should have been sent back for the past timestamp");
        if (past_reply != NULL)
        {
            CHECK(strncmp(past_reply->command, "error", 12) == 0,
                  "the reply command should be 'error', not 'verack'");
            bm_free_message(past_reply);
        }

        free(past_packet);
        close(fds12b[0]);
        close(fds12b[1]);
        bm_fd_data_free(conn12b);

        /* 12c. 境界値(ちょうどBM_MAX_TIME_OFFSET_SECONDS)は許容される(回帰確認) */
        int fds12c[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds12c) == 0, "socketpair for boundary-timestamp scenario");
        struct bm_fd_data *conn12c = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds12c[0]);
        CHECK(conn12c != NULL, "bm_fd_data_new for boundary-timestamp scenario");

        uint64_t boundary_ts = (uint64_t)time(NULL) + BM_MAX_TIME_OFFSET_SECONDS;
        size_t boundary_len = 0;
        unsigned char *boundary_packet = build_version_packet_with_timestamp(
                "/bitmessage-c-test:0.1.0/", BM_MIN_PROTOCOL_VERSION, &conn12c->peer_addr, &conn12c->local_addr,
                boundary_ts, &boundary_len);
        CHECK(boundary_packet != NULL, "build_version_packet_with_timestamp should build a boundary packet");

        struct bm_message *boundary_msg = NULL;
        size_t boundary_consumed = 0;
        CHECK(bm_parse_message(boundary_packet, boundary_len, &boundary_msg, &boundary_consumed) == BM_PARSE_OK,
              "the constructed boundary packet should parse back successfully");
        if (boundary_msg != NULL)
        {
            bm_object_sync_dispatch(conn12c, boundary_msg, &ctx);
            bm_free_message(boundary_msg);
        }
        CHECK(conn12c->should_disconnect == 0,
              "a peer whose version timestamp offset is exactly BM_MAX_TIME_OFFSET_SECONDS should be accepted");

        struct bm_message *boundary_reply = read_one_message(fds12c[1]);
        CHECK(boundary_reply != NULL, "a reply should have been sent back for an acceptable timestamp");
        if (boundary_reply != NULL)
        {
            CHECK(strncmp(boundary_reply->command, "verack", 12) == 0,
                  "the reply command should be 'verack' when the timestamp offset is within range");
            bm_free_message(boundary_reply);
        }

        free(boundary_packet);
        close(fds12c[0]);
        close(fds12c[1]);
        bm_fd_data_free(conn12c);
    }

    /* --- 13. handshake完了時のbig inv送信(§11 2026-08-23、PyBitmessage本家の
     * sendBigInv相当)。自分が保有する全objectのhashを新規peerへverack受信時に知らせる
     * ことを確認する。専用のsocketpairと、object_pool_dbをクリアした上で既知の2件だけを
     * 種として使う(他シナリオで積み上がった大量のobjectと混ざらないよう、以降このtestでは
     * object_pool_dbを使わないため安全にクリアできる)。peers.dbもクリアし、addr送信を
     * 空にしてinv1本だけが届く状態にする(read_one_messageで単純に読める) --- */
    {
        sqlite3_exec(object_pool_db, "DELETE FROM objects;", NULL, NULL, NULL);
        sqlite3_exec(peers_db, "DELETE FROM hosts;", NULL, NULL, NULL);

        unsigned char hash_a[32], hash_b[32];
        memset(hash_a, 0xAA, sizeof(hash_a));
        memset(hash_b, 0xBB, sizeof(hash_b));
        unsigned char dummy_payload[16] = {0};
        int64_t now13 = (int64_t)time(NULL);
        CHECK(bm_object_store_insert(object_pool_db, hash_a, BM_OBJECT_MSG, 1, dummy_payload,
                                      sizeof(dummy_payload), now13 + 86400, now13)
                  == 0,
              "seed object A for big-inv scenario");
        CHECK(bm_object_store_insert(object_pool_db, hash_b, BM_OBJECT_MSG, 1, dummy_payload,
                                      sizeof(dummy_payload), now13 + 86400, now13)
                  == 0,
              "seed object B for big-inv scenario");

        int fds13[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds13) == 0, "socketpair for big-inv scenario");
        struct bm_fd_data *conn13 = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds13[0]);
        CHECK(conn13 != NULL, "bm_fd_data_new for big-inv scenario");

        struct bm_message verack_msg13;
        memset(&verack_msg13, 0, sizeof(verack_msg13));
        memcpy(verack_msg13.command, "verack", 6);
        verack_msg13.length = 0;
        verack_msg13.payload = NULL;
        bm_object_sync_dispatch(conn13, &verack_msg13, &ctx);

        struct bm_message *inv_reply = read_one_message(fds13[1]);
        CHECK(inv_reply != NULL, "an inv message should have been sent right after verack (sendBigInv)");
        if (inv_reply != NULL)
        {
            CHECK(strncmp(inv_reply->command, "inv", 12) == 0, "the reply command should be 'inv'");

            struct bm_inventory_message parsed13;
            memset(&parsed13, 0, sizeof(parsed13));
            int parse_rc13 = bm_parse_inventory_message(inv_reply->payload, inv_reply->length, &parsed13);
            CHECK(parse_rc13 == 0, "the sent big-inv payload should parse back successfully");
            if (parse_rc13 == 0)
            {
                CHECK(parsed13.count == 2, "big inv should contain exactly the 2 seeded objects");
                int saw_a = 0, saw_b = 0;
                for (uint64_t i = 0; i < parsed13.count; i++)
                {
                    if (memcmp(parsed13.items[i], hash_a, 32) == 0)
                    {
                        saw_a = 1;
                    }
                    if (memcmp(parsed13.items[i], hash_b, 32) == 0)
                    {
                        saw_b = 1;
                    }
                }
                CHECK(saw_a && saw_b, "big inv should include both seeded object hashes");
                bm_free_inventory_message(&parsed13);
            }
            bm_free_message(inv_reply);
        }

        close(fds13[0]);
        close(fds13[1]);
        bm_fd_data_free(conn13);
    }

    /* --- 14. シナリオ13のinbound版(§11 2026-08-23、ユーザーからの指摘で判明した
     * テストカバレッジの穴)。verackハンドラ(object_sync.c)はconn->typeによる分岐が
     * 無く「inbound/outbound問わず」addr/big inv送信を行うはずだが、実際に
     * BM_FD_SERVER_SOCKET(相手からの接続)がverackを受信した場合でも同じことが
     * 起きることを直接確認できているテストが無かった。test_inbound.cは
     * 「inbound接続が相手のversionを受けてverack+versionを送り返す」ところまでしか
     * カバーしておらず、その後こちらが相手からのverackを受信する側は未検証だった --- */
    {
        sqlite3_exec(object_pool_db, "DELETE FROM objects;", NULL, NULL, NULL);
        sqlite3_exec(peers_db, "DELETE FROM hosts;", NULL, NULL, NULL);

        unsigned char hash_c[32], hash_d[32];
        memset(hash_c, 0xCC, sizeof(hash_c));
        memset(hash_d, 0xDD, sizeof(hash_d));
        unsigned char dummy_payload14[16] = {0};
        int64_t now14 = (int64_t)time(NULL);
        CHECK(bm_object_store_insert(object_pool_db, hash_c, BM_OBJECT_MSG, 1, dummy_payload14,
                                      sizeof(dummy_payload14), now14 + 86400, now14)
                  == 0,
              "seed object C for inbound big-inv scenario");
        CHECK(bm_object_store_insert(object_pool_db, hash_d, BM_OBJECT_MSG, 1, dummy_payload14,
                                      sizeof(dummy_payload14), now14 + 86400, now14)
                  == 0,
              "seed object D for inbound big-inv scenario");

        int fds14[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds14) == 0, "socketpair for inbound big-inv scenario");
        /* シナリオ13と違い、ここではBM_FD_SERVER_SOCKET(inbound、相手から接続してきた側)を使う */
        struct bm_fd_data *conn14 = bm_fd_data_new(BM_FD_SERVER_SOCKET, fds14[0]);
        CHECK(conn14 != NULL, "bm_fd_data_new for inbound big-inv scenario");

        struct bm_message verack_msg14;
        memset(&verack_msg14, 0, sizeof(verack_msg14));
        memcpy(verack_msg14.command, "verack", 6);
        verack_msg14.length = 0;
        verack_msg14.payload = NULL;
        bm_object_sync_dispatch(conn14, &verack_msg14, &ctx);

        CHECK(conn14->handshake_complete == 1, "inbound connection should also become fully established on verack");

        struct bm_message *inv_reply14 = read_one_message(fds14[1]);
        CHECK(inv_reply14 != NULL,
              "an inv message should have been sent right after verack on an inbound connection too");
        if (inv_reply14 != NULL)
        {
            CHECK(strncmp(inv_reply14->command, "inv", 12) == 0, "the reply command should be 'inv'");

            struct bm_inventory_message parsed14;
            memset(&parsed14, 0, sizeof(parsed14));
            int parse_rc14 = bm_parse_inventory_message(inv_reply14->payload, inv_reply14->length, &parsed14);
            CHECK(parse_rc14 == 0, "the sent big-inv payload should parse back successfully");
            if (parse_rc14 == 0)
            {
                CHECK(parsed14.count == 2, "big inv should contain exactly the 2 seeded objects");
                int saw_c = 0, saw_d = 0;
                for (uint64_t i = 0; i < parsed14.count; i++)
                {
                    if (memcmp(parsed14.items[i], hash_c, 32) == 0)
                    {
                        saw_c = 1;
                    }
                    if (memcmp(parsed14.items[i], hash_d, 32) == 0)
                    {
                        saw_d = 1;
                    }
                }
                CHECK(saw_c && saw_d, "big inv should include both seeded object hashes on inbound too");
                bm_free_inventory_message(&parsed14);
            }
            bm_free_message(inv_reply14);
        }

        close(fds14[0]);
        close(fds14[1]);
        bm_fd_data_free(conn14);
    }

    /* --- 15. §11 2026-08-24発覚のバグ修正: send_big_invが、今まさにstem中(まだ
     * fluffされていない)hashを正しく除外することを確認する。以前はbm_decide_propagation
     * 経由でhashごとに新規のDandelion++判定エントリを作ってしまい、既に公開済みの
     * objectまでstemタイムアウト→間引き→再作成の無限ループに巻き込んでいた
     * (broadcast_invの大量空発火として顕在化、ユーザー指摘で発覚)。専用のdandelion
     * モジュール状態・registryを使って隔離する(他シナリオのdandelion状態と混ざらない
     * ように、この検証の直前でbm_dandelion_module_initし直す) --- */
    {
        bm_dandelion_module_init();

        struct bm_peer_registry dandelion_reg;
        bm_peer_registry_init(&dandelion_reg);

        int fds_stem[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_stem) == 0, "socketpair for stem-successor fixture");
        struct bm_fd_data *stem_conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds_stem[0]);
        CHECK(stem_conn != NULL, "bm_fd_data_new for stem-successor fixture");
        stem_conn->services = BM_SERVICE_NODE_DANDELION;
        bm_peer_registry_add(&dandelion_reg, stem_conn);

        int64_t now15 = (int64_t)time(NULL);
        bm_dandelion_maybe_reshuffle(&dandelion_reg, now15); /* 候補が1つだけなので必ずstem_connが選ばれる */

        unsigned char hash_stem[32], hash_normal[32];
        memset(hash_stem, 0xEE, sizeof(hash_stem));
        memset(hash_normal, 0xFF, sizeof(hash_normal));

        /* hash_stemを「今まさにstem中」の状態にする(fluffed_at=0のまま、STEM判定される
         * ことも併せて確認する) */
        CHECK(bm_dandelion_decide(hash_stem, stem_conn, now15) == BM_PROPAGATE_STEM,
              "seeding: hash_stem should be decided as STEM for the configured successor");
        CHECK(bm_dandelion_is_stemming(hash_stem) == 1, "hash_stem should now report as actively stemming");
        CHECK(bm_dandelion_is_stemming(hash_normal) == 0,
              "hash_normal (never touched) should not report as stemming");

        sqlite3_exec(object_pool_db, "DELETE FROM objects;", NULL, NULL, NULL);
        unsigned char dummy_payload15[16] = {0};
        CHECK(bm_object_store_insert(object_pool_db, hash_stem, BM_OBJECT_MSG, 1, dummy_payload15,
                                      sizeof(dummy_payload15), now15 + 86400, now15)
                  == 0,
              "seed hash_stem into object_pool for send_big_inv exclusion test");
        CHECK(bm_object_store_insert(object_pool_db, hash_normal, BM_OBJECT_MSG, 1, dummy_payload15,
                                      sizeof(dummy_payload15), now15 + 86400, now15)
                  == 0,
              "seed hash_normal into object_pool for send_big_inv exclusion test");

        int fds15[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds15) == 0, "socketpair for send_big_inv exclusion test");
        struct bm_fd_data *conn15 = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds15[0]);
        CHECK(conn15 != NULL, "bm_fd_data_new for send_big_inv exclusion test");

        struct bm_message verack_msg15;
        memset(&verack_msg15, 0, sizeof(verack_msg15));
        memcpy(verack_msg15.command, "verack", 6);
        verack_msg15.length = 0;
        verack_msg15.payload = NULL;
        bm_object_sync_dispatch(conn15, &verack_msg15, &ctx);

        struct bm_message *inv_reply15 = read_one_message(fds15[1]);
        CHECK(inv_reply15 != NULL, "an inv message should have been sent right after verack");
        if (inv_reply15 != NULL)
        {
            struct bm_inventory_message parsed15;
            memset(&parsed15, 0, sizeof(parsed15));
            CHECK(bm_parse_inventory_message(inv_reply15->payload, inv_reply15->length, &parsed15) == 0,
                  "the sent big-inv payload should parse back successfully");
            int saw_stem = 0, saw_normal = 0;
            for (uint64_t i = 0; i < parsed15.count; i++)
            {
                if (memcmp(parsed15.items[i], hash_stem, 32) == 0)
                {
                    saw_stem = 1;
                }
                if (memcmp(parsed15.items[i], hash_normal, 32) == 0)
                {
                    saw_normal = 1;
                }
            }
            CHECK(!saw_stem, "the actively-stemming hash should be EXCLUDED from send_big_inv");
            CHECK(saw_normal, "the ordinary (non-stemming) hash should still be included");
            bm_free_inventory_message(&parsed15);
            bm_free_message(inv_reply15);
        }

        close(fds15[0]);
        close(fds15[1]);
        bm_fd_data_free(conn15);
        bm_peer_registry_remove(&dandelion_reg, stem_conn);
        close(fds_stem[0]);
        close(fds_stem[1]);
        bm_fd_data_free(stem_conn);
        bm_peer_registry_destroy(&dandelion_reg);
    }

    /* --- 16. onionpeer自己announceの定期再送(bm_object_sync_maybe_reannounce_onion_peer、
     * §11 2026-08-24 backlog項目6)。PyBitmessage本家(class_singleCleaner.pyの約2時間おき
     * チェック)に合わせ、BM_ONIONPEER_REANNOUNCE_INTERVAL_SECONDS(7380秒)未満の間隔での
     * 呼び出しは実際にはannounceしないこと、間隔が明ければ実際にannounceされること、
     * onion_addressがNULL/空文字列なら常にスキップされることを確認する --- */
    {
        const char *reannounce_onion = "f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion";

        sqlite3_stmt *count_stmt16 = NULL;
        sqlite3_prepare_v2(object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1,
                            &count_stmt16, NULL);
        sqlite3_bind_int(count_stmt16, 1, (int)BM_OBJECT_ONIONPEER);
#define ONIONPEER_COUNT16()                                                                    \
    (sqlite3_reset(count_stmt16), sqlite3_step(count_stmt16) == SQLITE_ROW                      \
                                       ? sqlite3_column_int(count_stmt16, 0)                     \
                                       : -1)

        ctx.last_onion_announce = 0;
        int before16 = ONIONPEER_COUNT16();

        /* last_onion_announce==0(未announce)なので即座にannounceされるはず */
        bm_object_sync_maybe_reannounce_onion_peer(&ctx, reannounce_onion, 8444, 1000);
        CHECK(ONIONPEER_COUNT16() == before16 + 1,
              "the first call (last_onion_announce==0) should announce immediately");
        CHECK(ctx.last_onion_announce == 1000, "last_onion_announce should be updated to the given now");

        /* 間隔未満(interval-1秒後)なら何もしない */
        bm_object_sync_maybe_reannounce_onion_peer(&ctx, reannounce_onion, 8444, 1000 + 7380 - 1);
        CHECK(ONIONPEER_COUNT16() == before16 + 1,
              "a call within the reannounce interval should not create another object");
        CHECK(ctx.last_onion_announce == 1000, "last_onion_announce should not change when skipped");

        /* 間隔が明ければ(interval秒後ちょうど)再度announceする */
        bm_object_sync_maybe_reannounce_onion_peer(&ctx, reannounce_onion, 8444, 1000 + 7380);
        CHECK(ONIONPEER_COUNT16() == before16 + 2,
              "a call once the reannounce interval has elapsed should announce again");
        CHECK(ctx.last_onion_announce == 1000 + 7380, "last_onion_announce should advance to the new now");

        /* onion_addressがNULL/空文字列なら、間隔に関わらず常にスキップする */
        int before_null16 = ONIONPEER_COUNT16();
        bm_object_sync_maybe_reannounce_onion_peer(&ctx, NULL, 8444, 1000 + 7380 * 100);
        bm_object_sync_maybe_reannounce_onion_peer(&ctx, "", 8444, 1000 + 7380 * 100);
        CHECK(ONIONPEER_COUNT16() == before_null16,
              "NULL/empty onion_address should always be a no-op regardless of elapsed time");

#undef ONIONPEER_COUNT16
        sqlite3_finalize(count_stmt16);
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
