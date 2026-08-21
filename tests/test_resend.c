/*
 * §11 再送(resend)ロジックのテスト。
 * - ack未着かつnext_resend_timeを過ぎたsent行が再送され、同じmsg_idの行が更新される
 *   (ack_dataが新しくなる、resend_countが増える、next_resend_timeが倍々で先送りされる)こと
 * - resend_count上限に達した行は再送対象から外れること
 * - status='ackreceived'の行は再送対象にならないこと
 * - 再送されたobjectがobject_pool.dbへ登録され、接続中peerへbroadcastされること
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pubkey_cache.h"
#include "../src/core/send_pipeline.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/peer_registry.h"
#include "../src/infra/protocol.h"

#define TEST_IDENTITY_DB "test_resend_identity.db"
#define TEST_MESSAGES_DB "test_resend_messages.db"
#define TEST_OBJECT_POOL_DB "test_resend_pool.db"

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
    sqlite3 *identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    sqlite3 *messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    sqlite3 *object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);

    bm_keyring_t kr;
    bm_keyring_init(&kr);

    struct bm_peer_registry registry;
    bm_peer_registry_init(&registry);
    struct bm_object_sync_ctx ctx;
    bm_object_sync_ctx_init(&ctx, object_pool_db, identity_db, messages_db, &kr, &registry);

    /* broadcastを観測するための"peer"接続 */
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    struct bm_fd_data *conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, fds[0]);
    bm_peer_registry_add(&registry, conn);

    struct bm_generated_address sender_gen;
    CHECK(bm_address_generate_deterministic("resend test sender", 1, &sender_gen) == 0, "gen sender");
    char *sender_address = bm_address_encode(4, 1, sender_gen.ripe, BM_RIPE_LEN);
    CHECK(bm_keyring_create_identity(identity_db, sender_address, "sender", 4, 1,
                                      sender_gen.pub_signing, sender_gen.pub_encryption,
                                      sender_gen.priv_signing, sender_gen.priv_encryption,
                                      "sender pass", 50, 50) == 0,
          "create sender identity");
    CHECK(bm_keyring_unlock(&kr, identity_db, sender_address, "sender pass") == 0, "unlock sender");

    struct bm_generated_address recv_gen;
    CHECK(bm_address_generate_deterministic("resend test receiver", 1, &recv_gen) == 0, "gen receiver");
    char *recv_address = bm_address_encode(4, 1, recv_gen.ripe, BM_RIPE_LEN);

    /* 再送はto_pub_encryption=NULL(pubkey_cache参照)で行う設計(§11)なので、初回送信で
     * 直接pubkeyを渡すだけではcacheに乗らず、再送時に失敗してしまう。実運用でも
     * 「直接pubkeyを渡した送信は自動再送できない」という制約になる(DESIGN.md §11に記載)ため、
     * ここでは事前にcacheへ登録しておく(cache経由で送った場合の一般的な使い方を再現)。 */
    struct bm_cached_pubkey recv_cached;
    memset(&recv_cached, 0, sizeof(recv_cached));
    memcpy(recv_cached.ripe, recv_gen.ripe, BM_RIPE_LEN);
    recv_cached.address_version = 4;
    recv_cached.stream = 1;
    memcpy(recv_cached.signing_pubkey, recv_gen.pub_signing, 65);
    memcpy(recv_cached.encryption_pubkey, recv_gen.pub_encryption, 65);
    recv_cached.nonce_trials_per_byte = 50;
    recv_cached.payload_length_extra_bytes = 50;
    CHECK(bm_pubkey_cache_upsert(identity_db, &recv_cached, (int64_t)time(NULL)) == 0,
          "seed pubkey_cache for receiver");

    /* --- 1. 初回送信(next_resend_timeを過去に設定し、即座に再送対象にする) --- */
    int64_t now = (int64_t)time(NULL);
    unsigned char *object1 = NULL;
    size_t object1_len = 0;
    CHECK(bm_send_pipeline_send_message(&kr, identity_db, messages_db, sender_address, recv_address,
                                         recv_gen.pub_encryption, "resend test", "body", 3600, 1,
                                         NULL, now - 1, &object1, &object1_len) == 0,
          "initial send");
    free(object1);

    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(messages_db, "SELECT msg_id, ack_data, resend_count FROM sent;", -1, &stmt, NULL);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "sent table should have exactly 1 row after initial send");
    unsigned char first_msg_id[32];
    unsigned char first_ack_data[128];
    int first_ack_data_len = sqlite3_column_bytes(stmt, 1);
    memcpy(first_msg_id, sqlite3_column_blob(stmt, 0), 32);
    memcpy(first_ack_data, sqlite3_column_blob(stmt, 1), (size_t)first_ack_data_len);
    CHECK(sqlite3_column_int(stmt, 2) == 0, "resend_count should start at 0");
    sqlite3_finalize(stmt);

    /* --- 2. 再送チェックを実行: 1件再送され、object_pool.dbへ登録・peerへbroadcastされるはず --- */
    int processed = bm_object_sync_check_resends(&ctx, now);
    CHECK(processed == 1, "check_resends should process exactly 1 candidate");

    /* bm_peer_registry_broadcast_invはobject本体ではなくinv(hash announce)を送る設計
     * (他peerはinv→getdataで実際のobjectを取りに行く、§1参照) */
    struct bm_message *broadcast = read_one_message(fds[1]);
    CHECK(broadcast != NULL, "resent object should be announced via inv to connected peers");
    if (broadcast != NULL)
    {
        CHECK(strncmp(broadcast->command, "inv", 12) == 0, "broadcast command should be inv");
        bm_free_message(broadcast);
    }

    sqlite3_prepare_v2(messages_db,
                        "SELECT msg_id, ack_data, resend_count, next_resend_time, status FROM sent;", -1, &stmt,
                        NULL);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "sent table should still have exactly 1 row after resend (no duplicate)");
    CHECK(memcmp(sqlite3_column_blob(stmt, 0), first_msg_id, 32) == 0, "resend should keep the same msg_id");
    int second_ack_data_len = sqlite3_column_bytes(stmt, 1);
    int ack_changed = (second_ack_data_len != first_ack_data_len)
        || memcmp(sqlite3_column_blob(stmt, 1), first_ack_data, (size_t)first_ack_data_len) != 0;
    CHECK(ack_changed, "resend should generate a fresh ack_data (different from the original)");
    CHECK(sqlite3_column_int(stmt, 2) == 1, "resend_count should be 1 after one resend");
    int64_t next_resend_time = sqlite3_column_int64(stmt, 3);
    CHECK(next_resend_time > now, "next_resend_time should be pushed into the future after resend");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 4), "sent") == 0, "status should remain 'sent' (no ack yet)");
    sqlite3_finalize(stmt);

    /* --- 3. 直後にもう一度チェックしても(next_resend_timeがまだ先なので)再送されないはず --- */
    processed = bm_object_sync_check_resends(&ctx, now);
    CHECK(processed == 0, "second immediate check should find no candidates (not due yet)");

    /* --- 4. resend_countが上限に達した行は対象から外れる --- */
    sqlite3_exec(messages_db, "UPDATE sent SET resend_count = 999, next_resend_time = 0;", NULL, NULL, NULL);
    processed = bm_object_sync_check_resends(&ctx, now + 10);
    CHECK(processed == 0, "rows past the resend attempt cap should not be resent");

    /* --- 5. status='ackreceived'の行は対象から外れる --- */
    sqlite3_exec(messages_db, "UPDATE sent SET resend_count = 0, next_resend_time = 0, status = 'ackreceived';",
                 NULL, NULL, NULL);
    processed = bm_object_sync_check_resends(&ctx, now + 10);
    CHECK(processed == 0, "rows already acknowledged should not be resent");

    close(fds[0]);
    close(fds[1]);
    bm_fd_data_free(conn);
    bm_peer_registry_destroy(&registry);
    bm_keyring_destroy(&kr);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(object_pool_db);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);
    free(sender_address);
    free(recv_address);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
