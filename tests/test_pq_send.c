/*
 * §11 2026-11-04 項目57: ポスト量子拡張(v5)の送信側(core/send_pipeline.c)のテスト。
 * DESIGN-PQ.md §9.1のフェーズ3。
 *
 * 背景: フェーズ2(項目55)で受信側は動くようになったが、v5のobjectを実際に作るのはテスト・ベンチだけ
 * だった。ここでは別々のDBとkeyringを持つ2ノード(A・B)の間で、送信パイプラインが作ったobjectを
 * 実際の受信経路(bm_object_sync_dispatch)へ渡して往復させる。
 * Aの難易度はネットワーク既定(1000,1000)、Bは自応答のPoWを軽くするため(1,1)。Bの自応答はそのため
 * ネットワーク既定を満たさないので、dispatchではなくプールへ直接入れてプールからの解決を確かめる。
 *
 * 検証観点:
 * 1. pubkeyが分からない宛先へは送れないこと、v5とv4以前の間では送れないこと
 * 2. 要求の前にプールに届いていたpubkeyをtagで見つけて解決できること(無ければ失敗すること)。
 *    Bの自応答の期限が7日であること
 * 3. A→Bのmsgが受信経路を通ってBのinboxへ入ること(ネットワーク既定のPoWを満たす)
 * 4. Bはgetpubkey無しでAへ返信できること(msgが運ぶ鍵を保存している)。Bの難易度は低いが、Aの難易度で
 *    PoWしていること(そうでなければAのdispatchが受け取らない)
 * 5. ackがAへ届くとsentがackreceivedになること
 * 6. 再送(bm_object_sync_check_resends)がv5でも新しいobjectを作り、Bが読めること
 * 7. 自分のv5 identity宛はpubkeyキャッシュ無しで送れ、inboxへ直接入り、ackを要求しないこと
 * 8. broadcastを購読者が読めること
 * 9. 本文長の上限(BM_PQ_MAX_SUBJECT_PLUS_BODY_LEN)と最大のackでもobjectが2^18に収まること
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/hash.h"
#include "../src/common/message_limits.h"
#include "../src/core/address.h"
#include "../src/core/broadcast_decrypt.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pq_keyring.h"
#include "../src/core/pq_pubkey_cache.h"
#include "../src/core/send_pipeline.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"
#include "../src/pq/pq_object.h"

#define STORE_PASS "pq send store pass"
#define TTL 120

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

struct node
{
    char identity_path[64];
    char messages_path[64];
    char pool_path[64];
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    sqlite3 *pool_db;
    bm_keyring_t kr;
    struct bm_peer_registry registry;
    struct bm_object_sync_ctx ctx;
    int fds[2];
    struct bm_fd_data *conn;
};

static sqlite3 *open_fresh_db(const char *path, int (*init_schema)(sqlite3 *))
{
    unlink(path);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || init_schema(db) != 0)
    {
        fprintf(stderr, "failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }
    return db;
}

static void node_open(struct node *n, const char *name)
{
    snprintf(n->identity_path, sizeof(n->identity_path), "test_pq_send_%s_identity.db", name);
    snprintf(n->messages_path, sizeof(n->messages_path), "test_pq_send_%s_messages.db", name);
    snprintf(n->pool_path, sizeof(n->pool_path), "test_pq_send_%s_pool.db", name);
    n->identity_db = open_fresh_db(n->identity_path, bm_identity_store_init_schema);
    n->messages_db = open_fresh_db(n->messages_path, bm_messages_store_init_schema);
    n->pool_db = open_fresh_db(n->pool_path, bm_object_store_init_schema);
    bm_keyring_init(&n->kr);
    bm_peer_registry_init(&n->registry);
    bm_object_sync_ctx_init(&n->ctx, n->pool_db, n->identity_db, n->messages_db, NULL, &n->kr, &n->registry, NULL);
    n->ctx.pq_enabled = 1;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, n->fds) == 0, "socketpair");
    n->conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, n->fds[0]);
}

static void node_close(struct node *n)
{
    close(n->fds[0]);
    close(n->fds[1]);
    bm_fd_data_free(n->conn);
    bm_peer_registry_destroy(&n->registry);
    bm_keyring_destroy(&n->kr);
    sqlite3_close(n->identity_db);
    sqlite3_close(n->messages_db);
    sqlite3_close(n->pool_db);
    unlink(n->identity_path);
    unlink(n->messages_path);
    unlink(n->pool_path);
}

static void deliver(struct node *n, const unsigned char *object, size_t object_len)
{
    struct bm_message msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.command, "object", 6);
    msg.length = (uint32_t)object_len;
    msg.payload = (unsigned char *)object;
    bm_object_sync_dispatch(n->conn, &msg, &n->ctx);
}

/* identityを生成してnodeへ保存しunlockする */
static void add_identity(struct node *n, const char *passphrase, uint64_t difficulty, struct bm_pqv5_identity *out,
                         char address[BM_KEYRING_MAX_ADDRESS_LEN])
{
    CHECK(bm_pqv5_identity_generate_deterministic(passphrase, 1, 0, 0, out) == 0, "generate identity");
    CHECK(bm_pq_keyring_create_identity(n->identity_db, out, "label", STORE_PASS, difficulty, difficulty, 1000, address)
              == 0,
          "store identity");
    CHECK(bm_pq_keyring_unlock(&n->kr, n->identity_db, address, STORE_PASS, 1000) == 0, "unlock identity");
}

static int inbox_has(struct node *n, const char *to, const char *from, const char *subject, const char *body)
{
    struct bm_inbox_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_inbox(n->messages_db, NULL, &list, &count) != 0)
    {
        return 0;
    }
    int found = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (strcmp(list[i].to_address, to) == 0 && strcmp(list[i].from_address, from) == 0
            && strcmp(list[i].subject, subject) == 0 && strcmp(list[i].body, body) == 0)
        {
            found = 1;
        }
    }
    bm_inbox_message_list_free(list, count);
    return found;
}

/* sentの1行目の状態を調べる */
static int sent_status_is(struct node *n, const char *status)
{
    struct bm_sent_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_sent(n->messages_db, &list, &count) != 0)
    {
        return 0;
    }
    int ok = count >= 1 && strcmp(list[0].status, status) == 0;
    bm_sent_message_list_free(list, count);
    return ok;
}

static int count_objects(sqlite3 *pool, int type)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(pool, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, type);
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

/* プールの指定typeのobjectを1本取り出す(mallocで返す) */
static unsigned char *first_object(sqlite3 *pool, int type, size_t *out_len)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(pool, "SELECT payload FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, type);
    unsigned char *out = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        *out_len = (size_t)sqlite3_column_bytes(stmt, 0);
        out = malloc(*out_len);
        memcpy(out, sqlite3_column_blob(stmt, 0), *out_len);
    }
    sqlite3_finalize(stmt);
    return out;
}

int main(void)
{
    static struct node a;
    static struct node b;
    node_open(&a, "a");
    node_open(&b, "b");

    static struct bm_pqv5_identity a_id;
    static struct bm_pqv5_identity a2_id;
    static struct bm_pqv5_identity b_id;
    char a_address[BM_KEYRING_MAX_ADDRESS_LEN];
    char a2_address[BM_KEYRING_MAX_ADDRESS_LEN];
    char b_address[BM_KEYRING_MAX_ADDRESS_LEN];
    add_identity(&a, "pq send a", 1000, &a_id, a_address);
    add_identity(&a, "pq send a2", 1, &a2_id, a2_address);
    add_identity(&b, "pq send b", 1, &b_id, b_address);

    int64_t now = (int64_t)time(NULL);
    int64_t next_resend = now + BM_RESEND_INITIAL_INTERVAL_SECONDS;
    unsigned char *object = NULL;
    size_t object_len = 0;

    /* --- 1. 送れない場合 --- */
    CHECK(bm_send_pipeline_send_message(&a.kr, a.identity_db, a.messages_db, a_address, b_address, "s", "b", TTL, 1, NULL,
                                        next_resend, &object, &object_len)
              != 0,
          "sending fails while the recipient's pubkey is unknown");
    {
        struct bm_generated_address v4_gen;
        CHECK(bm_address_generate_deterministic("pq send v4", 1, &v4_gen) == 0, "generate a v4 address");
        char *v4_address = bm_address_encode(4, 1, v4_gen.ripe, BM_RIPE_LEN);
        CHECK(bm_keyring_create_identity(a.identity_db, v4_address, "v4", 4, 1, v4_gen.pub_signing, v4_gen.pub_encryption,
                                         v4_gen.priv_signing, v4_gen.priv_encryption, STORE_PASS, 1, 1)
                      == 0
                  && bm_keyring_unlock(&a.kr, a.identity_db, v4_address, STORE_PASS) == 0,
              "store a v4 identity");
        CHECK(bm_send_pipeline_send_message(&a.kr, a.identity_db, a.messages_db, a2_address, v4_address, "s", "b", TTL, 1,
                                            NULL, next_resend, &object, &object_len)
                  != 0,
              "v5 cannot send to v4, even to our own identity");
        CHECK(bm_send_pipeline_send_message(&a.kr, a.identity_db, a.messages_db, v4_address, a2_address, "s", "b", TTL, 1,
                                            NULL, next_resend, &object, &object_len)
                  != 0,
              "v4 cannot send to v5, even to our own identity");
        free(v4_address);
    }

    /* --- 2. pubkeyの解決: Bの自応答をAのプールへ入れて、プールから見つける --- */
    CHECK(bm_object_sync_resolve_pq_pubkey_from_pool(a.pool_db, a.identity_db, 5, 1, b_id.id, now) != 0,
          "resolving from an empty pool fails");
    {
        size_t len = 0;
        uint64_t ttl = 300;
        unsigned char *payload = bm_pq_build_getpubkey(5, 1, b_id.id, (uint64_t)now + ttl, &len);
        uint64_t nonce = bm_pow_run(payload, len, bm_pow_get_target(len, ttl, 1000, 1000));
        size_t request_len = 8 + len;
        unsigned char *request = malloc(request_len);
        for (int i = 0; i < 8; i++)
        {
            request[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
        }
        memcpy(request + 8, payload, len);
        free(payload);
        deliver(&b, request, request_len);
        free(request);
    }
    size_t response_len = 0;
    unsigned char *response = first_object(b.pool_db, BM_OBJECT_PUBKEY, &response_len);
    CHECK(response != NULL, "B responded to the getpubkey");
    if (response != NULL)
    {
        struct bm_object_header hdr;
        CHECK(bm_object_parse_header(response, response_len, &hdr) == 0
                  && hdr.expires_time >= (uint64_t)now + 7 * 24 * 60 * 60
                  && hdr.expires_time < (uint64_t)now + 7 * 24 * 60 * 60 + 300,
              "the v5 pubkey response expires in 7 days");
        unsigned char hash[32];
        bm_inventory_hash(response, response_len, hash);
        CHECK(bm_object_store_insert(a.pool_db, hash, BM_OBJECT_PUBKEY, 1, response, response_len,
                                     (int64_t)hdr.expires_time, now)
                  == 0,
              "put B's pubkey in A's pool, as if it had been relayed before A asked");
        CHECK(bm_object_sync_resolve_pq_pubkey_from_pool(a.pool_db, a.identity_db, 5, 1, a2_id.id, now) != 0,
              "another address's pubkey is not found by this tag");
        CHECK(bm_pq_pubkey_cache_record_request(a.identity_db, 5, 1, b_id.id, now) == 0, "record a pending request");
        CHECK(bm_object_sync_resolve_pq_pubkey_from_pool(a.pool_db, a.identity_db, 5, 1, b_id.id, now) == 0,
              "B's pubkey is resolved from the pool");
        unsigned char b_tag[32];
        bm_pqv5_derive_secret_and_tag(5, 1, b_id.id, NULL, b_tag);
        struct bm_pq_pubkey_request request;
        CHECK(bm_pq_pubkey_cache_find_request(a.identity_db, b_tag, &request) != 0, "the pending request is cleared");
        free(response);
    }

    /* --- 3. A→B --- */
    CHECK(bm_send_pipeline_send_message(&a.kr, a.identity_db, a.messages_db, a_address, b_address, "hello", "from a", TTL,
                                        1, NULL, next_resend, &object, &object_len)
              == 0,
          "A sends to B once the pubkey is known");
    CHECK(sent_status_is(&a, "sent"), "the msg is recorded in sent");
    unsigned char *a_to_b = object;
    size_t a_to_b_len = object_len;
    deliver(&b, a_to_b, a_to_b_len);
    CHECK(inbox_has(&b, b_address, a_address, "hello", "from a"), "B reads A's msg through the receive path");

    /* --- 4. 返信: Bはgetpubkey無しでAの鍵を持っていて、Aの難易度でPoWする --- */
    object = NULL;
    CHECK(bm_send_pipeline_send_message(&b.kr, b.identity_db, b.messages_db, b_address, a_address, "reply", "from b", TTL,
                                        1, NULL, next_resend, &object, &object_len)
              == 0,
          "B replies using the key that came with A's msg");
    if (object != NULL)
    {
        deliver(&a, object, object_len);
        free(object);
    }
    CHECK(inbox_has(&a, a_address, b_address, "reply", "from b"),
          "A accepts and reads the reply, so B met A's difficulty");

    /* --- 5. ack: Aのsentが覚えているackがBのプールへ取り込まれていること、それがAへ届くと確認済みに
     * なること --- */
    {
        sqlite3_stmt *stmt = NULL;
        sqlite3_prepare_v2(a.messages_db, "SELECT ack_data FROM sent LIMIT 1;", -1, &stmt, NULL);
        unsigned char ack_hash[32] = {0};
        unsigned char *ack = NULL;
        size_t ack_len = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            ack_len = (size_t)sqlite3_column_bytes(stmt, 0);
            ack = malloc(ack_len);
            memcpy(ack, sqlite3_column_blob(stmt, 0), ack_len);
            bm_inventory_hash(ack, ack_len, ack_hash);
        }
        sqlite3_finalize(stmt);
        CHECK(ack != NULL && bm_object_store_has(b.pool_db, ack_hash), "B stored the ack embedded in A's msg");
        if (ack != NULL)
        {
            deliver(&a, ack, ack_len);
            free(ack);
        }
        CHECK(sent_status_is(&a, "ackreceived"), "the ack marks A's sent row as received");
    }

    /* --- 6. 再送: ackを受け取っていない行を作って、再送の時刻を過ぎた状態でcheck_resendsへ渡す。
     * 渡すnowを未来へずらすと、作るobjectの期限もずれて、dispatchの時点ではTTLが長く見えPoWが
     * 足りなくなるので、行の方を過去にする --- */
    sqlite3_exec(a.messages_db, "UPDATE sent SET status = 'sent', next_resend_time = 1;", NULL, NULL, NULL);
    {
        int before = count_objects(a.pool_db, BM_OBJECT_MSG);
        CHECK(bm_object_sync_check_resends(&a.ctx, (int64_t)time(NULL)) == 1, "one sent row is due for a resend");
        CHECK(count_objects(a.pool_db, BM_OBJECT_MSG) == before + 1, "the resend put a new v5 msg in the pool");
        struct bm_sent_message *list = NULL;
        size_t count = 0;
        CHECK(bm_messages_store_list_sent(a.messages_db, &list, &count) == 0 && count == 1 && list[0].resend_count == 1,
              "the resend counted on the same sent row");
        bm_sent_message_list_free(list, count);
        /* Aのプールには再送されたmsgのほかにBからの返信もある(A→Bの1本目は入っていない)。全部Bへ届ける */
        sqlite3_exec(b.messages_db, "DELETE FROM inbox;", NULL, NULL, NULL);
        sqlite3_stmt *stmt = NULL;
        sqlite3_prepare_v2(a.pool_db, "SELECT payload FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, BM_OBJECT_MSG);
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            deliver(&b, sqlite3_column_blob(stmt, 0), (size_t)sqlite3_column_bytes(stmt, 0));
        }
        sqlite3_finalize(stmt);
        CHECK(inbox_has(&b, b_address, a_address, "hello", "from a"), "B reads the resent msg");
    }
    free(a_to_b);

    /* --- 7. 自分宛 --- */
    object = NULL;
    sqlite3_exec(a.messages_db, "DELETE FROM sent;", NULL, NULL, NULL);
    CHECK(bm_send_pipeline_send_message(&a.kr, a.identity_db, a.messages_db, a2_address, a_address, "note", "to myself",
                                        3600, 1, NULL, next_resend, &object, &object_len)
              == 0,
          "sending to our own v5 identity needs no cached pubkey");
    CHECK(inbox_has(&a, a_address, a2_address, "note", "to myself"), "the copy goes straight to the inbox");
    CHECK(sent_status_is(&a, "msgsentnoackexpected"), "no ack is expected from ourselves");
    free(object);

    /* --- 8. broadcast(難易度1のidentityからで、PoW無しの受信経路へは渡さない) --- */
    object = NULL;
    CHECK(bm_send_pipeline_send_broadcast(&a.kr, a2_address, "news", "for subscribers", 3600, &object, &object_len) == 0,
          "a v5 broadcast is built");
    if (object != NULL)
    {
        CHECK(bm_pq_trial_decrypt_broadcast_and_store(b.identity_db, b.messages_db, object, object_len, 5, 1, a2_id.id, now)
                  == 0,
              "a subscriber opens the broadcast");
        CHECK(inbox_has(&b, a2_address, a2_address, "news", "for subscribers"), "the broadcast reached the inbox");
        static struct bm_pq_broadcast_parsed parsed;
        CHECK(bm_pq_parse_broadcast(object, object_len, 5, 1, a2_id.id, &parsed) == 0 && parsed.bitfield == 1,
              "the broadcast advertises BITFIELD_DOESACK");
        bm_pq_broadcast_parsed_free(&parsed);
        free(object);
    }

    /* --- 9. 本文長の上限。最大のack(level 2: 800byteの乱数を暗号化、パケットのヘッダ込みで1KB以内) --- */
    {
        size_t message_len = 8 + 6 + BM_PQ_MAX_SUBJECT_PLUS_BODY_LEN;
        unsigned char *message = calloc(1, message_len);
        unsigned char *ack = calloc(1, 1000);
        struct bm_pq_sender_info info;
        info.identity = &a_id;
        info.bitfield = 1;
        info.nonce_trials_per_byte = UINT64_MAX; /* varintが最長の9byteになる */
        info.payload_length_extra_bytes = UINT64_MAX;
        size_t len = 0;
        unsigned char *payload = bm_pq_build_msg(&info, 1, b_id.id, b_id.kem_pk, 2, message, message_len, ack, 1000,
                                                 (uint64_t)now + TTL, &len);
        CHECK(payload != NULL && 8 + len <= (1u << 18),
              "the longest v5 msg with the largest ack fits in an object");
        free(payload);
        free(ack);
        free(message);
    }

    node_close(&a);
    node_close(&b);

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_pq_send: all checks passed\n");
    return EXIT_SUCCESS;
}
