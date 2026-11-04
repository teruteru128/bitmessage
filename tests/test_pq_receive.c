/*
 * §11 2026-11-04 項目55の段5: ポスト量子拡張(v5)のobjectの受信処理(infra/object_sync.cの分岐と、
 * その先のcore層)のテスト。DESIGN-PQ.md §9.1のフェーズ2。
 *
 * 背景: 段4までで、v5のアドレスは作ってunlockできるが、v5のobjectは中継されるだけで中身は
 * 誰も見ていなかった。この段で4種類のobjectの受信を実行時フラグ([pq] enabled)の後ろに入れた。
 * 実際の経路を通すため、ネットワーク既定の難易度のPoWを払ったobjectをbm_object_sync_dispatchへ
 * 渡す(7.8KBのobjectは1本あたり約900万回の試行なので、同じobjectをプールから消して使い回す)。
 * dispatchを通す必要が無い検査は、PoW無しのobjectをcore層の関数へ直接渡す。
 *
 * §11 2026-11-04 項目57: msgとbroadcastの差出人の公開鍵を保存するようになったので、その確認を足した。
 * 送信側との往復はtest_pq_send.c。
 *
 * 検証観点:
 * 1. フラグ無効: 4種類とも保存はする(中継は変わらない)が、中身は処理しないこと
 * 2. getpubkey: ロック中は応答しないこと、unlock後は自分のpubkeyを返すこと(tagが合い、
 *    署名・idの検証まで通り、bitfieldがDOESACK)、2回目はキャッシュを再利用してPoWし直さないこと、
 *    ヘッダのstreamがidentityと違う要求には応答しないこと
 * 3. pubkey: 要求していなければ保存しないこと、要求していれば保存して要求が消えること
 * 4. msg: inboxへ保存されること(宛先・差出人・件名・本文)、埋め込まれたackがプールへ入ること、
 *    他のv5 identityが同時にunlockされていても宛先を取り違えないこと、ロック中は読めないこと、
 *    to_idが違うもの・fromAddressVersionが5でないもの・差出人のアドレスが列の幅を超えるものを
 *    受け取らないこと
 * 5. backfill: unlock後にプールの過去のmsgが読めること(1件版・複数アドレス版・全件版)、
 *    対象外のアドレスでは読まないこと
 * 6. broadcast: 購読していれば保存すること(to=from)、購読していなければ保存しないこと、
 *    v4以前の購読が混ざっていても動くこと
 */

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/common/address_limits.h"
#include "../src/common/hash.h"
#include "../src/core/address.h"
#include "../src/core/identity_store.h"
#include "../src/core/keyring.h"
#include "../src/core/messages_store.h"
#include "../src/core/pq_keyring.h"
#include "../src/core/pq_pubkey_cache.h"
#include "../src/core/trial_decrypt.h"
#include "../src/infra/object.h"
#include "../src/infra/object_store.h"
#include "../src/infra/object_sync.h"
#include "../src/infra/protocol.h"
#include "../src/pow/pow_engine.h"
#include "../src/pq/pq_object.h"

#define TEST_IDENTITY_DB "test_pq_receive_identity.db"
#define TEST_MESSAGES_DB "test_pq_receive_messages.db"
#define TEST_OBJECT_POOL_DB "test_pq_receive_pool.db"
#define STORE_PASS "pq receive store pass"
#define MSG_ENCODING_SIMPLE 2
#define SIMPLE_BODY "Subject:pq subject\nBody:pq body"

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
        fprintf(stderr, "failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }
    return db;
}

struct env
{
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    sqlite3 *object_pool_db;
    bm_keyring_t kr;
    struct bm_peer_registry registry;
    struct bm_object_sync_ctx ctx;
    int fds[2];
    struct bm_fd_data *conn;
};

/* nonce(8byte BE)を前置してobjectを作る(mallocで返す、payloadは解放する) */
static unsigned char *attach_nonce(unsigned char *payload, size_t payload_len, uint64_t nonce, size_t *out_len)
{
    unsigned char *object = malloc(8 + payload_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);
    *out_len = 8 + payload_len;
    return object;
}

/* ネットワーク既定の難易度のPoWを払う。TTLが短いのは期待試行回数を抑えるため。dispatch時点ではTTLが
 * さらに縮むので目標値は緩くなる方向にしか動かない */
static unsigned char *with_network_pow(unsigned char *payload, size_t payload_len, uint64_t ttl, size_t *out_len)
{
    uint64_t target = bm_pow_get_target(payload_len, ttl, 1000, 1000);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);
    return attach_nonce(payload, payload_len, nonce, out_len);
}

static void deliver(struct env *e, const unsigned char *object, size_t object_len)
{
    struct bm_message msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.command, "object", 6);
    msg.length = (uint32_t)object_len;
    msg.payload = (unsigned char *)object;
    bm_object_sync_dispatch(e->conn, &msg, &e->ctx);
}

/* 同じobjectをもう一度「未知のもの」として届けられるように、プールを空にする */
static void forget_pool(struct env *e)
{
    sqlite3_exec(e->object_pool_db, "DELETE FROM objects;", NULL, NULL, NULL);
}

static void forget_inbox(struct env *e)
{
    sqlite3_exec(e->messages_db, "DELETE FROM inbox;", NULL, NULL, NULL);
}

static int count_objects(struct env *e, int object_type)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e->object_pool_db, "SELECT COUNT(*) FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, object_type);
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

static size_t inbox_count(struct env *e)
{
    struct bm_inbox_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_inbox(e->messages_db, NULL, &list, &count) != 0)
    {
        return (size_t)-1;
    }
    bm_inbox_message_list_free(list, count);
    return count;
}

/* inboxに1件だけあり、その内容が期待どおりか */
static int inbox_is_only(struct env *e, const char *to, const char *from, const char *subject, const char *body)
{
    struct bm_inbox_message *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_inbox(e->messages_db, NULL, &list, &count) != 0)
    {
        return 0;
    }
    int ok = count == 1 && strcmp(list[0].to_address, to) == 0 && strcmp(list[0].from_address, from) == 0
             && strcmp(list[0].subject, subject) == 0 && strcmp(list[0].body, body) == 0;
    bm_inbox_message_list_free(list, count);
    return ok;
}

/* プール内のpubkey objectを1本取り出す(mallocで返す) */
static unsigned char *first_pubkey_object(struct env *e, size_t *out_len)
{
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(e->object_pool_db, "SELECT payload FROM objects WHERE object_type = ?1;", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, BM_OBJECT_PUBKEY);
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

static unsigned char *build_getpubkey_object(const struct bm_pqv5_identity *to, uint64_t ttl, size_t *out_len)
{
    size_t len = 0;
    unsigned char *payload =
        bm_pq_build_getpubkey(5, to->stream, to->id, (uint64_t)time(NULL) + ttl, &len);
    return with_network_pow(payload, len, ttl, out_len);
}

/* fromからtoへのmsgのpayload(PoW前)を作る。ackはNULL可 */
static unsigned char *build_msg_payload(const struct bm_pqv5_identity *from, const unsigned char to_id[BM_PQV5_ID_LEN],
                                        const unsigned char to_kem_pk[BM_PQV5_KEM_PK_LEN], const unsigned char *ack,
                                        size_t ack_len, uint64_t ttl, size_t *out_len)
{
    struct bm_pq_sender_info info;
    info.identity = from;
    info.bitfield = 1;
    info.nonce_trials_per_byte = 1000;
    info.payload_length_extra_bytes = 1000;
    return bm_pq_build_msg(&info, 1, to_id, to_kem_pk, MSG_ENCODING_SIMPLE, (const unsigned char *)SIMPLE_BODY,
                           strlen(SIMPLE_BODY), ack, ack_len, (uint64_t)time(NULL) + ttl, out_len);
}

/* PoW無しでcore層へ直接渡すためのobject(nonceは0) */
static unsigned char *as_object_without_pow(unsigned char *payload, size_t payload_len, size_t *out_len)
{
    return attach_nonce(payload, payload_len, 0, out_len);
}

int main(void)
{
    struct env *e = calloc(1, sizeof(*e));
    e->identity_db = open_fresh_db(TEST_IDENTITY_DB, bm_identity_store_init_schema);
    e->messages_db = open_fresh_db(TEST_MESSAGES_DB, bm_messages_store_init_schema);
    e->object_pool_db = open_fresh_db(TEST_OBJECT_POOL_DB, bm_object_store_init_schema);
    bm_keyring_init(&e->kr);
    bm_peer_registry_init(&e->registry);
    bm_object_sync_ctx_init(&e->ctx, e->object_pool_db, e->identity_db, e->messages_db, NULL, &e->kr, &e->registry,
                            NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, e->fds) == 0, "socketpair");
    e->conn = bm_fd_data_new(BM_FD_CLIENT_SOCKET, e->fds[0]);

    /* 受信者(identity.dbに保存)、同時にunlockする別のidentity、送信者(保存しない)。
     * null_bytes=0は探索を省くため。受信者の難易度を1,1にしているのは自応答のPoWを軽くするため
     * (test_getpubkey_automation.cと同じ理由。応答のPoWはidentity自身の難易度で計算される) */
    static struct bm_pqv5_identity receiver;
    static struct bm_pqv5_identity other;
    static struct bm_pqv5_identity sender;
    CHECK(bm_pqv5_identity_generate_deterministic("pq receive receiver", 1, 0, 0, &receiver) == 0, "generate receiver");
    CHECK(bm_pqv5_identity_generate_deterministic("pq receive other", 1, 0, 0, &other) == 0, "generate other");
    CHECK(bm_pqv5_identity_generate_deterministic("pq receive sender", 1, 0, 0, &sender) == 0, "generate sender");
    char receiver_address[BM_KEYRING_MAX_ADDRESS_LEN];
    char other_address[BM_KEYRING_MAX_ADDRESS_LEN];
    CHECK(bm_pq_keyring_create_identity(e->identity_db, &receiver, "receiver", STORE_PASS, 1, 1, 1000, receiver_address)
              == 0,
          "store receiver");
    CHECK(bm_pq_keyring_create_identity(e->identity_db, &other, "other", STORE_PASS, 1, 1, 1000, other_address) == 0,
          "store other");
    char *sender_address = bm_pqv5_address_encode(5, 1, sender.id);
    CHECK(sender_address != NULL, "encode sender address");

    /* dispatchへ渡すobject(PoWはそれぞれ1回だけ) */
    size_t getpubkey_len = 0;
    unsigned char *getpubkey_object = build_getpubkey_object(&receiver, 300, &getpubkey_len);

    struct bm_pq_sender_info sender_info;
    sender_info.identity = &sender;
    sender_info.bitfield = 1;
    sender_info.nonce_trials_per_byte = 1000;
    sender_info.payload_length_extra_bytes = 1000;
    size_t len = 0;
    unsigned char *payload = bm_pq_build_pubkey(&sender_info, (uint64_t)time(NULL) + 300, &len);
    size_t pubkey_len = 0;
    unsigned char *pubkey_object = with_network_pow(payload, len, 300, &pubkey_len);

    /* ack: fullAckPayload(P2Pのobjectパケット)に包む、PoW済みの小さなobject */
    size_t ack_object_len = 0;
    unsigned char *ack_object = build_getpubkey_object(&other, 301, &ack_object_len);
    unsigned char ack_hash[32];
    bm_inventory_hash(ack_object, ack_object_len, ack_hash);
    size_t ack_packet_len = 0;
    unsigned char *ack_packet = bm_create_packet("object", ack_object, ack_object_len, &ack_packet_len);

    payload = build_msg_payload(&sender, receiver.id, receiver.kem_pk, ack_packet, ack_packet_len, 300, &len);
    size_t msg_len = 0;
    unsigned char *msg_object = with_network_pow(payload, len, 300, &msg_len);

    payload = bm_pq_build_broadcast(&sender_info, MSG_ENCODING_SIMPLE, (const unsigned char *)SIMPLE_BODY,
                                    strlen(SIMPLE_BODY), (uint64_t)time(NULL) + 300, &len);
    size_t broadcast_len = 0;
    unsigned char *broadcast_object = with_network_pow(payload, len, 300, &broadcast_len);

    int64_t now = (int64_t)time(NULL);

    /* --- 1. フラグ無効: 保存(中継)はするが、中身は処理しない --- */
    CHECK(e->ctx.pq_enabled == 0, "the flag is off by default");
    CHECK(bm_pq_keyring_unlock(&e->kr, e->identity_db, receiver_address, STORE_PASS, now) == 0, "unlock receiver");
    CHECK(bm_pq_pubkey_cache_record_request(e->identity_db, 5, 1, sender.id, now) == 0, "record a pubkey request");
    CHECK(bm_messages_store_add_subscription(e->messages_db, sender_address, "sender") == 0, "subscribe to the sender");
    deliver(e, getpubkey_object, getpubkey_len);
    deliver(e, pubkey_object, pubkey_len);
    deliver(e, msg_object, msg_len);
    deliver(e, broadcast_object, broadcast_len);
    CHECK(count_objects(e, BM_OBJECT_GETPUBKEY) == 1 && count_objects(e, BM_OBJECT_MSG) == 1
              && count_objects(e, BM_OBJECT_BROADCAST) == 1,
          "with the flag off, v5 objects are still stored for relaying");
    CHECK(count_objects(e, BM_OBJECT_PUBKEY) == 1, "with the flag off, only the received pubkey is in the pool (no response)");
    CHECK(inbox_count(e) == 0, "with the flag off, msg and broadcast are not decrypted");
    static struct bm_pq_pubkey_parsed cached;
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) != 0, "with the flag off, the pubkey is not cached");
    bm_keyring_lock_all(&e->kr);
    forget_pool(e);
    CHECK(bm_messages_store_remove_subscription(e->messages_db, sender_address) == 0, "unsubscribe");
    unsigned char sender_tag[32];
    bm_pqv5_derive_secret_and_tag(5, 1, sender.id, NULL, sender_tag);
    CHECK(bm_pq_pubkey_cache_clear_request(e->identity_db, sender_tag) == 0, "clear the request");

    e->ctx.pq_enabled = 1;

    /* --- 2. getpubkey --- */
    deliver(e, getpubkey_object, getpubkey_len);
    CHECK(count_objects(e, BM_OBJECT_PUBKEY) == 0, "no response for an address that is still locked");
    forget_pool(e);

    CHECK(bm_pq_keyring_unlock(&e->kr, e->identity_db, receiver_address, STORE_PASS, now) == 0, "unlock receiver again");
    deliver(e, getpubkey_object, getpubkey_len);
    CHECK(count_objects(e, BM_OBJECT_PUBKEY) == 1, "an unlocked identity responds to getpubkey with its pubkey");
    size_t response_len = 0;
    unsigned char *response = first_pubkey_object(e, &response_len);
    CHECK(response != NULL, "the response is in the pool");
    if (response != NULL)
    {
        struct bm_object_header hdr;
        CHECK(bm_object_parse_header(response, response_len, &hdr) == 0 && hdr.version == BM_PQ_PUBKEY_OBJECT_VERSION
                  && hdr.stream == 1,
              "the response is a v5 pubkey object");
        static struct bm_pq_pubkey_parsed parsed;
        CHECK(bm_pq_parse_pubkey(response, response_len, 5, 1, receiver.id, &parsed) == 0,
              "the response opens and verifies as the receiver's pubkey");
        CHECK(parsed.bitfield == 1, "the response advertises BITFIELD_DOESACK");
        CHECK(parsed.nonce_trials_per_byte == 1 && parsed.payload_length_extra_bytes == 1,
              "the response carries the identity's own difficulty");
        free(response);
    }

    /* 別のgetpubkey(TTLを変えて別のobjectにする)。応答キャッシュが効くのでPoWし直さない */
    size_t second_len = 0;
    unsigned char *second = build_getpubkey_object(&receiver, 302, &second_len);
    deliver(e, second, second_len);
    free(second);
    CHECK(count_objects(e, BM_OBJECT_PUBKEY) == 1, "a second getpubkey reuses the cached response");

    /* tagはstream 1のまま、ヘッダのstreamだけ2にした要求。PoWは書き換えた後に払う */
    {
        size_t wrong_len = 0;
        uint64_t ttl = 303;
        unsigned char *wrong = bm_pq_build_getpubkey(5, 1, receiver.id, (uint64_t)time(NULL) + ttl, &wrong_len);
        wrong[8 + 4 + 1] = 2; /* expiresTime(8) + objectType(4) + objectVersion(1) の次がstream */
        size_t wrong_object_len = 0;
        unsigned char *wrong_object = with_network_pow(wrong, wrong_len, ttl, &wrong_object_len);
        sqlite3_exec(e->identity_db, "DELETE FROM self_pubkey_response_cache;", NULL, NULL, NULL);
        forget_pool(e);
        deliver(e, wrong_object, wrong_object_len);
        CHECK(count_objects(e, BM_OBJECT_PUBKEY) == 0, "no response when the header stream differs from the identity");
        free(wrong_object);
    }
    forget_pool(e);

    /* --- 3. pubkey --- */
    deliver(e, pubkey_object, pubkey_len);
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) != 0, "a pubkey nobody requested is not cached");
    forget_pool(e);

    CHECK(bm_pq_pubkey_cache_record_request(e->identity_db, 5, 1, sender.id, now) == 0, "record a pubkey request again");
    struct bm_pq_pubkey_request request;
    CHECK(bm_pq_pubkey_cache_find_request(e->identity_db, sender_tag, &request) == 0
              && memcmp(request.id, sender.id, BM_PQV5_ID_LEN) == 0,
          "the request can be found by tag");
    deliver(e, pubkey_object, pubkey_len);
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) == 0, "a requested pubkey is cached");
    CHECK(memcmp(cached.sig_pk, sender.sig_pk, BM_PQV5_SIG_PK_LEN) == 0
              && memcmp(cached.kem_pk, sender.kem_pk, BM_PQV5_KEM_PK_LEN) == 0,
          "the cached keys are the sender's");
    CHECK(cached.bitfield == 1 && cached.nonce_trials_per_byte == 1000 && cached.payload_length_extra_bytes == 1000,
          "the cached parameters match the pubkey");
    CHECK(bm_pq_pubkey_cache_find_request(e->identity_db, sender_tag, &request) != 0, "the request is cleared");
    forget_pool(e);

    /* --- 4. msg --- */
    CHECK(bm_pq_keyring_unlock(&e->kr, e->identity_db, other_address, STORE_PASS, now) == 0, "unlock the other identity");
    sqlite3_exec(e->identity_db, "DELETE FROM pq_pubkey_cache;", NULL, NULL, NULL);
    deliver(e, msg_object, msg_len);
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) == 0
              && memcmp(cached.kem_pk, sender.kem_pk, BM_PQV5_KEM_PK_LEN) == 0,
          "the msg's sender key is cached, so a reply needs no getpubkey");
    CHECK(inbox_is_only(e, receiver_address, sender_address, "pq subject", "pq body"),
          "the msg is stored for the right identity, with subject and body decoded");
    CHECK(bm_object_store_has(e->object_pool_db, ack_hash), "the embedded ack is stored in the pool");
    forget_inbox(e);

    /* 宛先を絞った場合 */
    CHECK(bm_pq_trial_decrypt_and_store(&e->kr, other_address, e->identity_db, e->messages_db, msg_object, msg_len, now, NULL, NULL) != 0,
          "the msg does not open with the other identity's key");
    CHECK(inbox_count(e) == 0, "nothing is stored when it does not open");
    CHECK(bm_pq_trial_decrypt_and_store(&e->kr, receiver_address, e->identity_db, e->messages_db, msg_object, msg_len, now, NULL, NULL) == 0,
          "the msg opens when narrowed to the receiver");
    forget_inbox(e);

    /* to_idが別人: 受信者の鍵で開封はできるが受け取らない(なりすまし転送対策) */
    {
        size_t l = 0;
        size_t object_len = 0;
        unsigned char *p = build_msg_payload(&sender, other.id, receiver.kem_pk, NULL, 0, 300, &l);
        unsigned char *object = as_object_without_pow(p, l, &object_len);
        CHECK(bm_pq_trial_decrypt_and_store(&e->kr, NULL, e->identity_db, e->messages_db, object, object_len, now, NULL, NULL) != 0,
              "a msg whose to_id is someone else's is refused");
        free(object);
    }
    /* fromAddressVersionが5でない: 署名は正しいが、v5の鍵とアドレスが対応しない */
    {
        static struct bm_pqv5_identity forged;
        forged = sender;
        forged.version = 4;
        size_t l = 0;
        size_t object_len = 0;
        unsigned char *p = build_msg_payload(&forged, receiver.id, receiver.kem_pk, NULL, 0, 300, &l);
        unsigned char *object = as_object_without_pow(p, l, &object_len);
        CHECK(bm_pq_trial_decrypt_and_store(&e->kr, NULL, e->identity_db, e->messages_db, object, object_len, now, NULL, NULL) != 0,
              "a msg claiming fromAddressVersion 4 is refused");
        free(object);
    }
    /* 差出人のstreamが巨大でアドレスの文字列が列の幅を超える: 切り詰めて別のアドレスに見せない */
    {
        static struct bm_pqv5_identity huge_stream;
        huge_stream = sender;
        huge_stream.stream = UINT64_C(1) << 60;
        size_t l = 0;
        size_t object_len = 0;
        unsigned char *p = build_msg_payload(&huge_stream, receiver.id, receiver.kem_pk, NULL, 0, 300, &l);
        unsigned char *object = as_object_without_pow(p, l, &object_len);
        char *long_address = bm_pqv5_address_encode(5, huge_stream.stream, huge_stream.id);
        CHECK(long_address != NULL && strlen(long_address) >= BM_ADDRESS_STR_MAX,
              "sanity: this sender address does not fit the column");
        free(long_address);
        CHECK(bm_pq_trial_decrypt_and_store(&e->kr, NULL, e->identity_db, e->messages_db, object, object_len, now, NULL, NULL) != 0,
              "a msg whose sender address does not fit is refused");
        free(object);
    }
    CHECK(inbox_count(e) == 0, "none of the refused msgs reached the inbox");

    /* ロック中は読めない */
    CHECK(bm_keyring_lock(&e->kr, receiver_address) == 0, "lock the receiver");
    forget_pool(e);
    deliver(e, msg_object, msg_len);
    CHECK(inbox_count(e) == 0, "a msg for a locked identity stays unread");

    /* --- 5. backfill(プールには直前の配送でmsgが入っている) --- */
    CHECK(bm_pq_keyring_unlock(&e->kr, e->identity_db, receiver_address, STORE_PASS, now) == 0, "unlock receiver for backfill");
    CHECK(bm_object_sync_backfill_trial_decrypt(e->object_pool_db, e->identity_db, e->messages_db, &e->kr, other_address, now) == 0,
          "backfill for an unrelated v5 address reads nothing");
    CHECK(inbox_count(e) == 0, "still nothing in the inbox");
    CHECK(bm_object_sync_backfill_trial_decrypt(e->object_pool_db, e->identity_db, e->messages_db, &e->kr, receiver_address, now) == 1,
          "backfill for the receiver reads the old msg");
    CHECK(inbox_is_only(e, receiver_address, sender_address, "pq subject", "pq body"), "the old msg reached the inbox");
    forget_inbox(e);
    {
        const char *only_other[1] = {other_address};
        CHECK(bm_object_sync_backfill_trial_decrypt_addresses(e->object_pool_db, e->identity_db, e->messages_db, &e->kr, only_other, 1, now)
                  == 0,
              "multi-address backfill without the receiver reads nothing");
        const char *both[3] = {other_address, "BM-2cNotUnlockedAnywhere", receiver_address};
        CHECK(bm_object_sync_backfill_trial_decrypt_addresses(e->object_pool_db, e->identity_db, e->messages_db, &e->kr, both, 3, now) == 1,
              "multi-address backfill reads the msg once");
        forget_inbox(e);
    }
    CHECK(bm_object_sync_backfill_trial_decrypt(e->object_pool_db, e->identity_db, e->messages_db, &e->kr, NULL, now) == 1,
          "backfill over the whole keyring also reads v5 msgs");
    forget_inbox(e);
    forget_pool(e);

    /* --- 6. broadcast --- */
    sqlite3_exec(e->identity_db, "DELETE FROM pq_pubkey_cache;", NULL, NULL, NULL);
    deliver(e, broadcast_object, broadcast_len);
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) != 0,
          "an unsubscribed broadcast does not cache its sender's key");
    CHECK(inbox_count(e) == 0, "a broadcast from an address we do not subscribe to is not stored");
    forget_pool(e);

    /* v4以前の購読が混ざっていても、v5の購読を見つけられること */
    {
        struct bm_generated_address v4_gen;
        CHECK(bm_address_generate_deterministic("pq receive v4 subscription", 1, &v4_gen) == 0, "generate a v4 address");
        char *v4_address = bm_address_encode(4, 1, v4_gen.ripe, BM_RIPE_LEN);
        CHECK(bm_messages_store_add_subscription(e->messages_db, v4_address, "v4") == 0, "subscribe to a v4 address");
        free(v4_address);
    }
    CHECK(bm_messages_store_add_subscription(e->messages_db, sender_address, "sender") == 0, "subscribe to the sender again");
    deliver(e, broadcast_object, broadcast_len);
    CHECK(inbox_is_only(e, sender_address, sender_address, "pq subject", "pq body"),
          "a subscribed v5 broadcast is stored, with to_address equal to from_address");
    CHECK(bm_pq_pubkey_cache_lookup(e->identity_db, 5, 1, sender.id, &cached) == 0, "the broadcast's sender key is cached");

    free(broadcast_object);
    free(msg_object);
    free(ack_packet);
    free(ack_object);
    free(pubkey_object);
    free(getpubkey_object);
    free(sender_address);
    close(e->fds[0]);
    close(e->fds[1]);
    bm_fd_data_free(e->conn);
    bm_peer_registry_destroy(&e->registry);
    bm_keyring_destroy(&e->kr);
    sqlite3_close(e->identity_db);
    sqlite3_close(e->messages_db);
    sqlite3_close(e->object_pool_db);
    free(e);
    unlink(TEST_IDENTITY_DB);
    unlink(TEST_MESSAGES_DB);
    unlink(TEST_OBJECT_POOL_DB);

    if (failures > 0)
    {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_pq_receive: all checks passed\n");
    return EXIT_SUCCESS;
}
