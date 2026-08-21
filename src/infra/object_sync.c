#include "object_sync.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common/hash.h"
#include "../core/messages_store.h"
#include "../core/pubkey_cache.h"
#include "../core/trial_decrypt.h"
#include "../pow/pow_engine.h"
#include "object.h"
#include "object_store.h"

/* DoS対策の上限値(DESIGN.md §5.0、PyBitmessage protocol.py準拠) */
#define BM_MAX_INVENTORY_ITEMS 50000
#define BM_MAX_OBJECT_PAYLOAD_SIZE (1u << 18)

/* 期限切れobject GCの間引き間隔。dispatchが呼ばれるたびに毎回DELETEを試みるのは無駄なので、
 * このくらいの間隔を置く(厳密である必要はない) */
#define BM_OBJECT_SYNC_GC_INTERVAL_SECONDS 300

/* ackobject自体の受け入れ基準。send_pipeline.cのBM_ACK_NONCE_TRIALS_PER_BYTE等と対になる
 * ネットワーク既定値(誰宛でもない匿名objectのため、宛先固有の難易度は使えない) */
#define BM_ACK_MIN_NONCE_TRIALS_PER_BYTE 1000
#define BM_ACK_MIN_PAYLOAD_LENGTH_EXTRA_BYTES 1000

void bm_object_sync_ctx_init(struct bm_object_sync_ctx *ctx, sqlite3 *object_pool_db,
                              sqlite3 *identity_db, sqlite3 *messages_db, bm_keyring_t *keyring)
{
    ctx->object_pool_db = object_pool_db;
    ctx->identity_db = identity_db;
    ctx->messages_db = messages_db;
    ctx->keyring = keyring;
    ctx->last_gc = 0;
}

int bm_object_sync_gc(struct bm_object_sync_ctx *ctx, int64_t now)
{
    ctx->last_gc = (time_t)now;
    return bm_object_store_delete_expired(ctx->object_pool_db, now);
}

static void maybe_run_gc(struct bm_object_sync_ctx *ctx)
{
    time_t now = time(NULL);
    if (now - ctx->last_gc >= BM_OBJECT_SYNC_GC_INTERVAL_SECONDS)
    {
        int deleted = bm_object_sync_gc(ctx, (int64_t)now);
        if (deleted > 0)
        {
            fprintf(stderr, "[object_sync] GC: removed %d expired object(s)\n", deleted);
        }
    }
}

/*
 * §5.5: msgに平文で埋め込まれていたfullAckPayload(P2P "object"パケット、送信者が既にPoW済み)を
 * 検証し、object_pool_dbへ挿入する。受信者は追加のPoWを行わずそのまま自分のobject_poolへ
 * 取り込むだけでよい設計(以後getdataで配れる状態になる)。不正なpacket(実装バグ、または悪意ある
 * 相手が偽装した可能性もある)は無視する(msg受信自体の成否には影響させない、ベストエフォート)。
 */
static void validate_and_store_ack(sqlite3 *object_pool_db, const unsigned char *ack_payload,
                                    size_t ack_payload_len)
{
    struct bm_message *msg = NULL;
    size_t consumed = 0;
    if (bm_parse_message(ack_payload, ack_payload_len, &msg, &consumed) != BM_PARSE_OK
        || consumed != ack_payload_len || strncmp(msg->command, "object", 12) != 0)
    {
        bm_free_message(msg);
        return;
    }

    struct bm_object_header hdr;
    if (bm_object_parse_header(msg->payload, msg->length, &hdr) != 0)
    {
        bm_free_message(msg);
        return;
    }

    int64_t now = (int64_t)time(NULL);
    if ((int64_t)hdr.expires_time <= now)
    {
        bm_free_message(msg);
        return;
    }

    /* PoW検証: ネットワーク既定の最低難易度(誰宛でもない匿名objectのため宛先固有値は使えない) */
    const unsigned char *payload_no_nonce = msg->payload + 8;
    size_t payload_no_nonce_len = msg->length - 8;
    uint64_t ttl = (hdr.expires_time > (uint64_t)now) ? (hdr.expires_time - (uint64_t)now) : 0;
    uint64_t target = bm_pow_get_target(payload_no_nonce_len, ttl,
                                         BM_ACK_MIN_NONCE_TRIALS_PER_BYTE, BM_ACK_MIN_PAYLOAD_LENGTH_EXTRA_BYTES);
    unsigned char initial_hash[64];
    bm_sha512(payload_no_nonce, payload_no_nonce_len, initial_hash);
    if (bm_pow_trial_value(hdr.nonce, initial_hash) > target)
    {
        bm_free_message(msg);
        return;
    }

    unsigned char hash[32];
    bm_inventory_hash(msg->payload, msg->length, hash);
    bm_object_store_insert(object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                            msg->payload, msg->length, (int64_t)hdr.expires_time, now);
    bm_free_message(msg);
}

static void handle_object(struct bm_object_sync_ctx *ctx, const struct bm_message *msg)
{
    if (msg->length > BM_MAX_OBJECT_PAYLOAD_SIZE)
    {
        fprintf(stderr, "[object_sync] object too large (%u bytes), ignoring\n", msg->length);
        return;
    }

    struct bm_object_header hdr;
    if (bm_object_parse_header(msg->payload, msg->length, &hdr) != 0)
    {
        fprintf(stderr, "[object_sync] malformed object header, ignoring\n");
        return;
    }

    unsigned char hash[32];
    bm_inventory_hash(msg->payload, msg->length, hash);

    /* §5.5: ack突合せは「既知object」判定より前に、type問わず毎回試みる。ack objectは
     * validate_and_store_ack(自分がmsgを復号した際の先回り登録)で既にobject_pool.dbに
     * 入っている場合があり、その状態でネットワークから"改めて"届いたときに既知判定で
     * 早期returnしてしまうと、単一ノードが送信者・受信者両方のアイデンティティを持つ
     * ケース(自己宛て送信、テスト等)でack検知を取りこぼす。突合せ自体は軽い(sentテーブルの
     * 未確認行だけを舐める)ので、既知/未知に関わらず毎回呼んでよい。 */
    bm_messages_store_try_mark_ack_received(ctx->messages_db, hash);

    if (bm_object_store_has(ctx->object_pool_db, hash))
    {
        return; /* 既知object。以降の保存・型別処理は再実行しない(通常のflooding gossipで
                 * 重複受信するのは正常) */
    }

    int64_t now = (int64_t)time(NULL);
    bm_object_store_insert(ctx->object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                            msg->payload, msg->length, (int64_t)hdr.expires_time, now);

    if (hdr.object_type == BM_OBJECT_MSG)
    {
        unsigned char *ack_payload = NULL;
        size_t ack_payload_len = 0;
        if (bm_trial_decrypt_and_store(ctx->keyring, ctx->messages_db, msg->payload, msg->length,
                                        &ack_payload, &ack_payload_len) == 0)
        {
            fprintf(stderr, "[object_sync] msg decrypted and stored to inbox\n");
            if (ack_payload_len > 0)
            {
                validate_and_store_ack(ctx->object_pool_db, ack_payload, ack_payload_len);
            }
        }
        free(ack_payload);
    }
    else if (hdr.object_type == BM_OBJECT_PUBKEY)
    {
        struct bm_cached_pubkey cached;
        int parsed = -1;
        if (hdr.version == 2)
        {
            parsed = bm_parse_pubkey_v2(msg->payload, msg->length, &cached);
        }
        else if (hdr.version == 3)
        {
            parsed = bm_parse_pubkey_v3(msg->payload, msg->length, &cached);
        }
        /* version==4は「誰宛の候補か」というあて推量が要る(pubkey_cache.h参照)ため、
         * getpubkey自動化と合わせたTODO(DESIGN.md §11) */
        if (parsed == 0)
        {
            bm_pubkey_cache_upsert(ctx->identity_db, &cached, now);
            fprintf(stderr, "[object_sync] pubkey (v%" PRIu64 ") cached\n", hdr.version);
        }
    }
}

static void handle_inv(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn, const struct bm_message *msg)
{
    struct bm_inventory_message inv_msg;
    if (bm_parse_inventory_message(msg->payload, msg->length, &inv_msg) != 0)
    {
        fprintf(stderr, "[object_sync] malformed inv\n");
        return;
    }
    if (inv_msg.count > BM_MAX_INVENTORY_ITEMS)
    {
        fprintf(stderr, "[object_sync] inv with %" PRIu64 " items exceeds limit, ignoring\n", inv_msg.count);
        bm_free_inventory_message(&inv_msg);
        return;
    }

    unsigned char (*missing)[32] = inv_msg.count > 0 ? malloc(sizeof(*missing) * inv_msg.count) : NULL;
    size_t missing_count = 0;
    for (uint64_t i = 0; i < inv_msg.count; i++)
    {
        if (!bm_object_store_has(ctx->object_pool_db, inv_msg.items[i]))
        {
            memcpy(missing[missing_count], inv_msg.items[i], 32);
            missing_count++;
        }
    }
    bm_free_inventory_message(&inv_msg);

    if (missing_count > 0)
    {
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("getdata", missing, missing_count, &packet_len);
        if (packet != NULL)
        {
            if (write(conn->fd, packet, packet_len) != (ssize_t)packet_len)
            {
                fprintf(stderr, "[object_sync] failed to send getdata\n");
            }
            free(packet);
        }
    }
    free(missing);
}

static void handle_getdata(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn, const struct bm_message *msg)
{
    struct bm_inventory_message inv_msg;
    if (bm_parse_inventory_message(msg->payload, msg->length, &inv_msg) != 0)
    {
        fprintf(stderr, "[object_sync] malformed getdata\n");
        return;
    }
    if (inv_msg.count > BM_MAX_INVENTORY_ITEMS)
    {
        fprintf(stderr, "[object_sync] getdata with %" PRIu64 " items exceeds limit, ignoring\n", inv_msg.count);
        bm_free_inventory_message(&inv_msg);
        return;
    }

    for (uint64_t i = 0; i < inv_msg.count; i++)
    {
        unsigned char *payload = NULL;
        size_t payload_len = 0;
        if (bm_object_store_get(ctx->object_pool_db, inv_msg.items[i], &payload, &payload_len) != 0)
        {
            continue; /* 持っていない要求は黙って無視(切断まではしない) */
        }
        size_t packet_len = 0;
        unsigned char *packet = bm_create_packet("object", payload, payload_len, &packet_len);
        free(payload);
        if (packet != NULL)
        {
            if (write(conn->fd, packet, packet_len) != (ssize_t)packet_len)
            {
                fprintf(stderr, "[object_sync] failed to send object for getdata\n");
            }
            free(packet);
        }
    }
    bm_free_inventory_message(&inv_msg);
}

void bm_object_sync_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data)
{
    struct bm_object_sync_ctx *ctx = user_data;

    if (strncmp(msg->command, "version", 12) == 0)
    {
        struct bm_version_message ver;
        bm_parse_version_message(msg->payload, msg->length, &ver);
        fprintf(stderr, "[object_sync] version: v=%u services=%" PRIu64 " ua=%s\n",
                ver.version, ver.services, ver.user_agent);
        bm_free_version_message(&ver);
        if (bm_reply_verack(conn) != 0)
        {
            fprintf(stderr, "[object_sync] failed to reply verack\n");
        }
    }
    else if (strncmp(msg->command, "verack", 12) == 0)
    {
        fprintf(stderr, "[object_sync] verack received\n");
    }
    else if (strncmp(msg->command, "ping", 12) == 0)
    {
        if (bm_reply_pong(conn) != 0)
        {
            fprintf(stderr, "[object_sync] failed to reply pong\n");
        }
    }
    else if (strncmp(msg->command, "addr", 12) == 0)
    {
        struct bm_addr_message addr_msg;
        if (bm_parse_addr_message(msg->payload, msg->length, &addr_msg) == 0)
        {
            fprintf(stderr, "[object_sync] addr: %" PRIu64 " entries (TODO: peer_manager未実装)\n",
                    addr_msg.count);
            bm_free_addr_message(&addr_msg);
        }
    }
    else if (strncmp(msg->command, "inv", 12) == 0)
    {
        handle_inv(ctx, conn, msg);
    }
    else if (strncmp(msg->command, "getdata", 12) == 0)
    {
        handle_getdata(ctx, conn, msg);
    }
    else if (strncmp(msg->command, "object", 12) == 0)
    {
        handle_object(ctx, msg);
    }
    else
    {
        char command[13] = {0};
        memcpy(command, msg->command, 12);
        fprintf(stderr, "[object_sync] unhandled command: %s\n", command);
    }

    maybe_run_gc(ctx);
}
