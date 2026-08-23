#include "object_sync.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common/hash.h"
#include "../common/logging.h"
#include "../common/varint.h"
#include "../core/address.h"
#include "../core/broadcast_decrypt.h"
#include "../core/message_builder.h"
#include "../core/messages_store.h"
#include "../core/peer_manager.h"
#include "../core/pubkey_cache.h"
#include "../core/send_pipeline.h"
#include "../core/trial_decrypt.h"
#include "../pow/pow_engine.h"
#include "dandelion.h"
#include "object.h"
#include "object_store.h"

/* DoS対策の上限値(DESIGN.md §5.0、PyBitmessage protocol.py準拠) */
#define BM_MAX_INVENTORY_ITEMS 50000
#define BM_MAX_OBJECT_PAYLOAD_SIZE (1u << 18)

/* 期限切れobject GCの間引き間隔。dispatchが呼ばれるたびに毎回DELETEを試みるのは無駄なので、
 * このくらいの間隔を置く(厳密である必要はない) */
#define BM_OBJECT_SYNC_GC_INTERVAL_SECONDS 300

/* 再送チェックの間引き間隔(§11)。next_resend_time自体は分単位以上の粒度なので、
 * これくらいの頻度で十分 */
#define BM_OBJECT_SYNC_RESEND_CHECK_INTERVAL_SECONDS 300

/* §11 受信object全般のPoW検証。宛先固有の難易度は分からない(pubkey_cacheに無い相手も
 * 受信しうる)ため、ネットワーク既定の最低難易度を全objectで一律に要求する
 * (send_pipeline.cのBM_ACK_NONCE_TRIALS_PER_BYTE等と同じ値)。 */
#define BM_NETWORK_MIN_NONCE_TRIALS_PER_BYTE 1000
#define BM_NETWORK_MIN_PAYLOAD_LENGTH_EXTRA_BYTES 1000

/* 自分のpubkeyで応答する際のobjectのTTL(§11 getpubkey要求の自動化)。PyBitmessageの
 * pubkey告知の目安(数週間)を参考にした固定値。 */
#define BM_PUBKEY_RESPONSE_TTL_SECONDS (28 * 24 * 60 * 60)

void bm_object_sync_ctx_init(struct bm_object_sync_ctx *ctx, sqlite3 *object_pool_db,
                              sqlite3 *identity_db, sqlite3 *messages_db, sqlite3 *peers_db,
                              bm_keyring_t *keyring, struct bm_peer_registry *registry,
                              const char *user_agent)
{
    ctx->object_pool_db = object_pool_db;
    ctx->identity_db = identity_db;
    ctx->messages_db = messages_db;
    ctx->peers_db = peers_db;
    ctx->keyring = keyring;
    ctx->registry = registry;
    ctx->user_agent = user_agent;
    ctx->last_gc = 0;
    ctx->last_resend_check = 0;
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
            bm_log("[object_sync] GC: removed %d expired object(s)\n", deleted);
        }
    }
}

int bm_object_sync_check_resends(struct bm_object_sync_ctx *ctx, int64_t now)
{
    ctx->last_resend_check = (time_t)now;

    struct bm_sent_resend_candidate *candidates = NULL;
    size_t count = 0;
    if (bm_messages_store_list_resend_candidates(ctx->messages_db, now, BM_RESEND_MAX_ATTEMPTS,
                                                  &candidates, &count) != 0)
    {
        return 0;
    }

    for (size_t i = 0; i < count; i++)
    {
        struct bm_sent_resend_candidate *c = &candidates[i];
        int new_resend_count = c->resend_count + 1;
        int64_t next_resend_time = now + (int64_t)BM_RESEND_INITIAL_INTERVAL_SECONDS * (1LL << new_resend_count);

        unsigned char *object = NULL;
        size_t object_len = 0;
        int rc = bm_send_pipeline_send_message(ctx->keyring, ctx->identity_db, ctx->messages_db,
                                                c->from_address, c->to_address, NULL,
                                                c->subject, c->body, (uint64_t)c->ttl, c->ack_stealth_level,
                                                c->msg_id, next_resend_time, &object, &object_len);
        if (rc == 0)
        {
            struct bm_object_header hdr;
            if (bm_object_parse_header(object, object_len, &hdr) == 0)
            {
                unsigned char hash[32];
                bm_inventory_hash(object, object_len, hash);
                if (!bm_object_store_has(ctx->object_pool_db, hash))
                {
                    bm_object_store_insert(ctx->object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                                            object, object_len, (int64_t)hdr.expires_time, now);
                    if (ctx->registry != NULL)
                    {
                        bm_peer_registry_broadcast_inv(ctx->registry, &hash, 1, NULL);
                    }
                }
            }
            bm_log("[object_sync] resent message to %s (attempt %d)\n", c->to_address, new_resend_count);
            free(object);
        }
        else
        {
            bm_log(
                    "[object_sync] resend attempt skipped for %s (fromAddress not unlocked or "
                    "recipient pubkey not cached?)\n",
                    c->to_address);
        }
    }

    bm_sent_resend_candidate_list_free(candidates, count);
    return (int)count;
}

static void maybe_run_resend_check(struct bm_object_sync_ctx *ctx)
{
    time_t now = time(NULL);
    if (now - ctx->last_resend_check >= BM_OBJECT_SYNC_RESEND_CHECK_INTERVAL_SECONDS)
    {
        bm_object_sync_check_resends(ctx, (int64_t)now);
    }
}

/*
 * §11: object(nonce込み、全長object_len)のnonceがネットワーク既定の最低難易度を満たすかを
 * 検証する。expires_timeが既にnowを過ぎている場合はtarget計算に使うttlを0とする
 * (=最も厳しい、最速で見つかるはずのtargetになる。期限切れ自体の拒否は呼び出し側の責務)。
 */
static int object_pow_is_valid(const unsigned char *object, size_t object_len,
                                const struct bm_object_header *hdr, int64_t now)
{
    const unsigned char *payload_no_nonce = object + 8;
    size_t payload_no_nonce_len = object_len - 8;
    uint64_t ttl = (hdr->expires_time > (uint64_t)now) ? (hdr->expires_time - (uint64_t)now) : 0;
    uint64_t target = bm_pow_get_target(payload_no_nonce_len, ttl, BM_NETWORK_MIN_NONCE_TRIALS_PER_BYTE,
                                         BM_NETWORK_MIN_PAYLOAD_LENGTH_EXTRA_BYTES);
    unsigned char initial_hash[64];
    bm_sha512(payload_no_nonce, payload_no_nonce_len, initial_hash);
    return bm_pow_trial_value(hdr->nonce, initial_hash) <= target;
}

/*
 * §5.5: msgに平文で埋め込まれていたfullAckPayload(P2P "object"パケット、送信者が既にPoW済み)を
 * 検証し、object_pool_dbへ挿入する。受信者は追加のPoWを行わずそのまま自分のobject_poolへ
 * 取り込むだけでよい設計(以後getdataで配れる状態になる)。不正なpacket(実装バグ、または悪意ある
 * 相手が偽装した可能性もある)は無視する(msg受信自体の成否には影響させない、ベストエフォート)。
 */
static void validate_and_store_ack(struct bm_object_sync_ctx *ctx, const struct bm_fd_data *except,
                                    const unsigned char *ack_payload, size_t ack_payload_len)
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
    if (!object_pow_is_valid(msg->payload, msg->length, &hdr, now))
    {
        bm_free_message(msg);
        return;
    }

    unsigned char hash[32];
    bm_inventory_hash(msg->payload, msg->length, hash);
    /* bm_object_store_insertはINSERT OR IGNOREのため既存行でも成功(0)を返す。新規挿入時のみ
     * broadcastしたいので、事前にhas()で判定する(handle_objectの主object処理と同じ流儀) */
    int already_known = bm_object_store_has(ctx->object_pool_db, hash);
    bm_object_store_insert(ctx->object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                            msg->payload, msg->length, (int64_t)hdr.expires_time, now);
    if (!already_known && ctx->registry != NULL)
    {
        bm_peer_registry_broadcast_inv(ctx->registry, &hash, 1, except);
    }
    bm_free_message(msg);
}

/*
 * §5.1/§11: 受信したgetpubkeyが自分の(keyringでunlock済みの)アドレス宛かどうかを判定し、
 * 該当すれば自分のpubkeyオブジェクトを組み立ててPoWし、object_pool.dbへ登録した上で
 * 全peer(除外無し、自分が新たに作った物なので§1の他object同様except=NULL)へbroadcastする。
 * unlockされていないアドレス宛の要求には応答できない(秘密鍵が必要な署名を作れないため、
 * keyringにロードされているアドレスのみ対応する設計)。
 */
static void handle_incoming_getpubkey(struct bm_object_sync_ctx *ctx, const struct bm_object_header *hdr,
                                       const struct bm_message *msg)
{
    const unsigned char *body = msg->payload + hdr->header_len;
    size_t body_len = msg->length - hdr->header_len;

    struct bm_unlocked_identity id;
    int found = 0;
    if (hdr->version <= 3)
    {
        if (body_len < BM_RIPE_LEN)
        {
            return;
        }
        found = bm_keyring_find_by_ripe(ctx->keyring, body, &id) ? 1 : 0;
    }
    else
    {
        if (body_len < 32)
        {
            return;
        }
        found = bm_keyring_find_by_tag(ctx->keyring, body, &id) ? 1 : 0;
    }
    if (!found)
    {
        return; /* 自分宛てではない、またはロックされたままのアドレス宛 */
    }

    unsigned char ripe[BM_RIPE_LEN];
    memcpy(ripe, id.ripe, sizeof(ripe));

    struct bm_identity_info info;
    memset(&info, 0, sizeof(info));
    info.address_version = id.address_version;
    info.stream = id.stream;
    memcpy(info.pub_signing, id.pub_signing, 65);
    memcpy(info.pub_encryption, id.pub_encryption, 65);
    memcpy(info.priv_signing, id.priv_signing, 32);
    info.nonce_trials_per_byte = id.nonce_trials_per_byte;
    info.payload_length_extra_bytes = id.payload_length_extra_bytes;
    uint64_t address_version = id.address_version;
    uint64_t stream = id.stream;
    OPENSSL_cleanse(&id, sizeof(id));

    /* §11 getpubkey応答のスロットリング: 直近作った応答がまだ有効期限内ならPoWを計算し
     * 直さず、既存objectのinvを再broadcastするだけにする(同じ宛先への短時間の連続要求に
     * 対し、正規のPoWを払われた場合でも毎回計算し直させられないようにするため) */
    int64_t now = (int64_t)time(NULL);
    unsigned char cached_hash[32];
    if (bm_pubkey_cache_get_self_response(ctx->identity_db, ripe, now, cached_hash) == 1
        && bm_object_store_has(ctx->object_pool_db, cached_hash))
    {
        if (ctx->registry != NULL)
        {
            bm_peer_registry_broadcast_inv(ctx->registry, &cached_hash, 1, NULL);
        }
        bm_log(
                "[object_sync] reused cached getpubkey response (v%" PRIu64 ", no PoW recomputation)\n",
                address_version);
        return;
    }

    uint64_t expires_time = (uint64_t)now + BM_PUBKEY_RESPONSE_TTL_SECONDS;
    size_t payload_len = 0;
    unsigned char *payload = NULL;
    if (address_version == 2)
    {
        payload = bm_build_pubkey_v2(&info, expires_time, &payload_len);
    }
    else if (address_version == 3)
    {
        payload = bm_build_pubkey_v3(&info, expires_time, &payload_len);
    }
    else
    {
        payload = bm_build_pubkey_v4(&info, ripe, expires_time, &payload_len);
    }
    if (payload == NULL)
    {
        return;
    }

    uint64_t target = bm_pow_get_target(payload_len, BM_PUBKEY_RESPONSE_TTL_SECONDS,
                                         info.nonce_trials_per_byte, info.payload_length_extra_bytes);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);

    unsigned char hash[32];
    bm_inventory_hash(object, object_len, hash);
    if (!bm_object_store_has(ctx->object_pool_db, hash))
    {
        bm_object_store_insert(ctx->object_pool_db, hash, BM_OBJECT_PUBKEY, (int)stream,
                                object, object_len, (int64_t)expires_time, now);
        bm_pubkey_cache_set_self_response(ctx->identity_db, ripe, hash, (int64_t)expires_time);
        if (ctx->registry != NULL)
        {
            bm_peer_registry_broadcast_inv(ctx->registry, &hash, 1, NULL);
        }
        bm_log("[object_sync] responded to getpubkey with our own pubkey (v%" PRIu64 ")\n",
                address_version);
    }
    free(object);
}

/*
 * §5.4/§11: 受信したbroadcastを、messages.dbのsubscriptions(購読先)に登録されている
 * アドレスそれぞれを候補として復号を試みる。成功した時点でinboxへ保存して打ち切る
 * (同じbroadcastが複数の購読先の"ふり"をして一致することは実質無い)。
 */
static void handle_incoming_broadcast(struct bm_object_sync_ctx *ctx, const struct bm_message *msg)
{
    struct bm_subscription *subs = NULL;
    size_t sub_count = 0;
    if (bm_messages_store_list_subscriptions(ctx->messages_db, &subs, &sub_count) != 0)
    {
        return;
    }

    for (size_t i = 0; i < sub_count; i++)
    {
        uint64_t candidate_version = 0;
        uint64_t candidate_stream = 0;
        unsigned char candidate_ripe[BM_RIPE_LEN];
        if (bm_address_decode(subs[i].address, &candidate_version, &candidate_stream, candidate_ripe) != 0)
        {
            continue;
        }
        if (bm_trial_decrypt_broadcast_and_store(ctx->messages_db, msg->payload, msg->length, candidate_version,
                                                  candidate_stream, candidate_ripe) == 0)
        {
            bm_log("[object_sync] broadcast decrypted (subscribed address %s)\n", subs[i].address);
            break;
        }
    }

    bm_subscription_list_free(subs);
}

/* RFC4648 base32(小文字、パディング無し)。§11 outbound Tor経路の強化: onionpeer objectの
 * ホストバイト列(v2=10byte→16文字、v3=35byte→56文字、どちらも5bit境界にきれいに乗るため
 * パディング不要)をonionアドレス文字列へ復元するために使う。out には len*8/5 バイト分の
 * 領域が必要(呼び出し側でlenを10または35に限定して呼ぶため常に割り切れる) */
static size_t base32_encode_lower(const unsigned char *data, size_t len, char *out)
{
    static const char ALPHABET[32] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t out_len = 0;
    uint64_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++)
    {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            out[out_len++] = ALPHABET[(buffer >> bits) & 0x1f];
        }
    }
    if (bits > 0)
    {
        out[out_len++] = ALPHABET[(buffer << (5 - bits)) & 0x1f];
    }
    return out_len;
}

/*
 * §11 outbound Tor経路の強化: PyBitmessage(class_singleWorker.pyのsendOnionPeerObj/
 * class_objectProcessor.pyのprocessonion)準拠のonionpeer object(BM_OBJECT_ONIONPEER)を
 * 受信し、v3 onionピア(56文字、35byte ed25519鍵ベース)をpeers.dbへ登録する。addr/version
 * メッセージの16byte固定node encodingとは異なりobjectペイロード末尾までを可変長のホスト
 * バイト列として使うため、v3もそのまま運べる(ワイヤーフォーマット: varint(port) ||
 * 0xfd87d87eeb43(OnionCat prefix) || onion鍵バイト列)。v2(10byte→16文字)はTorが2021年に
 * 廃止済みで実害が無いため無視する。
 */
static void handle_incoming_onionpeer(struct bm_object_sync_ctx *ctx, const struct bm_object_header *hdr,
                                       const struct bm_message *msg)
{
    static const unsigned char ONIONCAT_PREFIX[6] = {0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43};
    static const size_t V3_ONION_KEY_LEN = 35; /* 32byte ed25519 pubkey + 2byte checksum + 1byte version */

    const unsigned char *body = msg->payload + hdr->header_len;
    size_t body_len = msg->length - hdr->header_len;

    uint64_t port = 0;
    size_t port_len = bm_varint_decode(body, body_len, &port);
    if (port_len == 0 || port == 0 || port > 65535)
    {
        return;
    }
    const unsigned char *host = body + port_len;
    size_t host_len = body_len - port_len;

    if (host_len != sizeof(ONIONCAT_PREFIX) + V3_ONION_KEY_LEN
        || memcmp(host, ONIONCAT_PREFIX, sizeof(ONIONCAT_PREFIX)) != 0)
    {
        return; /* v2(10byte)や不正な形式は無視 */
    }

    char onion_address[56 + 6 + 1]; /* 56文字 + ".onion" + NUL */
    size_t b32_len = base32_encode_lower(host + sizeof(ONIONCAT_PREFIX), V3_ONION_KEY_LEN, onion_address);
    memcpy(onion_address + b32_len, ".onion", 7); /* ".onion" + NUL */

    if (ctx->peers_db != NULL
        && bm_peer_manager_upsert_learned(ctx->peers_db, onion_address, (int)port, (int)hdr->stream, 1,
                                           (int64_t)time(NULL), "onionpeer_obj") == 0)
    {
        bm_log("[object_sync] discovered v3 onion peer: %s:%" PRIu64 "\n", onion_address, port);
    }
}

/* §11: pubkey(28日)ほど長生きさせる必要は無い(恒久的なアイデンティティ情報ではなく
 * 「今どこに繋がるか」という一時的なピア発見情報のため)。api_server.cのgetpubkey要求
 * (2日)と同程度の中程度の寿命にする。この値が短いほどPoW計算(bm_pow_get_targetの
 * ttl引数)も軽くなり、daemon起動時にmain()を長時間ブロックしにくくなる副次効果もある */
#define BM_ONIONPEER_ANNOUNCE_TTL_SECONDS (2 * 24 * 60 * 60)

int bm_object_sync_announce_onion_peer(struct bm_object_sync_ctx *ctx, const char *onion_address, int port)
{
    int64_t now = (int64_t)time(NULL);
    uint64_t expires_time = (uint64_t)now + BM_ONIONPEER_ANNOUNCE_TTL_SECONDS;
    uint64_t stream = 1;

    size_t payload_len = 0;
    unsigned char *payload = bm_build_onionpeer(onion_address, (uint16_t)port, stream, expires_time, &payload_len);
    if (payload == NULL)
    {
        bm_log("[object_sync] failed to build onionpeer object (malformed onion address?)\n");
        return -1;
    }

    /* §11: 誰宛でもない匿名object(ack objectと同じ扱い)なのでネットワーク既定の最低難易度で
     * PoWする(getpubkey応答のように特定アイデンティティのnonce_trials_per_byteは無い) */
    uint64_t target = bm_pow_get_target(payload_len, BM_ONIONPEER_ANNOUNCE_TTL_SECONDS,
                                         BM_NETWORK_MIN_NONCE_TRIALS_PER_BYTE,
                                         BM_NETWORK_MIN_PAYLOAD_LENGTH_EXTRA_BYTES);
    uint64_t nonce = bm_pow_run(payload, payload_len, target);

    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    for (int i = 0; i < 8; i++)
    {
        object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
    }
    memcpy(object + 8, payload, payload_len);
    free(payload);

    unsigned char hash[32];
    bm_inventory_hash(object, object_len, hash);
    if (!bm_object_store_has(ctx->object_pool_db, hash))
    {
        bm_object_store_insert(ctx->object_pool_db, hash, BM_OBJECT_ONIONPEER, (int)stream, object, object_len,
                                (int64_t)expires_time, now);
        if (ctx->registry != NULL)
        {
            bm_peer_registry_broadcast_inv(ctx->registry, &hash, 1, NULL);
        }
        bm_log("[object_sync] announced our onion peer: %s:%d\n", onion_address, port);
    }
    free(object);
    return 0;
}

static void handle_object(struct bm_object_sync_ctx *ctx, const struct bm_fd_data *conn,
                           const struct bm_message *msg)
{
    if (msg->length > BM_MAX_OBJECT_PAYLOAD_SIZE)
    {
        bm_log("[object_sync] object too large (%u bytes), ignoring\n", msg->length);
        return;
    }

    struct bm_object_header hdr;
    if (bm_object_parse_header(msg->payload, msg->length, &hdr) != 0)
    {
        bm_log("[object_sync] malformed object header, ignoring\n");
        return;
    }

    int64_t now0 = (int64_t)time(NULL);
    if ((int64_t)hdr.expires_time <= now0)
    {
        bm_log("[object_sync] object already expired, ignoring\n");
        return;
    }
    /* §11: ネットワーク既定の最低難易度を満たさないobjectは受け入れない(悪意ある相手に
     * PoW無しのobjectで負荷をかけられるのを防ぐ、既知だった制限への対応) */
    if (!object_pow_is_valid(msg->payload, msg->length, &hdr, now0))
    {
        bm_log("[object_sync] insufficient PoW, ignoring\n");
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

    bm_object_store_insert(ctx->object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                            msg->payload, msg->length, (int64_t)hdr.expires_time, now0);
    if (ctx->registry != NULL)
    {
        bm_peer_registry_broadcast_inv(ctx->registry, &hash, 1, conn);
    }

    if (hdr.object_type == BM_OBJECT_MSG)
    {
        unsigned char *ack_payload = NULL;
        size_t ack_payload_len = 0;
        if (bm_trial_decrypt_and_store(ctx->keyring, ctx->messages_db, msg->payload, msg->length,
                                        &ack_payload, &ack_payload_len) == 0)
        {
            bm_log("[object_sync] msg decrypted and stored to inbox\n");
            if (ack_payload_len > 0)
            {
                validate_and_store_ack(ctx, conn, ack_payload, ack_payload_len);
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
        else if (hdr.version == 4)
        {
            /* 「誰宛の候補か」が必要(pubkey_cache.h参照)。自分がgetpubkeyを発行してpending
             * 登録している宛先を候補として順に試す(§11)。候補数は通常少数(未解決の宛先分)
             * なので線形に試して問題ない。 */
            struct bm_pubkey_request *pending = NULL;
            size_t pending_count = 0;
            if (bm_pubkey_cache_list_pending_requests(ctx->identity_db, &pending, &pending_count) == 0)
            {
                for (size_t i = 0; i < pending_count && parsed != 0; i++)
                {
                    parsed = bm_parse_pubkey_v4(msg->payload, msg->length, pending[i].ripe,
                                                 pending[i].address_version, pending[i].stream, &cached);
                }
                bm_pubkey_request_list_free(pending);
            }
        }
        if (parsed == 0)
        {
            bm_pubkey_cache_upsert(ctx->identity_db, &cached, now0);
            bm_pubkey_cache_clear_request(ctx->identity_db, cached.ripe);
            bm_log("[object_sync] pubkey (v%" PRIu64 ") cached\n", hdr.version);
        }
    }
    else if (hdr.object_type == BM_OBJECT_GETPUBKEY)
    {
        handle_incoming_getpubkey(ctx, &hdr, msg);
    }
    else if (hdr.object_type == BM_OBJECT_BROADCAST)
    {
        handle_incoming_broadcast(ctx, msg);
    }
    else if (hdr.object_type == BM_OBJECT_ONIONPEER)
    {
        handle_incoming_onionpeer(ctx, &hdr, msg);
    }
}

/*
 * §11「addrで教えられたホストのフィルタリング」。private/loopback/link-local/未指定/
 * マルチキャスト等、outbound接続先として意味が無い(あるいは教えられた情報を鵜呑みにして
 * 内部ネットワークへ接続を試みてしまう)アドレスを除外する。is_ipv4_mappedはipが
 * ::ffff:a.b.c.d形式かどうか(呼び出し側で判定済み)。ルーティング可能そうならreturn 1
 */
/* §11 2026-08-23: addr_msg由来の素のIPv6(非IPv4-mapped)は呼び出し側で一律filter済みのため、
 * ここではIPv4の非routable範囲だけを見ればよい(実ネットワーク上で本物のIPv6 peerが
 * 観測できておらず、garbageな16バイト値がfc00::/7等の除外範囲を運良く外れて素通りする
 * 問題があったための方針転換。詳細はDESIGN.md参照)。 */
static int is_routable_ipv4_peer_address(const unsigned char v4[4])
{
    if (v4[0] == 0)
    {
        return 0; /* 0.0.0.0/8 */
    }
    if (v4[0] == 10)
    {
        return 0; /* 10.0.0.0/8 */
    }
    if (v4[0] == 127)
    {
        return 0; /* 127.0.0.0/8 loopback */
    }
    if (v4[0] == 169 && v4[1] == 254)
    {
        return 0; /* 169.254.0.0/16 link-local */
    }
    if (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31)
    {
        return 0; /* 172.16.0.0/12 */
    }
    if (v4[0] == 192 && v4[1] == 168)
    {
        return 0; /* 192.168.0.0/16 */
    }
    if (v4[0] >= 224)
    {
        return 0; /* 224.0.0.0/4 multicast、240.0.0.0/4 reserved、255.255.255.255含む */
    }
    return 1;
}

static void handle_inv(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn, const struct bm_message *msg)
{
    struct bm_inventory_message inv_msg;
    if (bm_parse_inventory_message(msg->payload, msg->length, &inv_msg) != 0)
    {
        bm_log("[object_sync] malformed inv\n");
        return;
    }
    if (inv_msg.count > BM_MAX_INVENTORY_ITEMS)
    {
        bm_log("[object_sync] inv with %" PRIu64 " items exceeds limit, ignoring\n", inv_msg.count);
        bm_free_inventory_message(&inv_msg);
        return;
    }

    /* §9.5 Dandelion++ Stage 3: このメッセージがinv(通常、既に他ノードがfluff済み)なのか
     * dinv(stem中継、まだstem中)なのかを覚えておき、未所持hashについてのみ
     * bm_dandelion_note_sourceへ記録する(既知のhashは今後bm_dandelion_decideが呼ばれ
     * ないため記録不要)。inv/dinvはワイヤーフォーマットが同一なため、ここまでの処理
     * (パース・未所持判定・getdata送信)はStage 1から変わらず共通のまま */
    int is_dinv = (strncmp(msg->command, "dinv", 12) == 0);
    int64_t now = (int64_t)time(NULL);

    unsigned char (*missing)[32] = inv_msg.count > 0 ? malloc(sizeof(*missing) * inv_msg.count) : NULL;
    size_t missing_count = 0;
    for (uint64_t i = 0; i < inv_msg.count; i++)
    {
        if (!bm_object_store_has(ctx->object_pool_db, inv_msg.items[i]))
        {
            memcpy(missing[missing_count], inv_msg.items[i], 32);
            missing_count++;
            bm_dandelion_note_source(inv_msg.items[i], is_dinv, now);
        }
    }
    uint64_t received_count = inv_msg.count;
    bm_free_inventory_message(&inv_msg);

    /* §11 2026-08-23: これまで正常系(パース成功・上限内)には一切ログが無く、malformed/上限超過
     * といった異常系のログしか出ていなかった(listConnections調査中にユーザーが発見した
     * 「無言の切断」と同種の穴)。受信件数・未所持(=getdataを送る)件数を可視化する。 */
    bm_log("[object_sync] received %s: %" PRIu64 " item(s), %zu missing\n", msg->command, received_count,
            missing_count);

    if (missing_count > 0)
    {
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("getdata", missing, missing_count, &packet_len);
        if (packet != NULL)
        {
            if (bm_network_write_all(conn->fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) != 0)
            {
                bm_log("[object_sync] failed to send getdata\n");
            }
            else
            {
                conn->bytes_sent += (uint64_t)packet_len;
                /* §11 2026-08-24: これまで失敗時のログしか無く、正常系(実際に何件の
                 * getdataを送れたか)が可視化されていなかった(handle_inv/handle_getdata
                 * 受信側の可視化と同種の穴、ユーザー指摘)。 */
                bm_log("[object_sync] sent getdata: %zu item(s)\n", missing_count);
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
        bm_log("[object_sync] malformed getdata\n");
        return;
    }
    if (inv_msg.count > BM_MAX_INVENTORY_ITEMS)
    {
        bm_log("[object_sync] getdata with %" PRIu64 " items exceeds limit, ignoring\n", inv_msg.count);
        bm_free_inventory_message(&inv_msg);
        return;
    }

    uint64_t requested_count = inv_msg.count;
    size_t sent_count = 0;
    size_t not_found_count = 0;
    for (uint64_t i = 0; i < inv_msg.count; i++)
    {
        unsigned char *payload = NULL;
        size_t payload_len = 0;
        if (bm_object_store_get(ctx->object_pool_db, inv_msg.items[i], &payload, &payload_len) != 0)
        {
            not_found_count++;
            continue; /* 持っていない要求は黙って無視(切断まではしない) */
        }
        size_t packet_len = 0;
        unsigned char *packet = bm_create_packet("object", payload, payload_len, &packet_len);
        free(payload);
        if (packet != NULL)
        {
            if (bm_network_write_all(conn->fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) != 0)
            {
                bm_log("[object_sync] failed to send object for getdata\n");
            }
            else
            {
                sent_count++;
                conn->bytes_sent += (uint64_t)packet_len;
            }
            free(packet);
        }
    }
    bm_free_inventory_message(&inv_msg);

    /* §11 2026-08-23: inv受信の正常系ログ追加と同じ理由(ユーザーの指摘: 「外部から
     * getdataを1回でも受信したか、ログから確認できない」)。受信件数・実際に送れた件数・
     * 持っていなかった件数を可視化する。 */
    bm_log("[object_sync] received getdata: %" PRIu64 " item(s) requested, %zu sent, %zu not found\n",
            requested_count, sent_count, not_found_count);
}

/*
 * §11 2026-08-22発覚のバグ修正: outbound接続(BM_FD_CLIENT_SOCKET)が相手から実際に
 * version/verackを受け取った時点で初めてpeer_manager.cのratingへsuccessを記録する。
 * 以前はpeer_connector.cがTCP接続+自分のversion送信の成功だけでsuccessを記録していたが、
 * これは相手が実際に応答したかとは無関係な弱い基準で、「繋がるが直後に相手から切断される」
 * peerでも毎サイクル必ず成功扱いになり、network.cが切断時に記録するfailure(-0.1)を毎回
 * 打ち消してratingが上限1.0に張り付いたまま抜け出せないバグを引き起こしていた
 * (peer_connector.c参照)。inbound(BM_FD_SERVER_SOCKET、相手が接続してきた側)は
 * こちらが選んだ相手ではないため対象外(network.cの切断時failure記録と対称)。
 *
 * §11 2026-08-22発覚の追加バグ修正: SOCKS5(Tor)プロキシ有効時はconn->peer_addr
 * (getpeername)がプロキシ自身のアドレスになり、bm_network_extract_ip_portだけでは
 * peers.dbのどの行にも一致しないUPDATEになって静かに失敗し続けていた
 * (実際にbootstrap daemonで確認: SOCKS5有効化後、success/failureどちらの記録も
 * 一切反映されなくなっていた)。conn->logical_peer_ip(プロキシの有無に関わらず
 * peer_connector.cが設定する本来の接続先)を優先するbm_network_resolve_peer_ip_portを
 * 使うよう変更した(network.h参照)。 */
static void record_outbound_success(struct bm_object_sync_ctx *ctx, const struct bm_fd_data *conn)
{
    if (conn->type != BM_FD_CLIENT_SOCKET || ctx->peers_db == NULL)
    {
        return;
    }
    char ip[BM_PEER_IP_STRLEN];
    int port = 0;
    bm_network_resolve_peer_ip_port(conn, ip, sizeof(ip), &port);
    if (ip[0] != '\0')
    {
        bm_peer_manager_record_result(ctx->peers_db, ip, port, 1, 1);
    }
}

/* §11 2026-08-23: version/verack handshake完了時(=verack受信時)に1回だけ、自分が知っている
 * peer情報をその接続(conn)へ返す。PyBitmessage network/tcp.pyのset_connection_fully_
 * established内のsendAddr呼び出しに相当するタイミング。接続中の周期的な再送や、新規学習
 * したaddrのリアルタイム中継は行わない(PyBitmessage側もリアルタイム中継はflood/leak対策で
 * 無効化されている)。BM_ADDR_SHARE_MAX_COUNTはPyBitmessageの既定maxaddrperstreamsend=500に
 * 合わせた */
#define BM_ADDR_SHARE_MAX_COUNT 500

static void send_addr_reply(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn)
{
    if (ctx->peers_db == NULL)
    {
        return;
    }

    struct bm_peer_entry candidates[BM_ADDR_SHARE_MAX_COUNT];
    int candidate_count = 0;
    if (bm_peer_manager_list_shareable(ctx->peers_db, 1, (int64_t)time(NULL), candidates,
                                        BM_ADDR_SHARE_MAX_COUNT, &candidate_count)
        != 0)
    {
        return;
    }
    if (candidate_count == 0)
    {
        return;
    }

    static const unsigned char IPV4_MAPPED_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    struct bm_address_info *addresses = malloc(sizeof(struct bm_address_info) * (size_t)candidate_count);
    int n = 0;
    for (int i = 0; i < candidate_count; i++)
    {
        unsigned char v4[4];
        if (inet_pton(AF_INET, candidates[i].ip_address, v4) != 1)
        {
            continue; /* 通常起こらない想定(shareable候補はIPv4限定のはず)、念のためskip */
        }
        memcpy(addresses[n].ip, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX));
        memcpy(addresses[n].ip + 12, v4, 4);
        addresses[n].time = (uint64_t)candidates[i].last_seen;
        addresses[n].stream = (uint32_t)candidates[i].stream;
        addresses[n].services = candidates[i].services;
        addresses[n].port = (uint16_t)candidates[i].port;
        n++;
    }

    if (n > 0)
    {
        size_t packet_len = 0;
        unsigned char *packet = bm_create_addr_message(addresses, (size_t)n, &packet_len);
        if (packet != NULL)
        {
            if (bm_network_write_all(conn->fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) != 0)
            {
                bm_log("[object_sync] failed to send addr\n");
            }
            else
            {
                bm_log("[object_sync] sent addr (%d entries)\n", n);
                conn->bytes_sent += (uint64_t)packet_len;
            }
            free(packet);
        }
    }
    free(addresses);
}

/*
 * §11 2026-08-23: PyBitmessage本家(network/tcp.pyのsendBigInv)相当。verack受信=
 * handshake完了時に、自分が保有する全objectのhashを新規peerへ知らせる(本家のdocstring
 * 通り"Initiate inventory synchronisation")。これが無いと、新規に繋がったpeerから見て
 * 「何も持っていない役に立たないノード」に見えてしまい、相手からgetdataが一切来ない
 * (=自分が保有するobjectが他のnodeへ一切伝播しない)。addr送信と同じくverack受信時に
 * 1回だけ送る(定期的な再送はしない、本家も同様)。
 *
 * hashごとの実際のinv/dinv振り分けはbm_decide_propagation(DESIGN.md §9.2の差し込み点、
 * bm_peer_registry_broadcast_invと同じ経由方針)に委ねる。新規接続のconnがstem
 * successorとして選ばれていることは通常無い(選定はbm_dandelion_maybe_reshuffleが
 * 既存のoutbound接続の中から行うため)ので、実質的には「stemタイムアウト前でこの接続が
 * successorではないhash」=SKIPが除外され、それ以外がFLUFF(=通常のinv)としてまとめて
 * 送られる形になる。本家の「stem中のhashはbigInvから除外する」という方針と結果的に
 * 一致する。
 */
static void send_big_inv(struct bm_object_sync_ctx *ctx, struct bm_fd_data *conn)
{
    unsigned char(*hashes)[32] = NULL;
    size_t hash_count = 0;
    if (bm_object_store_list_hashes_by_stream(ctx->object_pool_db, 1, (int64_t)time(NULL), &hashes, &hash_count)
        != 0)
    {
        return;
    }
    if (hash_count == 0)
    {
        free(hashes);
        return;
    }

    unsigned char(*fluff)[32] = malloc(sizeof(*fluff) * hash_count);
    unsigned char(*stem)[32] = malloc(sizeof(*stem) * hash_count);
    /* §11 2026-08-24発覚: mallocの戻り値を確認していなかった(hash_countは現状1万件超、
     * 接続のたびに毎回この規模で呼ばれる)。失敗時にNULL参照でクラッシュしないよう
     * ガードする(daemon Aが原因不明で2回突然終了した件の調査中に発見、確証は無いが
     * 直接の原因候補として塞いでおく)。 */
    if (fluff == NULL || stem == NULL)
    {
        bm_log("[object_sync] send_big_inv: malloc failed for %zu hashes, aborting\n", hash_count);
        free(fluff);
        free(stem);
        free(hashes);
        return;
    }
    size_t fluff_count = 0;
    size_t stem_count = 0;
    for (size_t i = 0; i < hash_count; i++)
    {
        enum bm_propagation_mode mode = bm_decide_propagation(hashes[i], conn);
        if (mode == BM_PROPAGATE_FLUFF)
        {
            memcpy(fluff[fluff_count], hashes[i], 32);
            fluff_count++;
        }
        else if (mode == BM_PROPAGATE_STEM)
        {
            memcpy(stem[stem_count], hashes[i], 32);
            stem_count++;
        }
    }
    free(hashes);

    /* §11: 単一メッセージあたりBM_MAX_INVENTORY_ITEMS件まで(本家のMAX_OBJECT_COUNTと
     * 同じ50000。相手側もこの上限で受信するため超過分は複数メッセージに分ける) */
    for (size_t sent = 0; sent < fluff_count; sent += BM_MAX_INVENTORY_ITEMS)
    {
        size_t chunk = fluff_count - sent;
        if (chunk > BM_MAX_INVENTORY_ITEMS)
        {
            chunk = BM_MAX_INVENTORY_ITEMS;
        }
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("inv", fluff + sent, chunk, &packet_len);
        if (packet != NULL)
        {
            if (bm_network_write_all(conn->fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) == 0)
            {
                conn->bytes_sent += (uint64_t)packet_len;
            }
            free(packet);
        }
    }
    for (size_t sent = 0; sent < stem_count; sent += BM_MAX_INVENTORY_ITEMS)
    {
        size_t chunk = stem_count - sent;
        if (chunk > BM_MAX_INVENTORY_ITEMS)
        {
            chunk = BM_MAX_INVENTORY_ITEMS;
        }
        size_t packet_len = 0;
        unsigned char *packet = bm_create_inventory_message("dinv", stem + sent, chunk, &packet_len);
        if (packet != NULL)
        {
            if (bm_network_write_all(conn->fd, packet, packet_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) == 0)
            {
                conn->bytes_sent += (uint64_t)packet_len;
            }
            free(packet);
        }
    }
    bm_log("[object_sync] sent big inv to new peer: %zu fluff, %zu stem (of %zu total)\n", fluff_count, stem_count,
            hash_count);

    free(fluff);
    free(stem);
}

void bm_object_sync_dispatch(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data)
{
    struct bm_object_sync_ctx *ctx = user_data;

    if (strncmp(msg->command, "version", 12) == 0)
    {
        struct bm_version_message ver;
        bm_parse_version_message(msg->payload, msg->length, &ver);
        bm_log("[object_sync] version: v=%u services=%" PRIu64 " ua=%s\n",
                ver.version, ver.services, ver.user_agent);
        /* §11 2026-08-23 backlog項目3: プロトコルバージョン互換性チェック
         * (PyBitmessage network/bmproto.pyのpeerValidityChecks相当)。verackを送らずに
         * errorメッセージ(fatal=2)だけ送って切断する。conn->should_disconnectを立てて
         * network.c側の既存の切断経路(rating失敗記録込み)へ合流させる(network.hのdoc参照)。 */
        if (ver.version < BM_MIN_PROTOCOL_VERSION)
        {
            bm_log("[object_sync] closing connection: peer protocol version %u is below minimum %d\n",
                    ver.version, BM_MIN_PROTOCOL_VERSION);
            bm_free_version_message(&ver);
            size_t err_len = 0;
            unsigned char *err_packet =
                    bm_create_error_message(2, 0, "Your is using an old protocol. Closing connection.", &err_len);
            if (err_packet != NULL)
            {
                if (bm_network_write_all(conn->fd, err_packet, err_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) == 0)
                {
                    conn->bytes_sent += (uint64_t)err_len;
                }
                free(err_packet);
            }
            conn->should_disconnect = 1;
            return;
        }
        /* §11 2026-08-23 backlog項目4: version messageのtimestampの検証
         * (PyBitmessage network/bmproto.pyのpeerValidityChecks、timeOffsetチェック相当)。
         * 自分の時計との差がBM_MAX_TIME_OFFSET_SECONDS(1時間)を超える相手は、時計が
         * 大きく狂っているかobjectのPoW/期限判定を意図的に誤魔化そうとしている可能性が
         * あるため切断する。PyBitmessage側にある「時計ズレpeerが一定数を超えたらGUIの
         * ステータスバーに警告を出す」機能(timeOffsetWrongCount)はGUI専用でこの
         * ヘッドレスdaemonには該当機能が無いため移植しない。 */
        int64_t time_offset = (int64_t)ver.timestamp - (int64_t)time(NULL);
        if (time_offset > BM_MAX_TIME_OFFSET_SECONDS || time_offset < -BM_MAX_TIME_OFFSET_SECONDS)
        {
            bm_log("[object_sync] closing connection: peer's version timestamp is %" PRId64
                    "s off from our clock (limit %ds)\n",
                    time_offset, BM_MAX_TIME_OFFSET_SECONDS);
            bm_free_version_message(&ver);
            size_t err_len = 0;
            const char *err_text = (time_offset > 0)
                                            ? "Your time is too far in the future compared to mine. Closing "
                                              "connection."
                                            : "Your time is too far in the past compared to mine. Closing "
                                              "connection.";
            unsigned char *err_packet = bm_create_error_message(2, 0, err_text, &err_len);
            if (err_packet != NULL)
            {
                if (bm_network_write_all(conn->fd, err_packet, err_len, BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS) == 0)
                {
                    conn->bytes_sent += (uint64_t)err_len;
                }
                free(err_packet);
            }
            conn->should_disconnect = 1;
            return;
        }
        /* §9 Dandelion++: 相手のservicesビットフィールドを覚えておく(stem successor選定が
         * BM_SERVICE_NODE_DANDELIONを立てているoutbound peerだけを対象にするため使う) */
        conn->services = ver.services;
        /* §11 2026-08-23 backlog項目5: listConnections API用に相手のuser agentを覚えておく。
         * verが解放される前に複製する(通常は接続ごとに1回しかversionを受け取らないが、
         * 念のため既存値があれば先にfreeしてリークを防ぐ)。 */
        free(conn->user_agent);
        conn->user_agent = (ver.user_agent != NULL) ? strdup(ver.user_agent) : NULL;
        bm_free_version_message(&ver);
        record_outbound_success(ctx, conn);
        if (bm_reply_verack(conn) != 0)
        {
            bm_log("[object_sync] failed to reply verack\n");
        }
        /* §11 inbound接続(Tor hidden service)対応: outboundは接続直後に
         * peer_connector.cが既に自分のversionを送信済みだが、inbound(BM_FD_SERVER_SOCKET、
         * 相手が接続してきた側)はまだ送っていないため、相手のversionを受け取った
         * このタイミングで送り返す(verack+versionの両方を返すのが正しいハンドシェイク、
         * 実ネットワークの他ノードからの応答でも同じ挙動が観測されている) */
        if (conn->type == BM_FD_SERVER_SOCKET && ctx->user_agent != NULL)
        {
            if (bm_post_version(conn->fd, ctx->user_agent, 3, &conn->peer_addr, &conn->local_addr) != 0)
            {
                bm_log("[object_sync] failed to send version to inbound peer\n");
            }
            else
            {
                conn->bytes_sent += (uint64_t)bm_version_message_size(ctx->user_agent);
            }
        }
    }
    else if (strncmp(msg->command, "verack", 12) == 0)
    {
        bm_log("[object_sync] verack received\n");
        /* §11 2026-08-23: inbound/outbound問わず、verack受信時点で双方向のversion/verack
         * 交換が完了している(相手も既にこちらのversionを受け取っている)。
         * network.cのアイドル/ハンドシェイクタイムアウト判定(bm_network_idle_sweep)が
         * 使う「fully established」フラグをここで立てる。 */
        conn->handshake_complete = 1;
        record_outbound_success(ctx, conn);
        send_addr_reply(ctx, conn);
        send_big_inv(ctx, conn);
    }
    else if (strncmp(msg->command, "ping", 12) == 0)
    {
        if (bm_reply_pong(conn) != 0)
        {
            bm_log("[object_sync] failed to reply pong\n");
        }
    }
    else if (strncmp(msg->command, "addr", 12) == 0)
    {
        struct bm_addr_message addr_msg;
        if (bm_parse_addr_message(msg->payload, msg->length, &addr_msg) == 0)
        {
            uint64_t n = addr_msg.count;
            if (n > BM_MAX_INVENTORY_ITEMS)
            {
                n = BM_MAX_INVENTORY_ITEMS;
            }
            int registered = 0;
            int filtered = 0;
            if (ctx->peers_db != NULL)
            {
                static const unsigned char IPV4_MAPPED_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
                int64_t addr_now = (int64_t)time(NULL);
                for (uint64_t i = 0; i < n; i++)
                {
                    const struct bm_address_info *e = &addr_msg.addresses[i];
                    int is_ipv4_mapped = (memcmp(e->ip, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX)) == 0);
                    if (e->port == 0 || !is_ipv4_mapped || !is_routable_ipv4_peer_address(e->ip + 12)
                        || (int64_t)e->time > addr_now)
                    {
                        /* §11 2026-08-23: last_seen(peer申告のtime)が未来の値になっている
                         * garbage/悪意あるentryをfilterする(PyBitmessageのbm_command_addrの
                         * `time.time() - seenTime > 0`検証に相当)。無検証だと
                         * bm_peer_manager_cleanupの`now - last_seen > max_age`が常に負に
                         * なり、そのhostが永久にクリーンアップ対象から外れてしまう
                         * (実際にpeers.dbで2^31を超えるlast_seenが70件見つかって発覚)。 */
                        /* §11 2026-08-23: 素のIPv6は一律filter。実ネットワーク上で本物のIPv6 peerの
                         * 利用実績が無く、garbageな16バイト値をIPv6として誤登録してしまう問題が
                         * 見つかったため(DESIGN.md参照)。 */
                        filtered++;
                        continue;
                    }
                    char ip_str[INET6_ADDRSTRLEN];
                    const char *ok = inet_ntop(AF_INET, e->ip + 12, ip_str, sizeof(ip_str));
                    if (ok == NULL)
                    {
                        continue;
                    }
                    if (bm_peer_manager_upsert_learned(ctx->peers_db, ip_str, e->port, (int)e->stream,
                                                        e->services, (int64_t)e->time, "addr_msg") == 0)
                    {
                        registered++;
                    }
                }
            }
            bm_log(
                    "[object_sync] addr: %" PRIu64 " entries (%d registered to peers.db, %d filtered)\n",
                    addr_msg.count, registered, filtered);
            bm_free_addr_message(&addr_msg);
        }
    }
    else if (strncmp(msg->command, "inv", 12) == 0 || strncmp(msg->command, "dinv", 12) == 0)
    {
        /* §9 Dandelion++ Stage 1: dinv(stemフェーズ中の中継、まだ周りへ撒くなという合図)は
         * ワイヤーフォーマットがinvと完全に同一(varint(count) || hash(32byte)*count)なので、
         * stem状態を一切保持しないv1では安全にinvと全く同じ処理経路へ流せる
         * (DESIGN.md §9.2)。Dandelion対応ピアと接続してもプロトコル違反にはならない。 */
        handle_inv(ctx, conn, msg);
    }
    else if (strncmp(msg->command, "getdata", 12) == 0)
    {
        handle_getdata(ctx, conn, msg);
    }
    else if (strncmp(msg->command, "object", 12) == 0)
    {
        handle_object(ctx, conn, msg);
    }
    else if (strncmp(msg->command, "error", 12) == 0)
    {
        /* §11 2026-08-22調査: これまで単に"unhandled command: error"とだけ記録して中身を
         * 捨てていたため、rating調査中に何度も観測されたにも関わらず原因が分からなかった。
         * ワイヤーフォーマット(Bitmessageプロトコル仕様のerrorメッセージ):
         *   fatal(varint: 0=Warning, 1=Error, 2=Fatal/接続を切る) || banTime(varint) ||
         *   vector(varstr、関連objectのhash等、空文字列もあり) || errorText(varstr)
         * 人間が読めるerrorTextだけ抜き出してログに出す(相手が実際に何を嫌がって
         * 切断してくるのか初めて分かるようにする)。パース失敗(データ不足)は無視するだけで
         * 接続自体には影響させない(診断用途のベストエフォート)。 */
        const unsigned char *p = msg->payload;
        size_t remaining = msg->length;
        uint64_t fatal = 0;
        size_t consumed = bm_varint_decode(p, remaining, &fatal);
        if (consumed > 0)
        {
            p += consumed;
            remaining -= consumed;
            uint64_t ban_time = 0;
            consumed = bm_varint_decode(p, remaining, &ban_time);
            if (consumed > 0)
            {
                p += consumed;
                remaining -= consumed;
                uint64_t vector_len = 0;
                consumed = bm_varint_decode(p, remaining, &vector_len);
                if (consumed > 0 && vector_len <= remaining - consumed)
                {
                    p += consumed + vector_len;
                    remaining -= consumed + vector_len;
                    uint64_t text_len = 0;
                    consumed = bm_varint_decode(p, remaining, &text_len);
                    if (consumed > 0 && text_len <= remaining - consumed)
                    {
                        bm_log(
                                "[object_sync] error message from peer: fatal=%" PRIu64 " banTime=%" PRIu64
                                " text=\"%.*s\"\n",
                                fatal, ban_time, (int)text_len, p + consumed);
                    }
                }
            }
        }
        /* §11 2026-08-23発覚のバグ修正: fatal>=1(Error/Fatal、ワイヤーフォーマット仕様上
         * 0=Warning/1=Error/2=Fatal)を受信してもratingに一切反映していなかった。相手は
         * verack後すぐに"Server full, please try again later."のようなfatal=2を送って
         * 切断してくるケースが多く、verack受信時の成功クレジット(+0.1)とその後の切断による
         * 失敗クレジット(-0.1)がほぼ相殺してratingが高いまま維持されてしまい、明確に
         * 拒否されているpeerへ毎サイクル再接続し続ける実害が見つかった(peers.dbの大半が
         * わずかにマイナスで塩漬けになる一方、この種のpeerだけratingが高止まりしていた)。
         * ここで追加のペナルティを与えることで、1サイクル全体(成功+error受信+最終的な切断)
         * が正味マイナスへ傾くようにする。 */
        if (fatal >= 1 && conn->type == BM_FD_CLIENT_SOCKET && ctx->peers_db != NULL)
        {
            char ip[BM_PEER_IP_STRLEN];
            int port = 0;
            bm_network_resolve_peer_ip_port(conn, ip, sizeof(ip), &port);
            if (ip[0] != '\0')
            {
                bm_peer_manager_record_result(ctx->peers_db, ip, port, 1, 0);
            }
        }
    }
    else
    {
        char command[13] = {0};
        memcpy(command, msg->command, 12);
        bm_log("[object_sync] unhandled command: %s\n", command);
    }

    maybe_run_gc(ctx);
    maybe_run_resend_check(ctx);
}

void *bm_object_sync_broadcast_thread(void *arg)
{
    struct bm_broadcast_thread_args *args = arg;

    void *raw = NULL;
    while (bm_queue_pop(args->queue, &raw))
    {
        struct bm_broadcast_item *item = raw;

        struct bm_object_header hdr;
        if (bm_object_parse_header(item->object, item->object_len, &hdr) == 0)
        {
            unsigned char hash[32];
            bm_inventory_hash(item->object, item->object_len, hash);
            int already_known = bm_object_store_has(args->ctx->object_pool_db, hash);
            int64_t now = (int64_t)time(NULL);
            bm_object_store_insert(args->ctx->object_pool_db, hash, (int)hdr.object_type, (int)hdr.stream,
                                    item->object, item->object_len, (int64_t)hdr.expires_time, now);
            if (!already_known && args->ctx->registry != NULL)
            {
                bm_peer_registry_broadcast_inv(args->ctx->registry, &hash, 1, NULL);
                bm_log("[object_sync] broadcasted locally-originated object to peers\n");
            }
        }
        else
        {
            bm_log("[object_sync] broadcast_queue item has a malformed object header, dropping\n");
        }

        free(item->object);
        free(item);
    }

    free(args);
    return NULL;
}
