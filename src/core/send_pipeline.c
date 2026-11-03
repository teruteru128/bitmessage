#include "send_pipeline.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/hash.h"
#include "../infra/protocol.h"
#include "../pow/pow_engine.h"
#include "../pow/pow_queue.h"
#include "address.h"
#include "identity_store.h"
#include "message_builder.h"
#include "messages_store.h"
#include "pubkey_cache.h"

/* ackobject自体のPoW難易度。誰宛でもない匿名objectとして偽装するため、宛先固有の難易度
 * ではなくネットワーク既定値(PyBitmessage networkDefaultProofOfWorkNonceTrialsPerByte等)を使う */
#define BM_ACK_NONCE_TRIALS_PER_BYTE 1000
#define BM_ACK_PAYLOAD_LENGTH_EXTRA_BYTES 1000

static void pack_be64(unsigned char out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        out[i] = (unsigned char)((v >> (56 - 8 * i)) & 0xff);
    }
}

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d != NULL)
    {
        memcpy(d, s, n);
    }
    return d;
}

/* --- msg --- */

/*
 * §11 2026-11-03 項目38 Tier 2: sendMessageのPoWを呼び出し元スレッドから追い出すため、
 * 以前は1関数の中で順に行っていた処理を
 *   (1) 準備(呼び出し元スレッド): 鍵・宛先の解決、ack payloadの組み立て
 *   (2) ackのPoW(pow_queue)
 *   (3) msgの組み立て(ackのパケットを暗号化される本文へ埋め込むので(2)の後でしか作れない)と
 *       msgのPoW(pow_queue)
 *   (4) sentテーブルへの記録・自分宛ならinboxへのコピー・doneの呼び出し
 * に分けた。(2)(3)はどちらもワーカースレッド上の完了コールバックから次の段を投入する
 * 2段チェーンで、dedupキー('S'+msg_id)は段をまたいで引き継ぐ(pow_queue.h参照)。
 * (3)で署名するまで送信元の秘密署名鍵をこのjobが持つ(keyringのロック状態とは独立。
 * 投入後にlockAddressされても送信は完了する。これは同期実装でも同じ: 処理が終わるまで
 * lockAddressのAPI呼び出し自体が待たされていた)。
 */
struct send_msg_job
{
    struct bm_pow_queue *pow_queue;
    sqlite3 *messages_db;
    struct bm_identity_info from_info; /* 秘密署名鍵を含む。msgを組み立てた直後にcleanseする */
    uint64_t to_stream;
    unsigned char to_ripe[BM_RIPE_LEN];
    unsigned char to_pub_encryption[65];
    int is_self;
    char *from_address;
    char *to_address;
    char *subject;
    char *body;
    uint64_t ttl_seconds;
    int ack_stealth_level;
    uint64_t expires_time;
    uint64_t required_nonce_trials;
    uint64_t required_extra_bytes;
    unsigned char msg_id[32];
    int64_t next_resend_time;
    unsigned char *ack_data; /* nonce付き完成ackobject(§5.0形式)、sent.ack_dataとして保存 */
    size_t ack_data_len;
    unsigned char key[1 + 32];
    bm_send_done_fn done;
    void *user_data;
};

static void msg_job_free(struct send_msg_job *job)
{
    OPENSSL_cleanse(&job->from_info, sizeof(job->from_info));
    free(job->from_address);
    free(job->to_address);
    free(job->subject);
    free(job->body);
    free(job->ack_data);
    free(job);
}

static void msg_job_fail(struct send_msg_job *job, int64_t now)
{
    job->done(job->user_data, -1, NULL, 0, now);
    msg_job_free(job);
}

/* (4) msgのPoW完了 */
static void msg_pow_done(void *user_data, unsigned char *object, size_t object_len, int64_t now)
{
    struct send_msg_job *job = user_data;
    if (object == NULL)
    {
        msg_job_fail(job, now); /* shutdownでの打ち切り・破棄(投入時の拒否ではdoneは呼ばれない) */
        return;
    }

    /* §11 2026-08-31: is_selfはack_data==NULL(ackを生成しない)なので、sent.ack_data
     * (NOT NULL制約)にはNULLではなく長さ0の非NULLバッファを渡す。PyBitmessage本家の
     * status='msgsentnoackexpected'(class_singleWorker.py)に合わせ、resend候補一覧からも
     * 除外する(bm_messages_store_list_resend_candidates側の対応するWHERE句参照)。 */
    static const unsigned char empty_ack_data[1] = {0};
    const unsigned char *ack_data_for_store = (job->ack_data != NULL) ? job->ack_data : empty_ack_data;
    const char *status = job->is_self ? "msgsentnoackexpected" : "sent";
    /* sent_timeは以前もPoWの完了後に取っていた(time(NULL))。今はワーカーが完了時点で
     * 取ったnowを使う */
    int64_t sent_time = now;
    int rc = bm_messages_store_insert_sent(job->messages_db, job->msg_id, ack_data_for_store, job->ack_data_len,
                                           job->to_address, job->from_address, job->subject, job->body, status,
                                           job->ack_stealth_level, sent_time, (int64_t)job->ttl_seconds,
                                           job->next_resend_time);
    if (rc != 0)
    {
        free(object);
        msg_job_fail(job, now);
        return;
    }

    /* §11 2026-08-31 ユーザー指摘: 自分自身宛(chan投稿含む)はネットワーク経由で自分の元へ
     * ack/gossipが返ってこない限りinboxに現れない(chanの場合、他メンバーがgossipし直して
     * 初めて自分のノードにも届く。孤立ノードや他メンバー不在なら永久に現れない)。
     * PyBitmessage本家class_singleWorker.pyのsendMsg()も同じ理由でhelper_inbox.insert()により
     * 送信直後に同期的に自分のinboxへコピーを入れている。それに合わせ、is_selfの場合はここで
     * 直接messages.dbのinboxへ挿入する。msg_idはinbox側の慣習(trial_decrypt.c等)に合わせ
     * object全体のinventory hashを使う(sentテーブルのランダムmsg_idとは別概念)。ネットワーク
     * 経由で同じobjectを後から受信してもINSERT OR IGNOREのため重複は起きない。 */
    if (job->is_self)
    {
        unsigned char inbox_msg_id[32];
        bm_inventory_hash(object, object_len, inbox_msg_id);
        bm_messages_store_insert_inbox(job->messages_db, inbox_msg_id, job->to_address, job->from_address,
                                       job->subject, job->body, sent_time);
    }

    job->done(job->user_data, 0, object, object_len, now);
    msg_job_free(job);
}

/* (3) msgの組み立てとPoWの投入。ack_packetはNULL可(自分宛)、所有権は受け取らない */
static void build_and_submit_msg(struct send_msg_job *job, const unsigned char *ack_packet, size_t ack_packet_len,
                                 int64_t now)
{
    size_t payload_len = 0;
    unsigned char *payload = bm_build_msg(&job->from_info, job->to_stream, job->to_ripe, job->to_pub_encryption,
                                          job->subject, job->body, ack_packet, ack_packet_len, job->expires_time,
                                          &payload_len);
    /* 署名はここで済んだので、以後は秘密鍵を持ち歩かない */
    OPENSSL_cleanse(&job->from_info, sizeof(job->from_info));
    if (payload == NULL)
    {
        msg_job_fail(job, now);
        return;
    }

    /* §4.1: 宛先pubkeyが要求する難易度とネットワーク既定値の大きい方(準備段で計算済み) */
    uint64_t target = bm_pow_get_target(payload_len, job->ttl_seconds, job->required_nonce_trials,
                                        job->required_extra_bytes);
    /* 2段目の投入はワーカー上(ackのdoneの中)なので、拒否(上限超過・shutdown後)されたら
     * 非同期の失敗としてここで知らせる(拒否ではmsg_pow_doneは呼ばれない) */
    if (bm_pow_queue_submit(job->pow_queue, payload, payload_len, target, job->key, sizeof(job->key), msg_pow_done,
                            job, now)
        != 0)
    {
        msg_job_fail(job, now);
    }
}

/*
 * (2) ackのPoW完了。§5.5 generateFullAckMessage相当: bm_build_ack_objectが作るackobject本体
 * (type/version/stream/data)にexpiresTimeを付けてPoWしたnonce付きの完成object(sent.ack_data)と、
 * それをさらにP2P "object"パケットとして包んだもの(msgのackPayloadへ平文埋め込み用。
 * 受信側が復号後そのままソケットへ書き込める形)の両方を作る。
 */
static void ack_pow_done(void *user_data, unsigned char *object, size_t object_len, int64_t now)
{
    struct send_msg_job *job = user_data;
    if (object == NULL)
    {
        msg_job_fail(job, now); /* shutdownでの打ち切り・破棄(投入時の拒否ではdoneは呼ばれない) */
        return;
    }

    size_t packet_len = 0;
    unsigned char *packet = bm_create_packet("object", object, object_len, &packet_len);
    if (packet == NULL)
    {
        free(object);
        msg_job_fail(job, now);
        return;
    }
    job->ack_data = object;
    job->ack_data_len = object_len;

    build_and_submit_msg(job, packet, packet_len, now);
    free(packet);
}

/* ack payload(nonce抜き、expiresTime || ackobject本体)を組み立てる */
static unsigned char *build_ack_payload(int stealth_level, uint64_t stream, uint64_t expires_time, size_t *out_len)
{
    size_t ack_body_len = 0;
    unsigned char *ack_body = bm_build_ack_object(stealth_level, stream, &ack_body_len);
    if (ack_body == NULL)
    {
        return NULL;
    }
    size_t payload_len = 8 + ack_body_len;
    unsigned char *payload = malloc(payload_len);
    if (payload != NULL)
    {
        pack_be64(payload, expires_time);
        memcpy(payload + 8, ack_body, ack_body_len);
        *out_len = payload_len;
    }
    free(ack_body);
    return payload;
}

int bm_send_pipeline_send_message_async(struct bm_pow_queue *pow_queue, bm_keyring_t *kr, sqlite3 *identity_db,
                                        sqlite3 *messages_db, const char *from_address, const char *to_address,
                                        const char *subject, const char *body, uint64_t ttl_seconds,
                                        int ack_stealth_level, const unsigned char reuse_msg_id[32],
                                        int64_t next_resend_time, int64_t now, bm_send_done_fn done,
                                        void *user_data)
{
    struct bm_unlocked_identity from_id;
    if (!bm_keyring_find_by_address(kr, from_address, &from_id))
    {
        return -1; /* fromアドレスがunlockされていない */
    }

    uint64_t to_version = 0;
    uint64_t to_stream = 0;
    unsigned char to_ripe[BM_RIPE_LEN];
    if (bm_address_decode(to_address, &to_version, &to_stream, to_ripe) != 0)
    {
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }
    /* §11 2026-08-30 direct pubkey送信経路の廃止で自動upsert(entry.address_version代入)が
     * 無くなり、to_versionはbm_address_decodeの必須出力引数として受けるだけの値になった */
    (void)to_version;

    /* 宛先の公開暗号鍵は常にpubkey_cacheから引く。ただしto_addressが自分自身のidentity
     * (identity.dbに存在する。fromAddressと同一のchan投稿だけでなく、unlockしている/いないに
     * 関わらず自分が持つ別のidentity宛でも成立する、§11 2026-08-31 ユーザー指摘で
     * to_ripe==from_id.ripeのみを見ていた旧実装のバグを修正)の場合はcacheに無くても
     * identity.dbに保存済みのencryption_pubkeyをそのまま使える(公開鍵はunlock不要で
     * identity.dbに平文保存されている、§2.3)。
     * §11 2026-08-30 呼び出し側がto_pub_encryptionを直接指定できる経路は廃止した(検証されない
     * 鍵での暗号化・pubkey_cache汚染の実害があったため)。相手の鍵を事前に知っている場合は
     * 呼び出し側がbm_pubkey_cache_upsertで明示的に登録してから呼ぶ。 */
    struct bm_identity_row to_identity_row;
    int is_self = (bm_identity_store_load(identity_db, to_address, &to_identity_row) == 0);
    unsigned char to_pub_encryption[65];
    if (is_self)
    {
        memcpy(to_pub_encryption, to_identity_row.encryption_pubkey, 65);
    }
    else
    {
        struct bm_cached_pubkey cached;
        if (bm_pubkey_cache_lookup_by_ripe(identity_db, to_ripe, &cached) != 0)
        {
            OPENSSL_cleanse(&from_id, sizeof(from_id));
            return -1; /* 宛先のpubkeyが分からない(呼び出し側がgetpubkey要求を自動発行する) */
        }
        memcpy(to_pub_encryption, cached.encryption_pubkey, 65);
        bm_pubkey_cache_mark_used_personally(identity_db, to_ripe);
    }

    struct send_msg_job *job = calloc(1, sizeof(*job));
    if (job == NULL)
    {
        OPENSSL_cleanse(&from_id, sizeof(from_id));
        return -1;
    }
    job->pow_queue = pow_queue;
    job->messages_db = messages_db;
    job->from_info.address_version = from_id.address_version;
    job->from_info.stream = from_id.stream;
    memcpy(job->from_info.pub_signing, from_id.pub_signing, 65);
    memcpy(job->from_info.pub_encryption, from_id.pub_encryption, 65);
    memcpy(job->from_info.priv_signing, from_id.priv_signing, 32);
    job->from_info.nonce_trials_per_byte = from_id.nonce_trials_per_byte;
    job->from_info.payload_length_extra_bytes = from_id.payload_length_extra_bytes;
    /* TODO: PyBitmessageのdontsendack相当の設定はidentity.dbに未実装。既定でack要求する */
    job->from_info.does_ack = 1;
    job->to_stream = to_stream;
    memcpy(job->to_ripe, to_ripe, sizeof(job->to_ripe));
    memcpy(job->to_pub_encryption, to_pub_encryption, sizeof(job->to_pub_encryption));
    job->is_self = is_self;
    job->from_address = dup_str(from_address);
    job->to_address = dup_str(to_address);
    job->subject = dup_str(subject);
    job->body = dup_str(body);
    job->ttl_seconds = ttl_seconds;
    job->ack_stealth_level = ack_stealth_level;
    job->expires_time = (uint64_t)now + ttl_seconds;
    job->next_resend_time = next_resend_time;
    job->done = done;
    job->user_data = user_data;

    /* §4.1: 宛先pubkeyが要求する難易度とネットワーク既定値(=from_idの既定設定と同値)の
     * 大きい方を使う。pubkey_cacheに宛先の情報があれば(address_version>=3のみ意味を持つ、
     * §5.2)そちらを優先し、無ければ送信元の設定値のみを使う。 */
    job->required_nonce_trials = from_id.nonce_trials_per_byte;
    job->required_extra_bytes = from_id.payload_length_extra_bytes;
    OPENSSL_cleanse(&from_id, sizeof(from_id));
    {
        struct bm_cached_pubkey recipient_info;
        if (bm_pubkey_cache_lookup_by_ripe(identity_db, to_ripe, &recipient_info) == 0
            && recipient_info.address_version >= 3)
        {
            if (recipient_info.nonce_trials_per_byte > job->required_nonce_trials)
            {
                job->required_nonce_trials = recipient_info.nonce_trials_per_byte;
            }
            if (recipient_info.payload_length_extra_bytes > job->required_extra_bytes)
            {
                job->required_extra_bytes = recipient_info.payload_length_extra_bytes;
            }
        }
    }

    /* §11 2026-11-03: msg_idは以前はPoWの後で決めていたが、dedupキーに使うので準備段で決める */
    if (reuse_msg_id != NULL)
    {
        memcpy(job->msg_id, reuse_msg_id, 32);
    }
    else if (RAND_bytes(job->msg_id, sizeof(job->msg_id)) != 1)
    {
        msg_job_free(job);
        return -1;
    }
    if (job->from_address == NULL || job->to_address == NULL || job->subject == NULL || job->body == NULL)
    {
        msg_job_free(job);
        return -1;
    }
    /* dedupキー: 同じsent行(msg_id)の送信を2本同時に走らせない。新規送信はmsg_idが乱数なので
     * 実質効かず、効くのは再送(object_sync.cの再送チェックがPoWの完了前に同じ行をもう一度
     * 拾った場合。next_resend_timeはPoW完了時のsent行の更新で進むので、それまでは拾われうる) */
    job->key[0] = 'S';
    memcpy(job->key + 1, job->msg_id, 32);

    /* §11 2026-08-31 ユーザー指摘: 自分自身宛(=chanへの投稿含む)はack要求相手がいない
     * (自分がtrial_decryptで復号するだけで、誰も自分にackを返送してこない)ため、ackを
     * 組み立てて埋め込むこと自体が無駄なPoW/帯域の浪費だった。PyBitmessage本家
     * class_singleWorker.pyのsendMsg()も同じ理由でself/chan宛はfullAckPayload=''
     * (ackを一切生成・埋め込まない)にしている(コメント "Not bothering to include ackdata
     * because we are sending to ourselves or a chan.")。それに合わせ、is_selfの場合は
     * ackのPoW自体を行わない。 */
    if (is_self)
    {
        /* 1段目がmsgになる。組み立ては呼び出し元スレッドで行う(投入時に拒否されれば
         * msg_pow_doneは呼ばれないので、下でjobを片付けて戻り値をそのまま返す) */
        size_t payload_len = 0;
        unsigned char *payload = bm_build_msg(&job->from_info, job->to_stream, job->to_ripe, job->to_pub_encryption,
                                              job->subject, job->body, NULL, 0, job->expires_time, &payload_len);
        OPENSSL_cleanse(&job->from_info, sizeof(job->from_info));
        if (payload == NULL)
        {
            msg_job_free(job);
            return -1;
        }
        uint64_t target = bm_pow_get_target(payload_len, ttl_seconds, job->required_nonce_trials,
                                            job->required_extra_bytes);
        int rc = bm_pow_queue_submit(pow_queue, payload, payload_len, target, job->key, sizeof(job->key),
                                     msg_pow_done, job, now);
        if (rc != 0)
        {
            msg_job_free(job);
            return rc;
        }
        return 0;
    }

    size_t ack_payload_len = 0;
    unsigned char *ack_payload = build_ack_payload(ack_stealth_level, to_stream, job->expires_time, &ack_payload_len);
    if (ack_payload == NULL)
    {
        msg_job_free(job);
        return -1;
    }
    uint64_t ack_target = bm_pow_get_target(ack_payload_len, ttl_seconds, BM_ACK_NONCE_TRIALS_PER_BYTE,
                                            BM_ACK_PAYLOAD_LENGTH_EXTRA_BYTES);
    int rc = bm_pow_queue_submit(pow_queue, ack_payload, ack_payload_len, ack_target, job->key, sizeof(job->key),
                                 ack_pow_done, job, now);
    if (rc != 0)
    {
        msg_job_free(job);
        return rc;
    }
    return 0;
}

/* --- broadcast --- */

struct send_broadcast_job
{
    struct bm_pow_queue *pow_queue;
    bm_send_done_fn done;
    void *user_data;
};

static void broadcast_pow_done(void *user_data, unsigned char *object, size_t object_len, int64_t now)
{
    struct send_broadcast_job *job = user_data;
    if (object == NULL)
    {
        job->done(job->user_data, -1, NULL, 0, now); /* shutdownでの打ち切り・破棄 */
        free(job);
        return;
    }
    job->done(job->user_data, 0, object, object_len, now);
    free(job);
}

int bm_send_pipeline_send_broadcast_async(struct bm_pow_queue *pow_queue, bm_keyring_t *kr,
                                          const char *from_address, const char *subject, const char *body,
                                          uint64_t ttl_seconds, int64_t now, bm_send_done_fn done, void *user_data)
{
    struct bm_unlocked_identity from_id;
    if (!bm_keyring_find_by_address(kr, from_address, &from_id))
    {
        return -1; /* fromアドレスがunlockされていない */
    }

    struct bm_identity_info from_info;
    memset(&from_info, 0, sizeof(from_info));
    from_info.address_version = from_id.address_version;
    from_info.stream = from_id.stream;
    memcpy(from_info.pub_signing, from_id.pub_signing, 65);
    memcpy(from_info.pub_encryption, from_id.pub_encryption, 65);
    memcpy(from_info.priv_signing, from_id.priv_signing, 32);
    from_info.nonce_trials_per_byte = from_id.nonce_trials_per_byte;
    from_info.payload_length_extra_bytes = from_id.payload_length_extra_bytes;

    uint64_t expires_time = (uint64_t)now + ttl_seconds;

    /* broadcastは1段だけ(ackが無い)なので、署名・暗号化までは呼び出し元スレッドで済ませ、
     * PoWだけをpow_queueへ投げる */
    size_t payload_len = 0;
    unsigned char *payload = bm_build_broadcast(&from_info, from_id.ripe, subject, body, expires_time, &payload_len);
    OPENSSL_cleanse(&from_info, sizeof(from_info));
    uint64_t target = bm_pow_get_target(payload_len, ttl_seconds, from_id.nonce_trials_per_byte,
                                        from_id.payload_length_extra_bytes);
    OPENSSL_cleanse(&from_id, sizeof(from_id));
    if (payload == NULL)
    {
        return -1;
    }

    struct send_broadcast_job *job = malloc(sizeof(*job));
    if (job == NULL)
    {
        free(payload);
        return -1;
    }
    job->pow_queue = pow_queue;
    job->done = done;
    job->user_data = user_data;
    /* dedupキーは付けない(broadcastは毎回別物で、再送の対象にもしない) */
    int rc = bm_pow_queue_submit(pow_queue, payload, payload_len, target, NULL, 0, broadcast_pow_done, job, now);
    if (rc != 0)
    {
        free(job);
        return rc;
    }
    return 0;
}

/* --- 同期版(pow_queue==NULLで非同期版を呼び、その場で結果を受け取る) --- */

struct sync_result
{
    int rc;
    unsigned char *object;
    size_t object_len;
};

static void sync_done(void *user_data, int rc, unsigned char *object, size_t object_len, int64_t now)
{
    (void)now;
    struct sync_result *r = user_data;
    r->rc = rc;
    r->object = object;
    r->object_len = object_len;
}

int bm_send_pipeline_send_message(bm_keyring_t *kr, sqlite3 *identity_db, sqlite3 *messages_db,
                                   const char *from_address, const char *to_address,
                                   const char *subject, const char *body,
                                   uint64_t ttl_seconds, int ack_stealth_level,
                                   const unsigned char reuse_msg_id[32], int64_t next_resend_time,
                                   unsigned char **out_object, size_t *out_object_len)
{
    struct sync_result r = {-1, NULL, 0};
    if (bm_send_pipeline_send_message_async(NULL, kr, identity_db, messages_db, from_address, to_address, subject,
                                            body, ttl_seconds, ack_stealth_level, reuse_msg_id, next_resend_time,
                                            (int64_t)time(NULL), sync_done, &r)
        != 0)
    {
        return -1;
    }
    if (r.rc != 0)
    {
        return -1;
    }
    *out_object = r.object;
    *out_object_len = r.object_len;
    return 0;
}

int bm_send_pipeline_send_broadcast(bm_keyring_t *kr, const char *from_address,
                                     const char *subject, const char *body, uint64_t ttl_seconds,
                                     unsigned char **out_object, size_t *out_object_len)
{
    struct sync_result r = {-1, NULL, 0};
    if (bm_send_pipeline_send_broadcast_async(NULL, kr, from_address, subject, body, ttl_seconds,
                                              (int64_t)time(NULL), sync_done, &r)
        != 0)
    {
        return -1;
    }
    if (r.rc != 0)
    {
        return -1;
    }
    *out_object = r.object;
    *out_object_len = r.object_len;
    return 0;
}

void *bm_send_pipeline_thread(void *arg)
{
    (void)arg;
    /* §11 2026-11-03 項目38 Tier 2: 送信のPoWはpow_queue(src/pow/pow_queue.h)のワーカーで
     * 行うようになったので、§1.1で想定していた「send_request_queueをpopする専用スレッド」は
     * 不要になった(準備段は呼び出し元、PoW以降はpow_queueの完了コールバックのチェーン)。
     * スレッドの起動自体はmain.cの骨格に残してあるが、何もせずに戻る。 */
    return NULL;
}
