#ifndef BM_CORE_MESSAGE_BUILDER_H
#define BM_CORE_MESSAGE_BUILDER_H

/*
 * msg/broadcast/pubkey/getpubkeyオブジェクトの組み立て。DESIGN.md §5.1〜§5.5。
 * 戻り値は全て「PoW前(nonce抜き)のペイロード」= expiresTime(8)||objectType(4)||
 * varint(version)||varint(stream)||<種別依存部>。呼び出し側がpow_engine.cでnonceを
 * 見つけてから先頭にpack('>Q',nonce)を付与すると完成object(§5.0)になる。
 */

#include <stddef.h>
#include <stdint.h>

/* msg/broadcast/pubkeyの送信元アイデンティティ情報。ワイヤに乗る形式(64byte、0x04落とし済み)
 * ではなく、bm_address_get_public_key()が返す65byte(0x04||X||Y)のまま保持する
 * (ビルダー内部で[1:]して64byteにする)。 */
struct bm_identity_info
{
    uint64_t address_version;
    uint64_t stream;
    unsigned char pub_signing[65];
    unsigned char pub_encryption[65];
    unsigned char priv_signing[32]; /* 署名に使う */
    uint64_t nonce_trials_per_byte;
    uint64_t payload_length_extra_bytes;
    int does_ack; /* bitfieldのBITFIELD_DOESACKビット(§5.2) */
};

/* §5.1: ripeは常に20byte(version>=4の場合、関数内でtagに変換する) */
unsigned char *bm_build_getpubkey(uint64_t address_version, uint64_t stream,
                                   const unsigned char ripe[20], uint64_t expires_time,
                                   size_t *out_len);

/* §5.2 */
unsigned char *bm_build_pubkey_v2(const struct bm_identity_info *id, uint64_t expires_time,
                                   size_t *out_len);
unsigned char *bm_build_pubkey_v3(const struct bm_identity_info *id, uint64_t expires_time,
                                   size_t *out_len);
unsigned char *bm_build_pubkey_v4(const struct bm_identity_info *id, const unsigned char ripe[20],
                                   uint64_t expires_time, size_t *out_len);

/*
 * §5.3: toStreamがヘッダのstreamになる(fromStreamはpayload内部の別フィールド)。
 * subject/bodyはSIMPLEエンコーディング("Subject:...\nBody:...")固定(§8, v1スコープ)。
 * ack_payloadはNULL可(その場合ackPayloadLen=0として埋め込む、§5.5)。
 */
unsigned char *bm_build_msg(const struct bm_identity_info *from, uint64_t to_stream,
                             const unsigned char to_ripe[20],
                             const unsigned char to_pub_encryption[65],
                             const char *subject, const char *body,
                             const unsigned char *ack_payload, size_t ack_payload_len,
                             uint64_t expires_time, size_t *out_len);

/* §5.4: ヘッダのstreamはfrom->stream。objectVersionはfrom->address_versionから自動判定(4 or 5) */
unsigned char *bm_build_broadcast(const struct bm_identity_info *from, const unsigned char from_ripe[20],
                                   const char *subject, const char *body,
                                   uint64_t expires_time, size_t *out_len);

/* §5.5: stealth_level 0/1/2。戻り値はackobject本体(type+version+stream+random/暗号文)で、
 * 呼び出し側がtime+ackobjectを連結しPoWしてCreatePacketで包む(generateFullAckMessage相当は
 * send_pipeline.c側の責務、ここではackobjectの中身だけ作る)。 */
unsigned char *bm_build_ack_object(int stealth_level, uint64_t stream, size_t *out_len);

/*
 * §11 outbound Tor経路の強化(送信側): 自分自身のonion hidden service情報をonionpeer object
 * (BM_OBJECT_ONIONPEER)として組み立てる。onion_addressは"xxxx.onion"(v3、56文字+".onion")
 * 形式であること。base32部分をデコードし、OnionCat prefix(0xfd87d87eeb43)を前置した
 * ホストバイト列としてペイロードへ埋め込む(infra/object_sync.cのhandle_incoming_onionpeer、
 * 受信側のちょうど逆変換)。形式が不正(56文字+".onion"でない、base32として不正な文字を含む)
 * ならNULLを返す。
 */
unsigned char *bm_build_onionpeer(const char *onion_address, uint16_t port, uint64_t stream,
                                   uint64_t expires_time, size_t *out_len);

#endif /* BM_CORE_MESSAGE_BUILDER_H */
