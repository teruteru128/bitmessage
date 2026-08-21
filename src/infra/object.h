#ifndef BM_INFRA_OBJECT_H
#define BM_INFRA_OBJECT_H

/*
 * object種別の定数・共通ヘッダパーサ・ネットワーク伝播判断。DESIGN.md §5.0, §9。
 * v1スコープではobjectの検証・保存(object_store)への引き渡しは未実装(TODO)。
 * §9で決めた「将来の差し込み点」の骨組みも用意する。
 */

#include <stddef.h>
#include <stdint.h>

#include "network.h"

enum bm_object_type
{
    BM_OBJECT_GETPUBKEY = 0,
    BM_OBJECT_PUBKEY = 1,
    BM_OBJECT_MSG = 2,
    BM_OBJECT_BROADCAST = 3,
    /* §11 outbound Tor経路の強化。PyBitmessage(class_singleWorker.pyのsendOnionPeerObj/
     * class_objectProcessor.pyのprocessonion)準拠。ASCII "tor"の16進表現。addr/version
     * メッセージの16byte固定node encoding(v2 onionの80bitしか収まらない)とは別経路で、
     * objectペイロード末尾までを可変長のホストエンコードとして使うため、v3 onion(56文字
     * →35byte)も正しく往復できる */
    BM_OBJECT_ONIONPEER = 0x746f72,
};

/* §5.0: nonce(8)||expiresTime(8)||objectType(4)||varint(version)||varint(stream) */
struct bm_object_header
{
    uint64_t nonce;
    uint64_t expires_time;
    uint32_t object_type;
    uint64_t version;
    uint64_t stream;
    size_t header_len; /* nonce込みで消費したバイト数。data+header_lenが種別依存payloadの先頭 */
};

/* nonce込みの完全なobjectペイロードから共通ヘッダをパースする。成功時0、データ不足時は非0 */
int bm_object_parse_header(const unsigned char *data, size_t data_len, struct bm_object_header *out);

/* DESIGN.md §9.2: Dandelion++実装時に中身を差し替える差し込み点。v1は常にFLUFFを返す */
enum bm_propagation_mode
{
    BM_PROPAGATE_FLUFF,
    BM_PROPAGATE_STEM,
    BM_PROPAGATE_SKIP,
};

enum bm_propagation_mode bm_decide_propagation(const unsigned char object_hash[32],
                                                const struct bm_fd_data *target_connection);

#endif /* BM_INFRA_OBJECT_H */
