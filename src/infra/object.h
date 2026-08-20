#ifndef BM_INFRA_OBJECT_H
#define BM_INFRA_OBJECT_H

/*
 * object種別の定数とネットワーク伝播判断。DESIGN.md §5.0, §9。
 * v1スコープではobjectの検証・保存(object_store)・トライアル復号への引き渡しは未実装(TODO)。
 * ここでは§9で決めた「将来の差し込み点」の骨組みだけを用意する。
 */

#include "network.h"

enum bm_object_type
{
    BM_OBJECT_GETPUBKEY = 0,
    BM_OBJECT_PUBKEY = 1,
    BM_OBJECT_MSG = 2,
    BM_OBJECT_BROADCAST = 3,
};

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
