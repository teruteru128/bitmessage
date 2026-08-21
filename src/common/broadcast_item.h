#ifndef BM_COMMON_BROADCAST_ITEM_H
#define BM_COMMON_BROADCAST_ITEM_H

/*
 * main.cのbroadcast_queue(DESIGN.md §1.2)に積む要素。core層(core/api_server.c)が
 * 送信済みobjectをpushし、infra層(infra/object_sync.cのbm_object_sync_broadcast_thread)が
 * popしてobject_pool.dbへ挿入・peer_registry経由でネットワークへbroadcastする。
 * core/infra両方が依存できるようcommon層に置く(core->infraの直接依存を避けるため)。
 * objectの所有権はpushした側からpopした側へ移る(popした側がfreeする)。
 */

#include <stddef.h>

struct bm_broadcast_item
{
    unsigned char *object;
    size_t object_len;
};

#endif /* BM_COMMON_BROADCAST_ITEM_H */
