#ifndef BM_COMMON_QUEUE_H
#define BM_COMMON_QUEUE_H

/*
 * スレッドセーフな単方向連結リストキュー。DESIGN.md §1.2の層間キュー全ての基盤。
 * 移植元: study/libstudy/src/bm_queue.c
 *
 * 要素は void* で保持する。キューに積む前に呼び出し側で malloc したデータへの
 * ポインタを渡し、queue_pop 後の解放責任も呼び出し側が持つ(queue_destroy は
 * ノード自体は解放するが data は解放しない)。
 */

#include <pthread.h>
#include <stdbool.h>

typedef struct bm_queue_node
{
    void *data;
    struct bm_queue_node *next;
} bm_queue_node_t;

typedef struct
{
    bm_queue_node_t *head;
    bm_queue_node_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool shutdown;
} bm_queue_t;

void bm_queue_init(bm_queue_t *q);
void bm_queue_destroy(bm_queue_t *q);
void bm_queue_push(bm_queue_t *q, void *data);
/* shutdown済みかつ空なら false を返す。それ以外は data を新規要素で埋めて true */
bool bm_queue_pop(bm_queue_t *q, void **out_data);
void bm_queue_shutdown(bm_queue_t *q);

#endif /* BM_COMMON_QUEUE_H */
