#include "queue.h"

#include <stdlib.h>

void bm_queue_init(bm_queue_t *q)
{
    q->head = q->tail = NULL;
    q->shutdown = false;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

void bm_queue_destroy(bm_queue_t *q)
{
    pthread_mutex_lock(&q->mutex);
    bm_queue_node_t *curr = q->head;
    while (curr)
    {
        bm_queue_node_t *next = curr->next;
        free(curr);
        curr = next;
    }
    q->head = q->tail = NULL;
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

void bm_queue_push(bm_queue_t *q, void *data)
{
    bm_queue_node_t *new_node = malloc(sizeof(bm_queue_node_t));
    new_node->data = data;
    new_node->next = NULL;

    pthread_mutex_lock(&q->mutex);
    if (q->tail == NULL)
    {
        q->head = q->tail = new_node;
    }
    else
    {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

bool bm_queue_pop(bm_queue_t *q, void **out_data)
{
    pthread_mutex_lock(&q->mutex);

    while (q->head == NULL && !q->shutdown)
    {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    if (q->head == NULL)
    {
        /* shutdown済みかつ空 */
        pthread_mutex_unlock(&q->mutex);
        return false;
    }

    bm_queue_node_t *node = q->head;
    *out_data = node->data;
    q->head = q->head->next;
    if (q->head == NULL)
    {
        q->tail = NULL;
    }

    pthread_mutex_unlock(&q->mutex);
    free(node);
    return true;
}

void bm_queue_shutdown(bm_queue_t *q)
{
    pthread_mutex_lock(&q->mutex);
    q->shutdown = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}
