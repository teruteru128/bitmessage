#include "pow_queue.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pow_engine.h"

struct bm_pow_job
{
    unsigned char *payload;
    size_t payload_len;
    uint64_t target;
    unsigned char key[BM_POW_QUEUE_KEY_MAX];
    size_t key_len; /* 0ならdedup対象外 */
    bm_pow_done_fn done;
    void *user_data;
    struct bm_pow_job *next;
};

/* nonce(8byte BE) || payload を組み立てる。payloadはここで解放する。
 * 以前は呼び出し元3箇所(object_sync.c 2箇所、api_server.c 1箇所)がそれぞれ同じループで
 * 組み立てていたものを1箇所へ寄せた。 */
static unsigned char *build_object(unsigned char *payload, size_t payload_len, uint64_t nonce, size_t *out_len)
{
    size_t object_len = 8 + payload_len;
    unsigned char *object = malloc(object_len);
    if (object != NULL)
    {
        for (int i = 0; i < 8; i++)
        {
            object[i] = (unsigned char)((nonce >> (56 - 8 * i)) & 0xff);
        }
        memcpy(object + 8, payload, payload_len);
    }
    free(payload);
    *out_len = object != NULL ? object_len : 0;
    return object;
}

static void discard(unsigned char *payload, bm_pow_done_fn done, void *user_data)
{
    free(payload);
    done(user_data, NULL, 0, 0);
}

static void *pow_queue_worker(void *arg)
{
    struct bm_pow_queue *q = arg;

    pthread_mutex_lock(&q->mutex);
    for (;;)
    {
        while (!q->shutdown && q->head == NULL)
        {
            pthread_cond_wait(&q->cond, &q->mutex);
        }
        if (q->shutdown)
        {
            break;
        }
        struct bm_pow_job *job = q->head;
        q->head = job->next;
        if (q->head == NULL)
        {
            q->tail = NULL;
        }
        q->pending--;
        q->running = job;
        pthread_mutex_unlock(&q->mutex);

        uint64_t nonce = 0;
        if (bm_pow_run_cancellable(job->payload, job->payload_len, job->target, &q->cancel, &nonce) == 0)
        {
            size_t object_len = 0;
            unsigned char *object = build_object(job->payload, job->payload_len, nonce, &object_len);
            job->done(job->user_data, object, object_len, (int64_t)time(NULL));
        }
        else
        {
            discard(job->payload, job->done, job->user_data); /* shutdownによる打ち切り */
        }

        /* runningを下ろすのはdoneの後。doneの中で応答キャッシュ等を更新し終えるまでは
         * 同じキーの再投入をdedupで弾き続けたいため */
        pthread_mutex_lock(&q->mutex);
        q->running = NULL;
        q->completed++;
        free(job);
        pthread_cond_broadcast(&q->cond);
    }
    pthread_mutex_unlock(&q->mutex);
    return NULL;
}

int bm_pow_queue_init(struct bm_pow_queue *q, size_t max_pending)
{
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->max_pending = max_pending;
    atomic_init(&q->cancel, false);
    if (pthread_create(&q->thread, NULL, pow_queue_worker, q) != 0)
    {
        pthread_cond_destroy(&q->cond);
        pthread_mutex_destroy(&q->mutex);
        return -1;
    }
    return 0;
}

void bm_pow_queue_shutdown(struct bm_pow_queue *q)
{
    pthread_mutex_lock(&q->mutex);
    if (q->shutdown)
    {
        pthread_mutex_unlock(&q->mutex);
        return;
    }
    q->shutdown = true;
    atomic_store(&q->cancel, true);
    struct bm_pow_job *list = q->head;
    q->head = NULL;
    q->tail = NULL;
    q->pending = 0;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);

    pthread_join(q->thread, NULL);

    /* 待ちジョブはmutexの外で破棄する(doneの中で別のロックを取る実装があっても
     * キューのmutexと入れ子にならないように。submitの拒否経路も同じ) */
    while (list != NULL)
    {
        struct bm_pow_job *next = list->next;
        discard(list->payload, list->done, list->user_data);
        free(list);
        list = next;
    }
}

void bm_pow_queue_destroy(struct bm_pow_queue *q)
{
    pthread_cond_destroy(&q->cond);
    pthread_mutex_destroy(&q->mutex);
}

static int key_in_flight(const struct bm_pow_queue *q, const unsigned char *key, size_t key_len)
{
    if (q->running != NULL && q->running->key_len == key_len && memcmp(q->running->key, key, key_len) == 0)
    {
        return 1;
    }
    for (const struct bm_pow_job *j = q->head; j != NULL; j = j->next)
    {
        if (j->key_len == key_len && memcmp(j->key, key, key_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int bm_pow_queue_submit(struct bm_pow_queue *q, unsigned char *payload, size_t payload_len, uint64_t target,
                        const unsigned char *key, size_t key_len, bm_pow_done_fn done, void *user_data,
                        int64_t now)
{
    if (q == NULL)
    {
        uint64_t nonce = bm_pow_run(payload, payload_len, target);
        size_t object_len = 0;
        unsigned char *object = build_object(payload, payload_len, nonce, &object_len);
        done(user_data, object, object_len, now);
        return 0;
    }

    if (key == NULL || key_len > BM_POW_QUEUE_KEY_MAX)
    {
        key_len = 0;
    }

    pthread_mutex_lock(&q->mutex);
    int reject = 0;
    if (q->shutdown || q->pending >= q->max_pending)
    {
        reject = -1;
    }
    else if (key_len > 0 && key_in_flight(q, key, key_len))
    {
        reject = 1;
    }
    struct bm_pow_job *job = NULL;
    if (reject == 0)
    {
        job = calloc(1, sizeof(*job));
        if (job == NULL)
        {
            reject = -1;
        }
    }
    if (reject != 0)
    {
        pthread_mutex_unlock(&q->mutex);
        discard(payload, done, user_data);
        return reject;
    }

    job->payload = payload;
    job->payload_len = payload_len;
    job->target = target;
    if (key_len > 0)
    {
        memcpy(job->key, key, key_len);
    }
    job->key_len = key_len;
    job->done = done;
    job->user_data = user_data;
    if (q->tail != NULL)
    {
        q->tail->next = job;
    }
    else
    {
        q->head = job;
    }
    q->tail = job;
    q->pending++;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

uint64_t bm_pow_queue_completed_count(struct bm_pow_queue *q)
{
    pthread_mutex_lock(&q->mutex);
    uint64_t n = q->completed;
    pthread_mutex_unlock(&q->mutex);
    return n;
}
