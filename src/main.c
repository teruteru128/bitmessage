/*
 * DESIGN.md §1: DB初期化・鍵ロード・全スレッド起動・シグナルハンドリング。
 * v1スコープでは大半のスレッドがTODOスタブ(すぐreturnする)。§10で定めた通り、
 * まずスレッド起動〜終了までの骨格を通し、各モジュールを順次実装で埋めていく方針。
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/db_common.h"
#include "common/queue.h"
#include "core/api_server.h"
#include "core/identity_store.h"
#include "core/keyring.h"
#include "core/messages_store.h"
#include "core/send_pipeline.h"
#include "core/trial_decrypt.h"
#include "infra/object_store.h"
#include "infra/peer_manager.h"

/* DESIGN.md §1.2: 層間キュー一覧。中身のstructはまだ各モジュール実装時に確定させる(TODO) */
struct bm_queues
{
    bm_queue_t command_queue;
    bm_queue_t object_inbox_queue;
    bm_queue_t decrypt_request_queue;
    bm_queue_t send_request_queue;
    bm_queue_t pow_request_queue;
    bm_queue_t pow_result_queue;
    bm_queue_t broadcast_queue;
};

static void queues_init(struct bm_queues *q)
{
    bm_queue_init(&q->command_queue);
    bm_queue_init(&q->object_inbox_queue);
    bm_queue_init(&q->decrypt_request_queue);
    bm_queue_init(&q->send_request_queue);
    bm_queue_init(&q->pow_request_queue);
    bm_queue_init(&q->pow_result_queue);
    bm_queue_init(&q->broadcast_queue);
}

static void queues_shutdown(struct bm_queues *q)
{
    bm_queue_shutdown(&q->command_queue);
    bm_queue_shutdown(&q->object_inbox_queue);
    bm_queue_shutdown(&q->decrypt_request_queue);
    bm_queue_shutdown(&q->send_request_queue);
    bm_queue_shutdown(&q->pow_request_queue);
    bm_queue_shutdown(&q->pow_result_queue);
    bm_queue_shutdown(&q->broadcast_queue);
}

static void queues_destroy(struct bm_queues *q)
{
    bm_queue_destroy(&q->command_queue);
    bm_queue_destroy(&q->object_inbox_queue);
    bm_queue_destroy(&q->decrypt_request_queue);
    bm_queue_destroy(&q->send_request_queue);
    bm_queue_destroy(&q->pow_request_queue);
    bm_queue_destroy(&q->pow_result_queue);
    bm_queue_destroy(&q->broadcast_queue);
}

static sqlite3 *open_and_init(const char *filename, int (*init_schema)(sqlite3 *))
{
    sqlite3 *db = bm_db_open(filename);
    if (db == NULL)
    {
        return NULL;
    }
    if (init_schema(db) != 0)
    {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

int main(void)
{
    /* §1.3: DBはスレッドごとに個別接続を開く方針だが、v1では起動時のスキーマ初期化のみ行う */
    sqlite3 *peers_db = open_and_init("peers.db", bm_peer_manager_init_schema);
    sqlite3 *object_pool_db = open_and_init("object_pool.db", bm_object_store_init_schema);
    sqlite3 *identity_db = open_and_init("identity.db", bm_identity_store_init_schema);
    sqlite3 *messages_db = open_and_init("messages.db", bm_messages_store_init_schema);

    if (peers_db == NULL || object_pool_db == NULL || identity_db == NULL || messages_db == NULL)
    {
        fprintf(stderr, "DB初期化に失敗しました\n");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "DB初期化完了: peers.db, object_pool.db, identity.db, messages.db\n");

    struct bm_queues queues;
    queues_init(&queues);

    bm_keyring_t keyring;
    bm_keyring_init(&keyring);

    /* §1.1のスレッド一覧。現状ほとんどが即returnするTODOスタブ */
    pthread_t th_trial_decrypt, th_send_pipeline, th_api_server;
    pthread_create(&th_trial_decrypt, NULL, bm_trial_decrypt_thread, NULL);
    pthread_create(&th_send_pipeline, NULL, bm_send_pipeline_thread, NULL);
    pthread_create(&th_api_server, NULL, bm_api_server_thread, NULL);

    /* SIGINT/SIGTERMをブロックしてsigwaitで待つ(全スレッドが実装されればここが本体のライフサイクルになる) */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    int sig = 0;
    sigwait(&set, &sig);
    fprintf(stderr, "シグナル %d を受信、終了処理を開始します\n", sig);

    queues_shutdown(&queues);

    pthread_join(th_trial_decrypt, NULL);
    pthread_join(th_send_pipeline, NULL);
    pthread_join(th_api_server, NULL);

    queues_destroy(&queues);
    bm_keyring_destroy(&keyring);

    sqlite3_close(peers_db);
    sqlite3_close(object_pool_db);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);

    return EXIT_SUCCESS;
}
