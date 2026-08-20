/*
 * DESIGN.md §1: DB初期化・鍵ロード・全スレッド起動・シグナルハンドリング。
 * v1スコープでは大半のスレッドがTODOスタブ(すぐreturnする)。§10で定めた通り、
 * まずスレッド起動〜終了までの骨格を通し、各モジュールを順次実装で埋めていく方針。
 */

#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* §6.1: apiusername/apipasswordはランダム生成し起動時に表示する(設定ファイル未実装のため)。
     * bitmessagedプロセスが生きている間、mainのローカル変数としてこのconfigを保持し続ける
     * (api_server_threadはmain終了までこのconfigを参照し続けるため)。 */
    unsigned char api_password_raw[16];
    RAND_bytes(api_password_raw, sizeof(api_password_raw));
    char api_password[sizeof(api_password_raw) * 2 + 1];
    for (size_t i = 0; i < sizeof(api_password_raw); i++)
    {
        snprintf(api_password + i * 2, 3, "%02x", api_password_raw[i]);
    }

    struct bm_api_server_config api_config;
    memset(&api_config, 0, sizeof(api_config));
    api_config.bind_address = "127.0.0.1";
    api_config.port = 8442;
    api_config.username = "bitmessage";
    api_config.password = api_password;
    api_config.keyring = &keyring;
    api_config.identity_db = identity_db;
    api_config.messages_db = messages_db;
    fprintf(stderr, "[api] apiusername=bitmessage apipassword=%s (この起動でのみ有効、設定ファイル未実装)\n",
            api_password);

    /* §1.1のスレッド一覧。trial_decrypt/send_pipelineは現状即returnするTODOスタブ。
     * api_serverはaccept()でブロックし続けるため、TODO: グレースフルシャットダウン
     * (self-pipe trick等でaccept()を割り込み可能にする)が未実装。当面はdetachし、
     * プロセス終了時に道連れで終わらせる(pthread_joinすると永久にブロックしてしまうため)。 */
    pthread_t th_trial_decrypt, th_send_pipeline, th_api_server;
    pthread_create(&th_trial_decrypt, NULL, bm_trial_decrypt_thread, NULL);
    pthread_create(&th_send_pipeline, NULL, bm_send_pipeline_thread, NULL);
    pthread_create(&th_api_server, NULL, bm_api_server_thread, &api_config);
    pthread_detach(th_api_server);

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
    /* th_api_serverはdetach済み(上記コメント参照)。プロセス終了と共に破棄される */

    queues_destroy(&queues);
    bm_keyring_destroy(&keyring);

    sqlite3_close(peers_db);
    sqlite3_close(object_pool_db);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);

    return EXIT_SUCCESS;
}
