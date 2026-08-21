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
#include <sys/epoll.h>

#include "common/db_common.h"
#include "common/queue.h"
#include "core/api_server.h"
#include "core/config_store.h"
#include "core/identity_store.h"
#include "core/keyring.h"
#include "core/messages_store.h"
#include "core/send_pipeline.h"
#include "core/trial_decrypt.h"
#include "infra/network.h"
#include "infra/object_store.h"
#include "infra/object_sync.h"
#include "infra/peer_connector.h"
#include "infra/peer_registry.h"
#include "infra/peer_manager.h"
#include "infra/protocol.h"

/* BM_PROJECT_VERSIONはCMakeLists.txt(ルート)のproject(bitmessage VERSION ...)から
 * target_compile_definitionsで注入される(src/CMakeLists.txt参照)。バージョン文字列を
 * ここへ直接ハードコードすると更新を忘れやすいため(2026-08-21発覚: v1.0.0タグ後もずっと
 * "0.1.0"のままだった)、単一の情報源から取るようにした。 */
#ifndef BM_PROJECT_VERSION
#define BM_PROJECT_VERSION "0.0.0"
#endif
#define BM_USER_AGENT "/bitmessage-c:" BM_PROJECT_VERSION "/"
#define BM_MAX_OUTBOUND 3

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
    sqlite3 *config_db = open_and_init("config.db", bm_config_store_init_schema);

    if (peers_db == NULL || object_pool_db == NULL || identity_db == NULL || messages_db == NULL
        || config_db == NULL)
    {
        fprintf(stderr, "DB初期化に失敗しました\n");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "DB初期化完了: peers.db, object_pool.db, identity.db, messages.db, config.db\n");

    /* §11 outbound接続用SOCKS5プロキシ設定。起動時ログ用に一度読むだけで、実際に
     * peer_connector_threadが使う値は再接続サイクルのたびconfig_dbから読み直される
     * (§11設定変更の動的リロード、peer_connector.c参照)。CLIのset-socks-proxyでの変更は
     * daemon再起動なしで次の再接続サイクル(既定30秒間隔)から反映される。 */
    struct bm_socks_proxy_config socks_proxy_config;
    bm_config_store_get_socks_proxy(config_db, &socks_proxy_config);
    fprintf(stderr, "[config] socks proxy: %s (%s:%d)\n",
            socks_proxy_config.enabled ? "enabled" : "disabled",
            socks_proxy_config.host, socks_proxy_config.port);

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

    /* §11 ポート衝突対策: bitmessage-cliは以前からBM_API_PORTで接続先ポートを変更できたが、
     * daemon側にそれを上書きする手段が無く非対称だった(2026-08-21発覚: バックグラウンドで
     * peer bootstrap用に立てたdaemonと、テスト実行時にctestが自前で起動するdaemonがどちらも
     * 既定の8442を取り合って衝突した)。CLIと同じ環境変数名で揃える。 */
    int api_port = 8442;
    const char *api_port_env = getenv("BM_API_PORT");
    if (api_port_env != NULL)
    {
        api_port = atoi(api_port_env);
    }

    struct bm_api_server_config api_config;
    memset(&api_config, 0, sizeof(api_config));
    api_config.bind_address = "127.0.0.1";
    api_config.port = api_port;
    api_config.username = "bitmessage";
    api_config.password = api_password;
    api_config.keyring = &keyring;
    api_config.identity_db = identity_db;
    api_config.messages_db = messages_db;
    api_config.broadcast_queue = &queues.broadcast_queue;
    api_config.config_db = config_db;
    fprintf(stderr, "[api] apiusername=bitmessage apipassword=%s port=%d (この起動でのみ有効、設定ファイル未実装)\n",
            api_password, api_port);

    /* testnet切り替え。設定ファイル未実装のため環境変数BM_TESTNET=1で切り替える(既定mainnet)。
     * inbound(サーバーソケットでの待ち受け)は自宅環境のISP事情でTor実装まで現実的でないため、
     * v1はoutbound接続のみ(peer_connector参照)。 */
    int testnet = getenv("BM_TESTNET") != NULL && strcmp(getenv("BM_TESTNET"), "1") == 0;
    bm_protocol_set_testnet(testnet);
    fprintf(stderr, "[network] mode=%s\n", testnet ? "testnet" : "mainnet");

    int epfd = epoll_create1(0);
    if (epfd == -1)
    {
        perror("epoll_create1");
        return EXIT_FAILURE;
    }

    /* §1.1のスレッド一覧。trial_decrypt/send_pipelineは現状即returnするTODOスタブ。
     * network_epoll_threadはepoll_wait()のブロッキング待受でグレースフルシャットダウンの
     * 割り込み機構がない(self-pipe trick等が必要、TODO)。当面はdetachし、プロセス終了時に
     * 道連れで終わらせる(pthread_joinすると永久にブロックしてしまうため)。 */
    pthread_t th_trial_decrypt, th_send_pipeline, th_api_server, th_network, th_broadcast;
    pthread_create(&th_trial_decrypt, NULL, bm_trial_decrypt_thread, NULL);
    pthread_create(&th_send_pipeline, NULL, bm_send_pipeline_thread, NULL);

    /* §11 api_serverのgraceful shutdown。peer_connector_threadと同じstop flagポーリング方式
     * (poll()に1秒タイムアウトを与えてaccept()の代わりに使う、api_server.c参照)。
     * api_server_stopもmain()がsigwaitでブロックしている間ずっと生存するスタック変数。 */
    volatile sig_atomic_t api_server_stop = 0;
    struct bm_api_server_thread_args *api_args = malloc(sizeof(*api_args));
    api_args->config = &api_config;
    api_args->stop_flag = &api_server_stop;
    pthread_create(&th_api_server, NULL, bm_api_server_thread, api_args);

    /* §11 接続レジストリ。現在epollに登録中の接続一覧で、object_sync_threadが「新しく手に入れた
     * objectを他の接続中peerへinv broadcastする」ために使う。registryもmain()がsigwaitで
     * ブロックしている間ずっと生存するスタック変数。 */
    struct bm_peer_registry peer_registry;
    bm_peer_registry_init(&peer_registry);

    /* §1.1 object_sync_thread。ctxはmain()がsigwaitでブロックしている間ずっと生存する
     * スタック変数(api_configと同じ扱い)。network_epoll_threadはdetach済みなのでpthread_join
     * より前に破棄されないことをそれで保証している。 */
    struct bm_object_sync_ctx object_sync_ctx;
    bm_object_sync_ctx_init(&object_sync_ctx, object_pool_db, identity_db, messages_db, peers_db, &keyring,
                             &peer_registry);

    struct bm_epoll_thread_args *net_args = malloc(sizeof(*net_args));
    net_args->epfd = epfd;
    net_args->handler = bm_object_sync_dispatch;
    net_args->user_data = &object_sync_ctx;
    net_args->registry = &peer_registry;
    pthread_create(&th_network, NULL, bm_network_epoll_thread, net_args);
    pthread_detach(th_network);

    /* broadcast_queueの消費スレッド(§1.2)。api_server.cのsendMessageが積んだobjectを
     * object_pool.dbへ挿入し、peer_registry経由でネットワークへinv broadcastする。
     * queues_shutdown()でbroadcast_queueがshutdownされると自然に抜けるのでjoinできる
     * (th_trial_decrypt/th_send_pipelineと同じ扱い)。 */
    struct bm_broadcast_thread_args *broadcast_args = malloc(sizeof(*broadcast_args));
    broadcast_args->ctx = &object_sync_ctx;
    broadcast_args->queue = &queues.broadcast_queue;
    pthread_create(&th_broadcast, NULL, bm_object_sync_broadcast_thread, broadcast_args);

    /* BM_NO_CONNECT=1で実接続を抑止できる(自動テスト用。cli_integration等が本物のネットワークへ
     * 接続しに行くとCI環境の到達性次第で数十秒単位で遅くなる/非決定的になるため)。 */
    pthread_t th_peer_connector;
    int peer_connector_started = 0;
    volatile sig_atomic_t peer_connector_stop = 0;
    if (getenv("BM_NO_CONNECT") != NULL && strcmp(getenv("BM_NO_CONNECT"), "1") == 0)
    {
        fprintf(stderr, "[peer_connector] BM_NO_CONNECT=1のため接続をスキップします\n");
    }
    else
    {
        /* §1.1 peer_connector_thread(常駐)。argはスレッド側でfreeされるためmallocする。
         * peer_connector_stopはmain()がsigwaitでブロックしている間ずっと生存するスタック変数。 */
        struct bm_peer_connector_thread_args *pc_args = malloc(sizeof(*pc_args));
        pc_args->config.epfd = epfd;
        pc_args->config.peers_db = peers_db;
        pc_args->config.testnet = testnet;
        pc_args->config.max_outbound = BM_MAX_OUTBOUND;
        pc_args->config.user_agent = BM_USER_AGENT;
        pc_args->config.registry = &peer_registry;
        pc_args->config.config_db = config_db;
        pc_args->stop_flag = &peer_connector_stop;
        pthread_create(&th_peer_connector, NULL, bm_peer_connector_thread, pc_args);
        peer_connector_started = 1;
    }

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
    peer_connector_stop = 1;
    api_server_stop = 1;

    pthread_join(th_trial_decrypt, NULL);
    pthread_join(th_send_pipeline, NULL);
    pthread_join(th_broadcast, NULL);
    pthread_join(th_api_server, NULL); /* 最大1秒でpoll()のタイムアウト検知して終了する */
    if (peer_connector_started)
    {
        pthread_join(th_peer_connector, NULL); /* 最大STOP_POLL_INTERVAL_SECONDS秒でポーリング検知して終了する */
    }

    queues_destroy(&queues);
    bm_peer_registry_destroy(&peer_registry);
    bm_keyring_destroy(&keyring);

    sqlite3_close(peers_db);
    sqlite3_close(object_pool_db);
    sqlite3_close(identity_db);
    sqlite3_close(messages_db);
    sqlite3_close(config_db);

    return EXIT_SUCCESS;
}
