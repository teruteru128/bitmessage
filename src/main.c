/*
 * DESIGN.md §1: DB初期化・鍵ロード・全スレッド起動・シグナルハンドリング。
 * v1スコープでは大半のスレッドがTODOスタブ(すぐreturnする)。§10で定めた通り、
 * まずスレッド起動〜終了までの骨格を通し、各モジュールを順次実装で埋めていく方針。
 */

#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "common/db_common.h"
#include "common/queue.h"
#include "core/api_server.h"
#include "core/config_file.h"
#include "core/config_store.h"
#include "core/identity_store.h"
#include "core/keyring.h"
#include "core/messages_store.h"
#include "core/peer_manager.h"
#include "core/send_pipeline.h"
#include "core/trial_decrypt.h"
#include "infra/network.h"
#include "infra/object_store.h"
#include "infra/object_sync.h"
#include "infra/peer_connector.h"
#include "infra/peer_registry.h"
#include "infra/protocol.h"
#include "infra/tor_control.h"

/* BM_PROJECT_VERSIONはCMakeLists.txt(ルート)のproject(bitmessage VERSION ...)から
 * target_compile_definitionsで注入される(src/CMakeLists.txt参照)。バージョン文字列を
 * ここへ直接ハードコードすると更新を忘れやすいため(2026-08-21発覚: v1.0.0タグ後もずっと
 * "0.1.0"のままだった)、単一の情報源から取るようにした。 */
#ifndef BM_PROJECT_VERSION
#define BM_PROJECT_VERSION "0.0.0"
#endif
#define BM_USER_AGENT "/bitmessage-c:" BM_PROJECT_VERSION "/"

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

/* §11 起動時設定: env var > 設定ファイル > 組み込みの既定値、という優先順位(core/config_file.h
 * 参照)。env varが真偽フラグの場合は既存の"1"のみを真とみなす挙動(BM_TESTNET等)をそのまま
 * 保つ(env_flag_or)。数値/文字列はatoi/そのまま採用する(env_or_int/env_or_str)。 */
static int env_flag_or(const char *env_name, int file_value)
{
    const char *env_value = getenv(env_name);
    if (env_value != NULL)
    {
        return strcmp(env_value, "1") == 0 ? 1 : 0;
    }
    return file_value;
}

static int env_or_int(const char *env_name, int file_value)
{
    const char *env_value = getenv(env_name);
    return (env_value != NULL) ? atoi(env_value) : file_value;
}

static const char *env_or_str(const char *env_name, const char *file_value)
{
    const char *env_value = getenv(env_name);
    return (env_value != NULL) ? env_value : file_value;
}

static uint64_t env_or_u64(const char *env_name, uint64_t file_value)
{
    const char *env_value = getenv(env_name);
    return (env_value != NULL) ? strtoull(env_value, NULL, 10) : file_value;
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

    /* §11 起動時設定ファイル(既定"bitmessage.conf"、BM_CONFIG_FILEで別の場所を指定可能)。
     * env var > 設定ファイル > 組み込みの既定値、という優先順位でこの後の各設定に使う
     * (core/config_file.h参照)。ファイルが無くても正常に既定値で起動する。 */
    const char *config_file_path = getenv("BM_CONFIG_FILE");
    if (config_file_path == NULL)
    {
        config_file_path = "bitmessage.conf";
    }
    struct bm_config_file cfg;
    int config_file_found = bm_config_file_load(config_file_path, &cfg);
    fprintf(stderr, "[config] %s (%s)\n", config_file_path,
            config_file_found ? "読み込み完了" : "見つからないため既定値を使用");

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

    /* §6.1: apiusername/apipasswordはランダム生成し起動時に表示する。設定ファイルに平文の
     * 固定認証情報を書き出す設計は意図的に採らなかった(core/config_file.h参照、セキュリティ
     * 判断として起動毎の非永続を維持する)。bitmessagedプロセスが生きている間、mainの
     * ローカル変数としてこのconfigを保持し続ける(api_server_threadはmain終了までこの
     * configを参照し続けるため)。 */
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
    int api_port = env_or_int("BM_API_PORT", cfg.api_port);

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
    api_config.peers_db = peers_db;
    api_config.default_nonce_trials_per_byte =
        env_or_u64("BM_DEFAULT_NONCE_TRIALS_PER_BYTE", cfg.default_nonce_trials_per_byte);
    api_config.default_payload_length_extra_bytes =
        env_or_u64("BM_DEFAULT_PAYLOAD_LENGTH_EXTRA_BYTES", cfg.default_payload_length_extra_bytes);
    fprintf(stderr, "[api] apiusername=bitmessage apipassword=%s port=%d (この起動でのみ有効、認証情報は意図的に非永続)\n",
            api_password, api_port);

    /* testnet切り替え。bitmessage.confの[network] testnet、またはBM_TESTNET=1で切り替える
     * (既定mainnet)。 */
    int testnet = env_flag_or("BM_TESTNET", cfg.testnet);
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
                             &peer_registry, BM_USER_AGENT);

    /* §11 inbound接続(Tor hidden service)対応。BM_INBOUND_PORTが設定されていれば
     * 127.0.0.1:<port>でTCP listenし、Tor hidden serviceからの転送を受け付ける準備をする
     * (実際にTorのHiddenServicePortをこのポートへ向けて設定しないと外部からは到達しない、
     * DESIGN.md §11参照)。既定は未設定=inbound無効(v1のoutbound専用設計を壊さないため)。
     * listen_fd用のbm_fd_data(type=BM_FD_LISTEN_SOCKET)もmain()がsigwaitでブロックしている
     * 間ずっと生存するスタック変数として持つ(他のctx類と同じ扱い)。 */
    struct bm_fd_data *listen_conn = NULL;
    int inbound_port = env_or_int("BM_INBOUND_PORT", cfg.inbound_port);
    if (inbound_port != 0)
    {
        int listen_fd = bm_network_listen("127.0.0.1", inbound_port);
        if (listen_fd < 0)
        {
            fprintf(stderr, "[network] failed to listen on 127.0.0.1:%d for inbound connections\n",
                    inbound_port);
        }
        else
        {
            listen_conn = bm_fd_data_new(BM_FD_LISTEN_SOCKET, listen_fd);
            if (listen_conn == NULL)
            {
                fprintf(stderr, "[network] bm_fd_data_new failed for inbound listen socket\n");
                close(listen_fd);
            }
            else
            {
                struct epoll_event listen_ev;
                listen_ev.events = EPOLLIN;
                listen_ev.data.ptr = listen_conn;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &listen_ev) != 0)
                {
                    perror("[network] epoll_ctl (listen socket)");
                    bm_fd_data_free(listen_conn);
                    close(listen_fd);
                    listen_conn = NULL;
                }
                else
                {
                    fprintf(stderr, "[network] listening for inbound connections on 127.0.0.1:%d\n",
                            inbound_port);
                }
            }
        }
    }

    /* §11 inbound接続 Stage 2: Tor hidden service連携(ControlPort自動化 or 静的torrc設定)。
     * どちらもStage 1のlistenが成功している場合のみ試みる(listen_connが無ければ転送する
     * 先が無い)。外部から見えるポート番号はBM_TOR_VIRTUAL_PORT(既定8444)で、ControlPortの
     * ADD_ONIONでも静的torrc設定でも共通して使う(「他のpeerが自分のonionアドレスの
     * どのポートへ接続してくるか」という意味は経路によらず同じため)。 */
    int virtual_port = env_or_int("BM_TOR_VIRTUAL_PORT", cfg.tor_virtual_port);

    /* §11 静的torrc設定への対応(PyBitmessageのkeys.dat onionhostname相当)。ユーザーが
     * ControlPortを使わず自分でtorrcにHiddenServiceDir/HiddenServicePortを設定し、
     * BM_INBOUND_PORTへ転送するよう構成した場合、daemon自身はTorと一切やり取りしないため
     * 自分のonionアドレスを知る手段が無い。bitmessage.confの[tor] onion_address、または
     * BM_ONION_ADDRESSでユーザーが直接教えれば、ControlPort連携(下記)を完全にスキップして、
     * そのアドレスをそのままonionpeer objectで告知する。BM_TOR_CONTROLより優先する
     * (PyBitmessageもonionhostname設定時はstemによる自動作成を試みない、同じ優先順位)。 */
    int tor_control_fd = -1;
    const char *onion_address_from_file = (cfg.onion_address[0] != '\0') ? cfg.onion_address : NULL;
    const char *manual_onion_address = env_or_str("BM_ONION_ADDRESS", onion_address_from_file);
    if (listen_conn != NULL && manual_onion_address != NULL)
    {
        if (bm_object_sync_announce_onion_peer(&object_sync_ctx, manual_onion_address, virtual_port) == 0)
        {
            fprintf(stderr,
                    "[tor_control] using statically configured onion address: %s:%d -> 127.0.0.1:%d "
                    "(BM_ONION_ADDRESS)\n",
                    manual_onion_address, virtual_port, inbound_port);
        }
    }
    /* §11 inbound接続 Stage 2: Tor ControlPort連携。BM_TOR_CONTROL=1が設定されており、かつ
     * Stage 1のlistenが成功している場合のみ試みる(listen_connが無ければADD_ONIONで転送する
     * 先が無い)。ControlPortへの接続はUnixドメインソケット(既定/run/tor/control、Debian/
     * Ubuntu系torパッケージの既定)を優先し、失敗すればTCP(既定127.0.0.1:9051)へ
     * フォールバックする(infra/tor_control.h参照)。
     * tor_control_fdはmain()がsigwaitでブロックしている間ずっと開いたままにする
     * スタック変数(他のctx類と同じ扱い)。これはbm_tor_control_add_onionが意図的に
     * Flags=Detachを使わない設計とペアであり、この接続を維持し続けることでhidden service
     * のライフサイクルをプロセスの生存期間と一致させ、プロセス終了(正常終了・クラッシュ問わず)
     * でTor側が自動的にhidden serviceを片付けてくれるようにしている(そうしないと次回起動時に
     * 永続化した鍵での再作成が"550 Onion address collision"で失敗する、tor_control.h参照)。 */
    else if (listen_conn != NULL && env_flag_or("BM_TOR_CONTROL", cfg.tor_control))
    {
        struct bm_tor_control_config tor_config;
        memset(&tor_config, 0, sizeof(tor_config));
        tor_config.control_socket_path = env_or_str("BM_TOR_CONTROL_SOCKET", cfg.tor_control_socket);
        tor_config.control_host = env_or_str("BM_TOR_CONTROL_HOST", cfg.tor_control_host);
        tor_config.control_port = env_or_int("BM_TOR_CONTROL_PORT", cfg.tor_control_port);

        tor_control_fd = bm_tor_control_connect_and_authenticate(&tor_config);
        if (tor_control_fd < 0)
        {
            fprintf(stderr, "[tor_control] hidden serviceの自動作成をスキップします(ControlPortに"
                            "接続できませんでした)\n");
        }
        else
        {
            char existing_key[BM_TOR_ONION_KEY_MAX_LEN];
            int has_existing_key = bm_config_store_get_tor_onion_key(config_db, existing_key, sizeof(existing_key));

            char *onion_address = NULL;
            char *new_private_key = NULL;
            int add_onion_rc = bm_tor_control_add_onion(tor_control_fd, has_existing_key == 1 ? existing_key : NULL,
                                                          virtual_port, inbound_port, &onion_address,
                                                          &new_private_key);
            if (add_onion_rc != 0)
            {
                fprintf(stderr, "[tor_control] hidden serviceの作成に失敗しました\n");
                close(tor_control_fd);
                tor_control_fd = -1;
            }
            else
            {
                if (new_private_key != NULL)
                {
                    bm_config_store_set_tor_onion_key(config_db, new_private_key);
                }
                fprintf(stderr, "[tor_control] hidden service ready: %s:%d -> 127.0.0.1:%d\n", onion_address,
                        virtual_port, inbound_port);

                /* §11 onionpeer objectでの自己announce(送信側)。registryはこの時点では
                 * まだ空(peer_connector_threadはこの後起動する)だが、object_pool.dbへ
                 * 登録しておけば以後getdataで配れる状態になる(他の自己生成object、
                 * getpubkey応答等と同じ扱い、object_sync.h参照)。 */
                bm_object_sync_announce_onion_peer(&object_sync_ctx, onion_address, virtual_port);
            }
            free(onion_address);
            free(new_private_key);
        }
    }

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

    /* bitmessage.confの[network] no_connect、またはBM_NO_CONNECT=1で実接続を抑止できる
     * (自動テスト用。cli_integration等が本物のネットワークへ接続しに行くとCI環境の到達性
     * 次第で数十秒単位で遅くなる/非決定的になるため)。 */
    pthread_t th_peer_connector;
    int peer_connector_started = 0;
    volatile sig_atomic_t peer_connector_stop = 0;
    if (env_flag_or("BM_NO_CONNECT", cfg.no_connect))
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
        pc_args->config.max_outbound = env_or_int("BM_MAX_OUTBOUND", cfg.max_outbound_connections);
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
