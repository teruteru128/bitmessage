#ifndef BM_CORE_API_SERVER_H
#define BM_CORE_API_SERVER_H

/*
 * api_server_thread(§1.1)。自前JSON-RPC 2.0サーバー(§6)。
 * ハンドラ辞書(struct bm_api_method配列)とHTTPトランスポートを分離した設計(§6.0-6.1)。
 */

#include <signal.h>
#include <sqlite3.h>

#include "../common/queue.h"
#include "keyring.h"

struct bm_api_server_config
{
    const char *bind_address; /* 既定"127.0.0.1"(§6.1) */
    int port;                  /* 既定8442 */
    const char *username;       /* HTTP Basic認証。NULLなら認証を要求しない(テスト用) */
    const char *password;
    bm_keyring_t *keyring;
    sqlite3 *identity_db;
    sqlite3 *messages_db;
    /* sendMessageが生成したobjectの投入先(DESIGN.md §1.2)。NULL可(その場合はネットワークへ
     * 流さず、objectはinventoryHashの計算にのみ使われて破棄される。testやCLI単体動作用)。
     * infra/object_sync.cのbm_object_sync_broadcast_threadが消費する。 */
    bm_queue_t *broadcast_queue;
    /* §11 config.db(core/config_store.c)。NULL可(その場合getSocksProxy/setSocksProxyは
     * エラーを返す。testやCLI単体動作用)。 */
    sqlite3 *config_db;
    /* §11 peers.db(core/peer_manager.c)。NULL可(その場合addPeerはエラーを返す。testや
     * CLI単体動作用)。addPeerで手動追加したpeerはsource='manual'で登録される。 */
    sqlite3 *peers_db;
};

/* bind+listenする。成功時0、*out_listen_fdにfdを設定。失敗時(ポート使用中等)は非0 */
int bm_api_server_listen(const struct bm_api_server_config *config, int *out_listen_fd);

/* accept済みの1コネクションに対して1リクエスト処理する(処理後closeする) */
void bm_api_server_handle_connection(int client_fd, const struct bm_api_server_config *config);

/*
 * listen_fdに対してaccept loopを回し続ける(呼び出し元スレッドをブロックする)。
 * accept()を直接ブロッキングでは呼ばず、poll()に1秒のタイムアウトを与えて*stop_flagを
 * 定期的に再チェックすることでグレースフルシャットダウンに対応する(peer_connector_thread
 * と同じポーリング方式、§11)。*stop_flagが非0になれば次のタイムアウトで抜ける。
 */
void bm_api_server_serve_forever(int listen_fd, const struct bm_api_server_config *config,
                                  volatile sig_atomic_t *stop_flag);

/*
 * pthread_createのarg用にmallocして渡す(スレッド側でfreeする、peer_connector_thread等と
 * 同じ扱い)。configはスレッドの生存期間中ずっと有効な場所(呼び出し側のスタック変数等)を
 * 指していること。
 */
struct bm_api_server_thread_args
{
    const struct bm_api_server_config *config;
    volatile sig_atomic_t *stop_flag;
};
void *bm_api_server_thread(void *arg);

#endif /* BM_CORE_API_SERVER_H */
