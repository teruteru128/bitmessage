#ifndef BM_INFRA_PEER_CONNECTOR_H
#define BM_INFRA_PEER_CONNECTOR_H

/*
 * peer_connector_thread(§1.1)。peers.dbへブートストラップシードを投入し、
 * rating上位から接続数を維持し続ける常駐スレッド実装。
 */

#include <signal.h>
#include <sqlite3.h>

struct bm_peer_registry; /* peer_registry.h、循環includeを避けるため前方宣言のみ */

struct bm_peer_connector_config
{
    int epfd;
    sqlite3 *peers_db;
    int testnet;
    int max_outbound;
    const char *user_agent;
    struct bm_peer_registry *registry; /* NULL可(未使用ならレジストリ登録・重複接続チェックをスキップ) */
    /* §11 outbound接続用SOCKS5プロキシ設定(config.db、core/config_store.c)。NULL可
     * (その場合は常に直結)。ポインタではなくDBハンドルを持たせているのは、
     * bm_peer_connector_connect_initialが呼ばれるたび(=再接続サイクルのたび、既定30秒間隔)
     * に都度読み直すため(§11設定変更の動的リロード): setSocksProxy APIでの変更が
     * daemon再起動なしで次の再接続サイクルから反映されるようにする。 */
    sqlite3 *config_db;
};

/*
 * peers.dbが空ならブートストラップシード(bm_peer_manager_seed_bootstrap)を投入し、
 * rating上位から(既にregistryに接続済みのものは除く)max_outbound件になるまでTCP接続を
 * 試みる(1件あたり5秒タイムアウト)。成功した接続はepollへ登録・versionメッセージ送信・
 * registryへの登録・peer_manager.dbのratingを更新する(成功+0.1)。失敗した候補は
 * ratingを減点する(-0.1)。戻り値: 今回新たに接続できた件数(0以上)、エラー時は-1。
 */
int bm_peer_connector_connect_initial(const struct bm_peer_connector_config *config);

/*
 * 常駐スレッド本体。起動直後にbm_peer_connector_connect_initial相当を1回実行し、以後
 * RECONNECT_INTERVAL_SECONDS間隔で接続数(registry参照)をmax_outboundまで補充し続ける。
 * *stop_flagが非0になったら次のポーリングタイミング(最大1秒)で終了する(pthread_join可能)。
 * argはmallocされたstruct bm_peer_connector_thread_args*を期待し、終了時に自身でfreeする。
 */
struct bm_peer_connector_thread_args
{
    struct bm_peer_connector_config config;
    volatile sig_atomic_t *stop_flag;
};
void *bm_peer_connector_thread(void *arg);

#endif /* BM_INFRA_PEER_CONNECTOR_H */
