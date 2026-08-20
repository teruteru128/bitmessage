#ifndef BM_INFRA_PEER_CONNECTOR_H
#define BM_INFRA_PEER_CONNECTOR_H

/*
 * peer_connector_thread(§1.1)のv1実装。起動時にpeers.dbへブートストラップシードを
 * 投入し、上位N件へ実際にTCP接続してversionメッセージを送る。
 *
 * TODO: v1は起動時1回のみの接続で、再接続・維持・rating更新ループは未実装。
 * 本来のDESIGN.md §1.1「peer_connector_thread」は常駐スレッドとして接続数を
 * 維持し続ける想定だが、まずは実際にネットワークと繋がることを優先し、
 * 定期実行化は次のステップとする。
 */

#include <sqlite3.h>

struct bm_peer_connector_config
{
    int epfd;
    sqlite3 *peers_db;
    int testnet;
    int max_outbound;
    const char *user_agent;
};

/*
 * peers.dbが空ならブートストラップシード(bm_peer_manager_seed_bootstrap)を投入し、
 * rating上位からmax_outbound件までTCP接続を試みる(1件あたり5秒タイムアウト)。
 * 成功した接続はepollへ登録し、versionメッセージを送信する
 * (以後の応答はnetwork_epoll_threadが処理する)。
 * 戻り値: 実際に接続できた件数(0以上)、エラー時は-1。
 */
int bm_peer_connector_connect_initial(const struct bm_peer_connector_config *config);

#endif /* BM_INFRA_PEER_CONNECTOR_H */
