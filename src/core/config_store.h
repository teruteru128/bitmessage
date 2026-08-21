#ifndef BM_CORE_CONFIG_STORE_H
#define BM_CORE_CONFIG_STORE_H

/*
 * config.db(§11 設定の永続化)。bitmessagedプロセスの再起動をまたいで保持したい設定を置く。
 * v1.1時点ではSOCKS5プロキシ(Tor等をoutbound接続に使うためのもの。inbound/hidden serviceの
 * 実装は§9のままスコープ外)の1項目のみ。core層に置くのは、core(api_server.c)からも
 * infra(peer_connector.c)からも参照するため(infra→coreの片方向依存というDESIGN.md §1.2の
 * 決定に合わせる)。設定変更はAPI経由(api_server.cのgetSocksProxy/setSocksProxy)で行うが、
 * peer_connector_threadは起動時に読み込んだ値を使い続ける(実行中の設定変更は次回起動まで
 * 反映されない、v1.1のスコープ簡略化)。
 */

#include <sqlite3.h>

struct bm_socks_proxy_config
{
    int enabled;
    char host[256];
    int port;
};

/* 成功時0 */
int bm_config_store_init_schema(sqlite3 *db);

/* 行が無ければ既定値(enabled=0, host="127.0.0.1", port=9050、Torの既定SocksPort)を返す。
 * DBエラー時のみ-1、未設定は正常系として0を返す */
int bm_config_store_get_socks_proxy(sqlite3 *db, struct bm_socks_proxy_config *out);

/* upsert(常に1行のみ)。成功時0 */
int bm_config_store_set_socks_proxy(sqlite3 *db, const struct bm_socks_proxy_config *cfg);

#endif /* BM_CORE_CONFIG_STORE_H */
