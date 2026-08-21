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
#include <stddef.h>

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

/*
 * §11 Stage 2: Tor hidden serviceのed25519秘密鍵("ED25519-V3:<base64>"、control-spec準拠の
 * ADD_ONIONへそのまま渡せる形式)。一度ADD_ONIONで生成した鍵をここへ永続化し、再起動のたびに
 * 同じ鍵を渡すことで同一のonionアドレスを再利用できるようにする(生成のたびにアドレスが
 * 変わるのを防ぐため。infra/tor_control.c参照)。
 */
#define BM_TOR_ONION_KEY_MAX_LEN 160

/* 未設定(行が無い/NULL)ならoutを空文字列にし0を返す。設定済みなら値を書き込み1を返す。
 * DBエラー時のみ-1 */
int bm_config_store_get_tor_onion_key(sqlite3 *db, char *out, size_t out_size);

/* upsert(常に1行のみ)。成功時0 */
int bm_config_store_set_tor_onion_key(sqlite3 *db, const char *private_key);

#endif /* BM_CORE_CONFIG_STORE_H */
