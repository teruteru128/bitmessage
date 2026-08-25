#ifndef BM_CORE_CONFIG_STORE_H
#define BM_CORE_CONFIG_STORE_H

/*
 * config.db(§11 設定の永続化)。bitmessagedプロセスの再起動をまたいで保持したい設定を置く。
 * SOCKS5プロキシ(Tor等をoutbound接続に使うためのもの。inbound/hidden serviceの実装は
 * §9のままスコープ外)を持つ。core層に置くのは、core(api_server.c)からもinfra
 * (peer_connector.c)からも参照するため(infra→coreの片方向依存というDESIGN.md §1.2の
 * 決定に合わせる)。設定変更はAPI経由(api_server.cのgetSocksProxyOnion/Clearnet系)で
 * 行うが、peer_connector_threadは接続サイクルのたびconfig.dbを読み直す(§11設定変更の
 * 動的リロード、peer_connector.h参照)。
 *
 * §11 2026-08-26発覚: 以前はonion/クリアネットの区別無く単一のsocks_proxy設定を全
 * outbound接続に適用していたが、これはPyBitmessage本家(network/connectionpool.pyの
 * socksproxytype/onionsocksproxytype分離)と異なる誤りだった。Tor(SOCKS5)を有効化すると
 * クリアネットIP宛の接続まで全てTor出口ノード経由になってしまい、出口ノードは多数の
 * Torユーザーで共有されるIPのため相手ノードから"Too many connections from your IP"等の
 * レート制限を受けやすく、外部ノードへの接続性が悪化する原因になっていた
 * (journalctl調査で実際に多数観測、DESIGN-LOG.md参照)。本家に合わせ、onion peer(.onion
 * 宛)専用のプロキシ設定(socks_proxyテーブル、既存ユーザーの設定はそのままこちらに
 * 引き継がれる)と、クリアネットIP宛専用のプロキシ設定(socks_proxy_clearnetテーブル、
 * 既定disabled=直結)を分離した。
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

/* onion peer(.onion宛)向けSOCKS5設定。行が無ければ既定値(enabled=0, host="127.0.0.1",
 * port=9050、Torの既定SocksPort)を返す。DBエラー時のみ-1、未設定は正常系として0を返す */
int bm_config_store_get_socks_proxy_onion(sqlite3 *db, struct bm_socks_proxy_config *out);

/* upsert(常に1行のみ)。成功時0 */
int bm_config_store_set_socks_proxy_onion(sqlite3 *db, const struct bm_socks_proxy_config *cfg);

/* クリアネットIP宛のSOCKS5設定。行が無ければ既定値(enabled=0=直結, host="127.0.0.1",
 * port=9050)を返す。DBエラー時のみ-1、未設定は正常系として0を返す */
int bm_config_store_get_socks_proxy_clearnet(sqlite3 *db, struct bm_socks_proxy_config *out);

/* upsert(常に1行のみ)。成功時0 */
int bm_config_store_set_socks_proxy_clearnet(sqlite3 *db, const struct bm_socks_proxy_config *cfg);

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
