#ifndef BM_CORE_API_SERVER_H
#define BM_CORE_API_SERVER_H

/*
 * api_server_thread(§1.1)。自前JSON-RPC 2.0サーバー(§6)。
 * ハンドラ辞書(struct bm_api_method配列)とHTTPトランスポートを分離した設計(§6.0-6.1)。
 */

#include <sqlite3.h>

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
};

/* bind+listenする。成功時0、*out_listen_fdにfdを設定。失敗時(ポート使用中等)は非0 */
int bm_api_server_listen(const struct bm_api_server_config *config, int *out_listen_fd);

/* accept済みの1コネクションに対して1リクエスト処理する(処理後closeする) */
void bm_api_server_handle_connection(int client_fd, const struct bm_api_server_config *config);

/* listen_fdに対してaccept loopを回し続ける(呼び出し元スレッドをブロックする) */
void bm_api_server_serve_forever(int listen_fd, const struct bm_api_server_config *config);

/* argは `const struct bm_api_server_config *` を期待する。ポート衝突時は§6.1のランダム
 * フォールバック(32767〜65535)を行う。 */
void *bm_api_server_thread(void *arg);

#endif /* BM_CORE_API_SERVER_H */
