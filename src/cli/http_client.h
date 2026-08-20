#ifndef BM_CLI_HTTP_CLIENT_H
#define BM_CLI_HTTP_CLIENT_H

/*
 * bitmessaged(core/api_server.c)宛てのJSON-RPC 2.0リクエストを送るための
 * 最小限のHTTP/1.1クライアント。CLI専用(daemon側では使わない)。
 */

#include <stddef.h>

/*
 * host:portへPOSTし、レスポンスボディをmalloc文字列で返す(呼び出し側でfree)。
 * *out_http_statusにHTTPステータスコード(200, 401等)を設定する。
 * 接続自体に失敗した場合はNULLを返し、*out_http_statusは0のまま。
 */
char *bm_http_post_json(const char *host, int port, const char *username, const char *password,
                         const char *body, int *out_http_status);

#endif /* BM_CLI_HTTP_CLIENT_H */
