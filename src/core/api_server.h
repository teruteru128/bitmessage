#ifndef BM_CORE_API_SERVER_H
#define BM_CORE_API_SERVER_H

/*
 * api_server_thread(§1.1)。自前JSON-RPC 2.0サーバー(§6)。
 * TODO: ハンドラ辞書(struct api_method配列)とHTTPレイヤーの実装に着手する。
 */

void *bm_api_server_thread(void *arg);

#endif /* BM_CORE_API_SERVER_H */
