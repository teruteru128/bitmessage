#ifndef BM_INFRA_PEER_MANAGER_H
#define BM_INFRA_PEER_MANAGER_H

/*
 * peers.db(§2.1)の操作。移植元: study/libstudy の bm_peer_manager.h/bm_node_db.h
 * (いずれも中身が空だったため新規実装)。
 */

#include <sqlite3.h>
#include <stdint.h>

struct bm_peer_entry
{
    char ip_address[64];
    int port;
    int stream;
    uint64_t services;
    int64_t last_seen;
    double rating;
    char source[16];
};

/* 成功時0 */
int bm_peer_manager_init_schema(sqlite3 *db);

/* 既存行があればUPDATE、なければINSERT。成功時0 */
int bm_peer_manager_upsert(sqlite3 *db, const struct bm_peer_entry *entry);

/*
 * streamに属するホストをrating降順でmax_results件まで取得する。
 * *out_countに実際に取得できた件数を設定する。呼び出し側は results[max_results]を確保しておく。
 * 成功時0
 */
int bm_peer_manager_list_top(sqlite3 *db, int stream, struct bm_peer_entry *results,
                              int max_results, int *out_count);

/*
 * hostsテーブルが空ならブートストラップシードノードを投入する(PyBitmessage
 * knownnodes.pyのDEFAULT_NODES/TESTNET_NODES準拠、2026-08-21確認)。既に1件でも
 * あれば何もしない(手動追加・既知情報を上書きしないため)。成功時0(0件挿入でも0)。
 */
int bm_peer_manager_seed_bootstrap(sqlite3 *db, int testnet);

#endif /* BM_INFRA_PEER_MANAGER_H */
