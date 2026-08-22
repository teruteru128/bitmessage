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

/*
 * §11「開発者が確認した身元不明のつながる可能性のあるノード」リスト(seeds/observed_nodes.txt、
 * 既定でbm_peer_manager_seed_bootstrapがmainnet時のみ自動的に読み込む)を読み込みpeers.dbへ
 * 登録する。1行に"ip_address port"、#で始まる行と空行は無視する。ファイルが無ければ何もせず
 * 0を返す(非致命的、配布形態によっては同梱されない場合もあるため)。公式seed一覧とは別の
 * source='observed_seed'で登録し、rating=0.0からのスタートとする(優先的に信用するわけでは
 * なく、初回接続の足がかり候補が1つ増えるだけの位置づけ、ファイル冒頭のコメント参照)。
 * 登録できた件数を返す(パース失敗行・DB書き込み失敗行はスキップしてカウントしない。
 * ファイル無し・有効な行が0件でも0を返すだけでエラー扱いはしない)。
 */
int bm_peer_manager_load_observed_nodes(sqlite3 *db, const char *path);

/*
 * peer_connectorの接続試行結果をratingへ反映する(PyBitmessageのrating更新方式を簡略化した
 * もの)。成功ならrating+0.1(上限1.0)とlast_seenを現在時刻に更新、失敗ならrating-0.1
 * (下限-1.0)のみ更新する。該当行が無ければ何もしない(候補は常にlist_topの結果から来るため
 * 通常は存在するはずだが、念のため無視する)。成功時0。
 */
int bm_peer_manager_record_result(sqlite3 *db, const char *ip_address, int port, int stream, int success);

/*
 * §1/§11: addrメッセージ/onionpeer object(infra/object_sync.c)等、ネットワークからの
 * 伝聞情報で教えられたホストを登録する。既存行があればservices/last_seenのみ更新し、
 * rating/sourceは変更しない(実際の接続実績で積み上げたratingを、単なる伝聞情報で
 * 上書き・リセットしないため)。新規行ならrating=0.0, source=sourceで挿入する。成功時0。
 */
int bm_peer_manager_upsert_learned(sqlite3 *db, const char *ip_address, int port, int stream,
                                    uint64_t services, int64_t last_seen, const char *source);

/*
 * §11 2026-08-22: 自分自身のonionアドレスをhostsテーブルへ"is_self=1"としてマークする
 * (PyBitmessageのknownnodes myselfフィールドと同じ発想)。version messageのnonceによる
 * 自己接続検知は、Torではプロセス全体で同じnonceを使い回すこと自体が「同一ノードが複数
 * circuitから接続している」という相関情報を漏らしTorの匿名性を損なうため採用しなかった
 * (ユーザーとの議論の結論)。代わりにbm_peer_manager_list_top(接続候補選定)がis_self=1の
 * 行を常に除外することで、そもそも自分自身へ接続を試みないようにする。main.cがTor
 * ControlPort連携(Stage 2)またはBM_ONION_ADDRESS(静的torrc設定)で自分のonionアドレスが
 * 判明した直後に1回呼ぶ想定。既存行(gossip等で自分のアドレスが既に学習済みだった場合)が
 * あればis_selfだけ立てて他の列(rating/source等)はそのまま残す。成功時0。
 */
int bm_peer_manager_mark_self(sqlite3 *db, const char *ip_address, int port, int stream);

/*
 * §11 peers.dbの低rating/古いノードのクリーンアップ。PyBitmessage(network/knownnodes.pyの
 * cleanupKnownNodes)準拠の2条件で削除する: (1) last_seenからBM_PEER_CLEANUP_MAX_AGE_SECONDS
 * (28日)以上経過したホストはratingを問わず削除、(2) last_seenからBM_PEER_CLEANUP_MIN_AGE_
 * SECONDS(3時間)以上経過し、かつratingがBM_PEER_CLEANUP_FORGET_RATING(-0.5)以下のホストを
 * 削除する。PyBitmessageと異なりstreamごとに最低1件残す安全弁は設けていない
 * (bm_peer_manager_seed_bootstrapがhostsテーブル完全空の場合のみ既定シードを再投入する
 * 既存の仕組みが、テーブル全体が空になった場合の実質的な安全弁として機能するため)。
 * 削除件数を返す(エラー時-1)。
 */
int bm_peer_manager_cleanup(sqlite3 *db, int64_t now);

#endif /* BM_INFRA_PEER_MANAGER_H */
