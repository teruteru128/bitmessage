#ifndef BM_INFRA_PEER_CONNECTOR_H
#define BM_INFRA_PEER_CONNECTOR_H

/*
 * peer_connector_thread(§1.1)。peers.dbへブートストラップシードを投入し、
 * 確率的な重み付きランダムサンプリング(§11 2026-08-23、PyBitmessage本家の
 * network/connectionchooser.py chooseConnection移植)で接続数を維持し続ける常駐
 * スレッド実装。
 */

#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

struct bm_peer_registry; /* peer_registry.h、循環includeを避けるため前方宣言のみ */
struct bm_peer_entry; /* core/peer_manager.h、同上 */
struct bm_object_sync_ctx; /* object_sync.h、同上 */

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
    /* §11 2026-08-23発覚のバグ修正: NULL可。非NULLかつ*stop_flagが非0になったら、
     * bm_peer_connector_connect_initialの候補ループを次のcandidateへ進める前に中断する。
     * これが無いと、SIGTERM後もmax_outbound件ぶんの候補(1件あたりCONNECT_TIMEOUT_SEC+
     * SOCKS5_HANDSHAKE_TIMEOUT_SEC=最大25秒)を全部試し終えるまでbm_peer_connector_thread
     * がpthread_joinできず、daemonの終了処理が数分単位で長引く原因になっていた
     * (bm_peer_connector_threadが自動的にこのフィールドへ自身のstop_flagを設定する)。
     * §11 2026-08-24 backlog項目9(TSan導入)で発覚: `volatile sig_atomic_t`はスレッド間の
     * 可視性を保証しないため、`_Atomic sig_atomic_t`(C11)へ変更した(api_server.h参照、
     * 詳細な経緯はそちら)。 */
    _Atomic sig_atomic_t *stop_flag;
    /* §11 2026-08-24 backlog項目6: onionpeer自己announceの定期再送(2時間おきチェック、
     * PyBitmessage本家準拠)を、この既存の1秒間隔ポーリングループに相乗りさせる(Dandelion++の
     * bm_dandelion_maybe_reshuffle/expire_and_refluffと同じ理由、専用スレッドは新設しない)。
     * object_sync_ctxがNULLか、self_onion_addressがNULL/空文字列ならreannounceはスキップする
     * (Tor未使用の構成、またはonionアドレスがまだ確立していない起動直後を想定)。 */
    struct bm_object_sync_ctx *object_sync_ctx;
    const char *self_onion_address;
    int self_onion_port;
};

/*
 * peers.dbが空ならブートストラップシード(bm_peer_manager_seed_bootstrap)を投入し、
 * bm_peer_connector_choose_candidate_index(確率的な重み付きランダムサンプリング、
 * 既にregistryに接続済みのものは除く)でmax_outbound件になるまでTCP接続を試みる
 * (1件あたり5秒タイムアウト)。成功した接続はepollへ登録・versionメッセージ送信・
 * registryへの登録・peer_manager.dbのratingを更新する(成功+0.1)。失敗した候補は
 * ratingを減点する(-0.1)。config->stop_flagが非NULLかつ非0になった時点で候補ループを
 * 中断する。戻り値: 今回新たに接続できた件数(0以上)、エラー時は-1。
 */
int bm_peer_connector_connect_initial(const struct bm_peer_connector_config *config);

/*
 * §11 2026-08-23: PyBitmessage本家(network/connectionchooser.pyのchooseConnection)を
 * 移植した確率的な重み付きランダムサンプリング。candidates[0..candidate_count)から毎回
 * 一様ランダムに1件選び、ratingに応じた確率(0.05/(1-rating)、rating=0で5%、rating=0.9で
 * 50%、rating>=1.0では無条件採用)で採用するかどうかを判定し、棄却されたら別の候補を
 * 再度試す(最大max_attempts回)。registryが非NULLなら既に接続済みの相手は無条件で
 * 不採用として次を試す。戻り値: 選ばれた候補のcandidates配列内index、見つからなければ-1
 * (peer_connector.cのテスト、tests/test_peer_connector_choose.c向けに公開している)。
 *
 * §11 2026-08-24: rating<0の候補には追加でBM_PEER_LOW_RATING_COOLDOWN_SECONDS(既定30分)の
 * 再接続クールダウンを課す(candidates[].last_attempt基準、nowから経過していなければ
 * registry済みと同様に不採用として次を試す)。PyBitmessage本家のchooseConnection自体は
 * rating<0を排除しない設計(候補選定と接続結果の意味論はPyBitmessage互換のまま維持する
 * 方針、DESIGN.md §11参照)だが、「TCP応答はあるが直後にfatal切断してくるノード」への
 * 無駄な再接続頻度だけをうちの実装側で緩和する。rating>=0の候補には一切影響しない。
 */
int bm_peer_connector_choose_candidate_index(const struct bm_peer_entry *candidates, int candidate_count,
                                              struct bm_peer_registry *registry, int max_attempts, int64_t now);

/*
 * 常駐スレッド本体。起動直後にbm_peer_connector_connect_initial相当を1回実行し、以後
 * RECONNECT_INTERVAL_SECONDS間隔で接続数(registry参照)をmax_outboundまで補充し続ける。
 * *stop_flagが非0になったら、実行中のconnect_initial呼び出し内の候補ループも次の候補へは
 * 進まず中断する(pthread_join可能)。ただし「今まさに接続/SOCKS5ハンドシェイク中の1件」
 * だけは処理を中断できず、最大CONNECT_TIMEOUT_SEC+SOCKS5_HANDSHAKE_TIMEOUT_SEC(既定25秒)
 * かかりうる。
 * argはmallocされたstruct bm_peer_connector_thread_args*を期待し、終了時に自身でfreeする。
 */
struct bm_peer_connector_thread_args
{
    struct bm_peer_connector_config config;
    _Atomic sig_atomic_t *stop_flag;
};
void *bm_peer_connector_thread(void *arg);

#endif /* BM_INFRA_PEER_CONNECTOR_H */
