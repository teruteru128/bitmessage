#ifndef BM_INFRA_DANDELION_H
#define BM_INFRA_DANDELION_H

/*
 * §9 Dandelion++ Stage 2: 自分が新規に検出したobjectをまず単一の子ピア(stem successor)へ
 * dinvで中継し、タイムアウト(固定10秒 + 平均30秒の指数分布、DESIGN.md §9.1の「ポアソン分布」
 * を指数分布で近似したもの)経過、または子ピア候補が居ない場合に通常のfluff(inv全配信)へ
 * 強制遷移させる。
 *
 * 今回実装したのは単一ホップ分のstem(DESIGN.md §9.1の「これをピアが連鎖的に繰り返す
 * ランダムウォーク」のうち自分が担う1ホップ目)のみ。dinvで受信したobjectを自分も
 * 継続してstem中継する(多段リレー)部分は未実装(DESIGN.md v1.1以降のbacklog参照、
 * 受信経路(inv/dinv受信→getdata→object到着)全体に「どちらで最初に知ったか」の状態を
 * 通す必要があり影響範囲が大きいため、ユーザーと合意の上でStage 2のスコープから外した)。
 *
 * プロセス内シングルトンとして実装する(DESIGN.md §9.2、DB永続化不要、再起動でリセットされる
 * 仕様)。テスト容易性のため、時刻は全てUNIX秒(int64_t)を呼び出し側から明示的に渡す設計にした
 * (内部でtime(NULL)を呼ばない)。infra/object.cのbm_decide_propagation(既存の公開interface、
 * §9.2で確保済み)がこのモジュールへ委譲する形で実際のロジックを提供する。
 */

#include <stddef.h>
#include <stdint.h>

#include "network.h"
#include "object.h"
#include "peer_registry.h"

/* プロセス起動時に1回呼ぶ(main.c)。テストでも各テストの先頭で呼び直してよい
 * (内部状態を初期化するだけで、二重初期化しても安全)。 */
void bm_dandelion_module_init(void);

/*
 * 現在のstem successorを、必要なら再抽選する。BM_DANDELION_EPOCH_SECONDS(600秒)経過ごとに、
 * registryに登録済みのoutbound(BM_FD_CLIENT_SOCKET)接続のうちBM_SERVICE_NODE_DANDELION
 * ビットを立てているものから一様ランダムに1つ選び直す(bm_peer_registry_pick_random_
 * dandelion_peer)。該当ピアが1つも無ければstem successor無し(以後は常にFLUFF、
 * DESIGN.md §9.1「outbound接続がないノードでは機能しない」に対応)として扱う。
 * nowはUNIX秒(テスト容易性のため呼び出し側が渡す)。
 */
void bm_dandelion_maybe_reshuffle(struct bm_peer_registry *registry, int64_t now);

/*
 * infra/object.hのbm_decide_propagationの実体。object_hashを初めて見た時点でstem successorの
 * 有無を確認し、タイムアウト(固定10秒+平均30秒の指数分布)を設定する。以後同じhashに
 * ついて呼ばれるたびに: タイムアウト前かつstem successorがあればtarget_connectionが
 * stem successorと一致する場合のみSTEM、それ以外はSKIP。タイムアウト後(またはそもそも
 * stem successorが無い場合)は常にFLUFF(以後このhashについては恒久的にFLUFF)。
 */
enum bm_propagation_mode bm_dandelion_decide(const unsigned char object_hash[32],
                                              const struct bm_fd_data *target_connection, int64_t now);

/*
 * stemタイムアウトを過ぎてもまだfluffされていないhashを能動的にfluffする。
 * bm_dandelion_decideは"呼ばれた時点"でしか判定しないため、誰も呼び直さない限り
 * stemのまま埋もれてしまう。定期的に(1秒間隔目安、DESIGN.md §9.2のInvThread.expire()相当)
 * peer_connector_threadの再接続ループ等から呼ぶ想定。合わせて、fluff済みになってから
 * 十分時間が経った古いエントリを間引く(無制限のメモリ増加を防ぐ)。
 * 実際にfluffした件数を返す。
 */
int bm_dandelion_expire_and_refluff(struct bm_peer_registry *registry, int64_t now);

#endif /* BM_INFRA_DANDELION_H */
