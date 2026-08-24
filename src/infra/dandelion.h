#ifndef BM_INFRA_DANDELION_H
#define BM_INFRA_DANDELION_H

/*
 * §9 Dandelion++ Stage 2: 自分が新規に検出したobjectをまず単一の子ピア(stem successor)へ
 * dinvで中継し、タイムアウト(固定10秒 + 平均30秒の指数分布、DESIGN.md §9.1の「ポアソン分布」
 * を指数分布で近似したもの)経過、または子ピア候補が居ない場合に通常のfluff(inv全配信)へ
 * 強制遷移させる。
 *
 * §9.4(Stage 2)で単一ホップ分のstem(DESIGN.md §9.1の「これをピアが連鎖的に繰り返す
 * ランダムウォーク」のうち自分が担う1ホップ目)を実装した。§9.5(Stage 3)で、objectを
 * 最初にどちらのコマンドで知ったか(inv=既に他ノードがfluff済み、dinv=まだstem中)を
 * 区別し、inv経由で知ったobjectはstemせず即座にfluffするようにした(既に公開済みの
 * objectをそれ以上stemしても匿名性の得は無く、遅延させるだけ無駄なため)。dinv経由・
 * 自分発(bm_dandelion_note_sourceを呼ばれていない=provenance不明)のobjectは従来通り
 * stem→タイムアウトfluffの経路を通る。
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
 * §9.5 Stage 3: inv/dinv受信時点(object本体がまだ手元に無い、getdataを送る段階)で、
 * このhashを最初にどちらのコマンドで知ったかを記録しておく。is_dinv=0(通常のinv)なら
 * 「既に他ノードがfluff済み」を意味し、後でbm_dandelion_decideが呼ばれた際にstemを
 * 一切試みず即座にFLUFFする。is_dinv=1(dinv)なら通常のstem→タイムアウトfluff経路を通る
 * (実質的には何もしない、bm_dandelion_decideの既定動作のまま)。
 * infra/object_sync.cのhandle_inv(inv/dinv共通処理)が、未所持だったhashについてのみ
 * 呼ぶ想定(既知のhashは今後bm_dandelion_decideが呼ばれることも無いため記録不要)。
 */
void bm_dandelion_note_source(const unsigned char object_hash[32], int is_dinv, int64_t now);

/*
 * infra/object.hのbm_decide_propagationの実体。object_hashを初めて見た時点でstem successorの
 * 有無を確認し、タイムアウト(固定10秒+平均30秒の指数分布)を設定する。bm_dandelion_note_source
 * で「通常invで知った」と記録済みのhashは、この時点でstemを試みず即座にFLUFFする
 * (Stage 3)。それ以外(dinvで知った、または自分発でprovenance不明)は従来通り: タイムアウト
 * 前かつstem successorがあればtarget_connectionがstem successorと一致する場合のみSTEM、
 * それ以外はSKIP。タイムアウト後(またはそもそもstem successorが無い場合)は常にFLUFF
 * (以後このhashについては恒久的にFLUFF)。
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

/*
 * §11 2026-08-24発覚のバグ修正: object_sync.cのsend_big_inv(自分の保有object全件を
 * 新規peerへ知らせる、handshake完了時に1回)が、誤ってbm_dandelion_decide経由で
 * このモジュール本来のstem/fluff判定ロジックを新規に発火させてしまっていた。
 * 何年も前から公開済みのobjectを、まるで今作られたばかりの新規objectであるかのように
 * stem対象にしてしまい、10〜40秒後のタイムアウト→300秒後の間引き→次回send_big_inv
 * 呼び出し時に再度「未知」扱いで作り直され同じサイクルを繰り返す、という実質無限ループで
 * bm_peer_registry_broadcast_invが大量に空発火し続けていた(実測: 稼働7時間で
 * object_pool.dbの実件数の50倍superのbroadcast発生)。
 *
 * PyBitmessage本家のsendBigInv(`dandelion_ins.hasHash(objHash)`相当)に合わせ、
 * 「今まさにstem中(まだfluffされていない)hashかどうか」だけを読み取り専用で判定する
 * 関数を新設した。bm_dandelion_decideと違い、エントリが存在しなければ新規作成せず
 * 単に「stem中ではない」(0)を返す(副作用が無い、send_big_invはこれで単純に除外判定
 * するだけで、fluff/stemの判定自体には一切関与しない)。
 */
int bm_dandelion_is_stemming(const unsigned char object_hash[32]);

#endif /* BM_INFRA_DANDELION_H */
