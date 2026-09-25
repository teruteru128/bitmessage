#ifndef BM_COMMON_LOG_THROTTLE_H
#define BM_COMMON_LOG_THROTTLE_H

#include <stdint.h>

/*
 * §11 2026-09-25 項目46: 同じ理由のログを一定間隔に1回へ間引くための小さな状態。
 * 経緯: 時計が数時間ずれたPyBitmessageノードがTor経由で数秒〜十数秒おきに
 * inbound接続してきて、そのたびにversion timestampの検証で切断され、同じWARNが
 * 1時間に約190行ずつjournalを埋めた(こちらの拒否自体はPyBitmessage本家と同じ仕様で
 * 正しく、相手の時計が直るまで止める手段が無い)。Tor経由のinboundは送信元が全て
 * 127.0.0.1に見えるため相手ごとの識別もできず、ログの側で間引くことにした。
 *
 * 使い方: 出したいログの直前でbm_log_throttle_checkを呼び、1が返ったときだけログを出す。
 * *out_suppressedに前回出してから黙った回数が入るので、それもログに含めること。
 * 間引かれた最後の分の回数は、次にログが出るまで(=同じ理由が再び起きるまで)報告されない。
 * 排他制御はしない(呼び出し側が単一スレッドから使う前提。使う側でその旨を明記すること)。
 * ゼロ初期化した状態がそのまま初期状態(最初の1回は必ず出る)。
 */
struct bm_log_throttle
{
    int64_t last_emit;   /* 最後にログを出した時刻。emitted==0の間は無意味 */
    uint64_t suppressed; /* last_emit以降に黙った回数 */
    int emitted;         /* 1度でもログを出したか */
};

/*
 * 今ログを出すべきなら1を返し、*out_suppressedへ前回から黙った回数を入れて数をリセットする。
 * 前回ログを出してからinterval_seconds未満なら0を返し、黙った回数を1つ増やす
 * (*out_suppressedは変更しない)。out_suppressedはNULL可。
 */
int bm_log_throttle_check(struct bm_log_throttle *t, int64_t now, int64_t interval_seconds,
                          uint64_t *out_suppressed);

#endif /* BM_COMMON_LOG_THROTTLE_H */
