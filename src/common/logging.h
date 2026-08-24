#ifndef BM_COMMON_LOGGING_H
#define BM_COMMON_LOGGING_H

/*
 * §11 2026-08-23: fprintf(stderr, ...)による診断ログには時刻が無く、実際にどの起動
 * (どのrun)のログなのか行番号とrunの区切り("DB初期化完了"等)から推測するしかなかった
 * (長時間の運用テスト中にユーザーが気づいた不便)。
 *
 * 実運用ではsystemd配下での起動を想定しており、その場合はjournaldがログ受信時刻を
 * 別途正確に記録するため、こちらで時刻を埋め込むと二重になる。systemdは
 * journald接続のstdout/stderrに対して環境変数JOURNAL_STREAMをセットするので、これを
 * 起動時に一度だけ確認し、未設定(=手動起動、開発時のnohup運用等)ならこちらで時刻を
 * 先頭に付け、設定済み(=systemd配下)なら付けない。BM_LOG_TIMESTAMPS=0/1で明示的に
 * 上書きすることもできる(自動判定が外れるケースの保険)。
 *
 * §11 2026-08-24 backlog項目8完了: ログレベル(DEBUG/INFO/WARN/ERROR)を追加。
 * 全呼び出し箇所(約140箇所)を1つずつ「どのレベルに当たるか」判断し直して移行した
 * (判断基準はDESIGN.md §11参照)。既定の最低レベルはBM_LOG_INFO(DEBUGは既定で抑制)。
 * BM_LOG_LEVEL環境変数(DEBUG/INFO/WARN/ERROR、大文字小文字区別しない)で変更できる。
 * journald連携(優先度プレフィックス`<N>`によるSD_ERR等へのマッピング)はスコープ外とした
 * (フィルタリングのみが要求事項で、journald固有の仕組みへ依存を増やすのは過剰と判断)。
 */

enum bm_log_level
{
    BM_LOG_DEBUG = 0,
    BM_LOG_INFO = 1,
    BM_LOG_WARN = 2,
    BM_LOG_ERROR = 3
};

/* 起動時に1回だけ呼ぶ(main()の先頭付近を想定)。呼ばなくても既定(時刻を付ける、
 * 最低レベルBM_LOG_INFO)で動く */
void bm_log_init(void);

/* fprintf(stderr, fmt, ...)相当。bm_log_initの判定に従い、先頭に"[YYYY-MM-DD HH:MM:SS] "
 * を付けるかどうかが変わり、さらに"[DEBUG]"/"[INFO]"/"[WARN]"/"[ERROR]"のレベルタグが
 * 付く。levelが現在の最低レベル未満なら出力しない。fmt自体に改行を含めること(fprintfと
 * 同じ作法)。呼び出し側は直接使わず、下記のbm_log_debug/info/warn/errorマクロ経由で使う */
void bm_log_leveled(enum bm_log_level level, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#define bm_log_debug(...) bm_log_leveled(BM_LOG_DEBUG, __VA_ARGS__)
#define bm_log_info(...) bm_log_leveled(BM_LOG_INFO, __VA_ARGS__)
#define bm_log_warn(...) bm_log_leveled(BM_LOG_WARN, __VA_ARGS__)
#define bm_log_error(...) bm_log_leveled(BM_LOG_ERROR, __VA_ARGS__)

#endif /* BM_COMMON_LOGGING_H */
