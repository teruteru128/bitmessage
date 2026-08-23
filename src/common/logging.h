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
 */

/* 起動時に1回だけ呼ぶ(main()の先頭付近を想定)。呼ばなくても既定(時刻を付ける)で動く */
void bm_log_init(void);

/* fprintf(stderr, fmt, ...)相当。bm_log_initの判定に従い、先頭に"[YYYY-MM-DD HH:MM:SS] "を
 * 付けるかどうかが変わる。fmt自体に改行を含めること(fprintfと同じ作法) */
void bm_log(const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#endif /* BM_COMMON_LOGGING_H */
