#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 既定は「時刻を付ける」(手動nohup運用で困らない安全側のデフォルト)。
 * bm_log_initが呼ばれない場合(テスト実行等)もこのままで動く。 */
static int g_include_timestamp = 1;

void bm_log_init(void)
{
    const char *override_env = getenv("BM_LOG_TIMESTAMPS");
    if (override_env != NULL)
    {
        g_include_timestamp = (strcmp(override_env, "0") != 0);
        return;
    }
    /* systemdはjournald接続のstdout/stderrに対してJOURNAL_STREAMをセットする。
     * 設定済みならjournaldが受信時刻を別途正確に記録するため、こちらでは付けない */
    g_include_timestamp = (getenv("JOURNAL_STREAM") == NULL);
}

void bm_log(const char *fmt, ...)
{
    /* §11 2026-08-23発覚のバグ修正: 以前は時刻部分と本文部分を別々のfprintf呼び出しで
     * 書いていたため、bitmessagedはマルチスレッド(object_sync/peer_connector/network等)
     * であることと相まって、2回の呼び出しの間に別スレッドの出力が割り込み、
     * "[ts][ts] 片方のメッセージ" + "(時刻無し)もう片方のメッセージ"のように行が
     * 混ざってしまうことがあった(実際にユーザーがログで観測して発覚)。
     * stdioの各呼び出し自体はストリームごとの内部ロックでスレッドセーフだが、
     * 「呼び出しをまたいだ」順序は保証されない。ここではvsnprintfで本文を一旦バッファへ
     * 組み立ててから、時刻込みで単一のfprintf呼び出しにまとめることで、1行分の出力が
     * 他スレッドの出力と混ざらないようにする。 */
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (g_include_timestamp)
    {
        time_t now = time(NULL);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
        fprintf(stderr, "[%s] %s", ts, msg);
    }
    else
    {
        fputs(msg, stderr);
    }
}
