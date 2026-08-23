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
    if (g_include_timestamp)
    {
        time_t now = time(NULL);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
        fprintf(stderr, "[%s] ", ts);
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
