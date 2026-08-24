#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* 既定は「時刻を付ける」(手動nohup運用で困らない安全側のデフォルト)。
 * bm_log_initが呼ばれない場合(テスト実行等)もこのままで動く。 */
static int g_include_timestamp = 1;

/* §11 2026-08-24 backlog項目8: 既定の最低レベルはBM_LOG_INFO(DEBUGを抑制)。
 * bm_log_initが呼ばれない場合(テスト実行等)もこのままで動く。 */
static enum bm_log_level g_min_level = BM_LOG_INFO;

static const char *level_tag(enum bm_log_level level)
{
    switch (level)
    {
        case BM_LOG_DEBUG:
            return "DEBUG";
        case BM_LOG_INFO:
            return "INFO";
        case BM_LOG_WARN:
            return "WARN";
        case BM_LOG_ERROR:
            return "ERROR";
        default:
            return "?";
    }
}

/* BM_LOG_LEVELの値を解釈する。認識できない値の場合は*outを書き換えずに返し、
 * 呼び出し元(bm_log_init)が既定値(BM_LOG_INFO)のまま使うようにする
 * (誤った値でログが完全に沈黙する事故を避けるため、安全側に倒す)。 */
static int parse_log_level(const char *s, enum bm_log_level *out)
{
    if (strcasecmp(s, "DEBUG") == 0)
    {
        *out = BM_LOG_DEBUG;
        return 0;
    }
    if (strcasecmp(s, "INFO") == 0)
    {
        *out = BM_LOG_INFO;
        return 0;
    }
    if (strcasecmp(s, "WARN") == 0 || strcasecmp(s, "WARNING") == 0)
    {
        *out = BM_LOG_WARN;
        return 0;
    }
    if (strcasecmp(s, "ERROR") == 0)
    {
        *out = BM_LOG_ERROR;
        return 0;
    }
    return -1;
}

void bm_log_init(void)
{
    const char *override_env = getenv("BM_LOG_TIMESTAMPS");
    if (override_env != NULL)
    {
        g_include_timestamp = (strcmp(override_env, "0") != 0);
    }
    else
    {
        /* systemdはjournald接続のstdout/stderrに対してJOURNAL_STREAMをセットする。
         * 設定済みならjournaldが受信時刻を別途正確に記録するため、こちらでは付けない */
        g_include_timestamp = (getenv("JOURNAL_STREAM") == NULL);
    }

    /* g_min_levelは呼び出しのたびに既定値(BM_LOG_INFO)へ明示的に戻してから、
     * 環境変数が有効な値であれば上書きする。「未指定/不正値なら前回の値のまま
     * 変更しない」という仕様だと、bm_log_initを複数回呼ぶテストで前のテストケースの
     * 設定を引きずってしまい非決定的になる(実運用ではmain()の起動時に1回しか
     * 呼ばないため問題にならないが、テストでの再現性のため単純に決定的な仕様にした)。 */
    g_min_level = BM_LOG_INFO;
    const char *level_env = getenv("BM_LOG_LEVEL");
    if (level_env != NULL)
    {
        enum bm_log_level parsed;
        if (parse_log_level(level_env, &parsed) == 0)
        {
            g_min_level = parsed;
        }
    }
}

void bm_log_leveled(enum bm_log_level level, const char *fmt, ...)
{
    if (level < g_min_level)
    {
        return;
    }

    /* §11 2026-08-23発覚のバグ修正: 以前は時刻部分と本文部分を別々のfprintf呼び出しで
     * 書いていたため、bitmessagedはマルチスレッド(object_sync/peer_connector/network等)
     * であることと相まって、2回の呼び出しの間に別スレッドの出力が割り込み、
     * "[ts][ts] 片方のメッセージ" + "(時刻無し)もう片方のメッセージ"のように行が
     * 混ざってしまうことがあった(実際にユーザーがログで観測して発覚)。
     * stdioの各呼び出し自体はストリームごとの内部ロックでスレッドセーフだが、
     * 「呼び出しをまたいだ」順序は保証されない。ここではvsnprintfで本文を一旦バッファへ
     * 組み立ててから、時刻・レベルタグ込みで単一のfprintf呼び出しにまとめることで、
     * 1行分の出力が他スレッドの出力と混ざらないようにする。 */
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
        fprintf(stderr, "[%s] [%s] %s", ts, level_tag(level), msg);
    }
    else
    {
        fprintf(stderr, "[%s] %s", level_tag(level), msg);
    }
}
