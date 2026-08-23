/*
 * §11 2026-08-23: ログ行に時刻を付けるかどうかの自動判定(JOURNAL_STREAM/
 * BM_LOG_TIMESTAMPS)を確認する。stderrを一時ファイルへリダイレクトして出力内容を検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/common/logging.h"

#define TEST_LOG_FILE "test_logging_stderr.txt"

static int failures = 0;

#define CHECK(cond, msg)                                                    \
    do                                                                      \
    {                                                                       \
        if (!(cond))                                                        \
        {                                                                   \
            fprintf(stdout, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

/* stderrを一時ファイルへ切り替えてbm_logを1回呼び、書き込まれた内容を返す(呼び出し側でfree) */
static char *capture_one_log_line(void)
{
    fflush(stderr);
    FILE *redirected = freopen(TEST_LOG_FILE, "w", stderr);
    if (redirected == NULL)
    {
        return NULL;
    }
    bm_log("hello world\n");
    fflush(stderr);

    FILE *f = fopen(TEST_LOG_FILE, "r");
    if (f == NULL)
    {
        return NULL;
    }
    char *buf = malloc(256);
    size_t n = fread(buf, 1, 255, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

int main(void)
{
    /* stdoutはCHECKマクロで使うため、テスト全体を通してstderrだけをリダイレクトする。
     * 元のstderrへは戻さない(プロセス終了まで使わないため問題ない) */

    /* --- 1. BM_LOG_TIMESTAMPS=0を明示指定すると、時刻を付けない --- */
    {
        setenv("BM_LOG_TIMESTAMPS", "0", 1);
        unsetenv("JOURNAL_STREAM");
        bm_log_init();
        char *line = capture_one_log_line();
        CHECK(line != NULL, "capturing a log line should succeed");
        if (line != NULL)
        {
            CHECK(strcmp(line, "hello world\n") == 0,
                  "BM_LOG_TIMESTAMPS=0 should produce output with no timestamp prefix");
            free(line);
        }
    }

    /* --- 2. BM_LOG_TIMESTAMPS=1を明示指定すると、"[YYYY-MM-DD HH:MM:SS] "が先頭に付く --- */
    {
        setenv("BM_LOG_TIMESTAMPS", "1", 1);
        bm_log_init();
        char *line = capture_one_log_line();
        CHECK(line != NULL, "capturing a log line should succeed");
        if (line != NULL)
        {
            CHECK(strlen(line) > strlen("hello world\n"), "a timestamp prefix should add extra bytes");
            CHECK(line[0] == '[', "the timestamp prefix should start with '['");
            const char *suffix = strstr(line, "] hello world\n");
            CHECK(suffix != NULL, "the original message should still follow the timestamp prefix intact");
            free(line);
        }
    }

    /* --- 3. JOURNAL_STREAMが設定されていて、BM_LOG_TIMESTAMPSが未指定なら、
     * systemd/journald配下と判定して時刻を付けない --- */
    {
        unsetenv("BM_LOG_TIMESTAMPS");
        setenv("JOURNAL_STREAM", "8:1234", 1);
        bm_log_init();
        char *line = capture_one_log_line();
        CHECK(line != NULL, "capturing a log line should succeed");
        if (line != NULL)
        {
            CHECK(strcmp(line, "hello world\n") == 0,
                  "under JOURNAL_STREAM (systemd/journald), no timestamp prefix should be added");
            free(line);
        }
        unsetenv("JOURNAL_STREAM");
    }

    /* --- 4. どちらも未設定なら、既定(手動起動想定)で時刻を付ける --- */
    {
        unsetenv("BM_LOG_TIMESTAMPS");
        unsetenv("JOURNAL_STREAM");
        bm_log_init();
        char *line = capture_one_log_line();
        CHECK(line != NULL, "capturing a log line should succeed");
        if (line != NULL)
        {
            CHECK(line[0] == '[', "with neither env var set, the safe default should add a timestamp prefix");
            free(line);
        }
    }

    unlink(TEST_LOG_FILE);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    printf("%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
