/*
 * §11 2026-08-23: ログ行に時刻を付けるかどうかの自動判定(JOURNAL_STREAM/
 * BM_LOG_TIMESTAMPS)を確認する。stderrを一時ファイルへリダイレクトして出力内容を検証する。
 */

#include <pthread.h>
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

#define N_THREADS 8
#define N_ITERS 200

struct thread_arg
{
    int thread_id;
};

static void *worker(void *arg_ptr)
{
    struct thread_arg *a = arg_ptr;
    for (int i = 0; i < N_ITERS; i++)
    {
        bm_log("thread%d-iter%d\n", a->thread_id, i);
    }
    return NULL;
}

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

    /* --- 5. §11 2026-08-23発覚のバグ修正: マルチスレッドから同時にbm_logを呼んでも
     * 行が混ざらないことを確認する。以前は時刻部分と本文部分を別々のfprintf呼び出しに
     * 分けていたため、2回の呼び出しの間に別スレッドの出力が割り込み、
     * "[ts][ts] 片方のメッセージ"+"(時刻無し)もう片方のメッセージ"のように行が
     * 混ざることがあった(実daemonの運用中にユーザーが実際に観測して発覚)。 */
    {
        setenv("BM_LOG_TIMESTAMPS", "1", 1);
        unsetenv("JOURNAL_STREAM");
        bm_log_init();

        fflush(stderr);
        FILE *redirected = freopen(TEST_LOG_FILE, "w", stderr);
        CHECK(redirected != NULL, "redirecting stderr for the concurrency scenario should succeed");

        if (redirected != NULL)
        {
            struct thread_arg args[N_THREADS];
            pthread_t threads[N_THREADS];
            for (int t = 0; t < N_THREADS; t++)
            {
                args[t].thread_id = t;
                pthread_create(&threads[t], NULL, worker, &args[t]);
            }
            for (int t = 0; t < N_THREADS; t++)
            {
                pthread_join(threads[t], NULL);
            }
            fflush(stderr);

            FILE *f = fopen(TEST_LOG_FILE, "r");
            CHECK(f != NULL, "reopening the concurrency scenario log file should succeed");
            if (f != NULL)
            {
                int seen[N_THREADS][N_ITERS];
                memset(seen, 0, sizeof(seen));
                int line_count = 0;
                int malformed = 0;
                char line[512];
                while (fgets(line, sizeof(line), f) != NULL)
                {
                    line_count++;
                    const char *close_bracket = strstr(line, "] ");
                    int tid = -1, iter = -1;
                    if (line[0] != '[' || close_bracket == NULL
                        || sscanf(close_bracket + 2, "thread%d-iter%d", &tid, &iter) != 2
                        || tid < 0 || tid >= N_THREADS || iter < 0 || iter >= N_ITERS)
                    {
                        malformed++;
                        continue;
                    }
                    seen[tid][iter]++;
                }
                fclose(f);

                CHECK(line_count == N_THREADS * N_ITERS,
                      "the total line count should exactly match what all threads wrote (no merged/split lines)");
                CHECK(malformed == 0, "every line should be well-formed: '[timestamp] threadN-iterM'");

                int missing_or_duplicated = 0;
                for (int t = 0; t < N_THREADS; t++)
                {
                    for (int i = 0; i < N_ITERS; i++)
                    {
                        if (seen[t][i] != 1)
                        {
                            missing_or_duplicated++;
                        }
                    }
                }
                CHECK(missing_or_duplicated == 0,
                      "every (thread, iteration) message should appear exactly once, intact");
            }
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
