/*
 * §11 2026-11-03 項目54(国際化): bitmessage-cliのgettext初期化。背景はi18n.h参照。
 */

#include "i18n.h"

#ifdef BM_ENABLE_NLS

#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * 実行ファイルと同じディレクトリにlocale/が有ればそのパスをbufへ書いて1を返す。
 *
 * ビルドツリー(build-Debug/src/cli/)では、.moをbitmessage-cliの隣のlocale/に置いている
 * (src/cli/CMakeLists.txt)。こうしておくと、インストールしていないbuild-*のCLIを
 * そのまま実行しても、テストから実行しても訳が出る(ビルドツリーの絶対パスを実行ファイルに
 * 埋め込まずに済む)。インストール先(/usr/local/bin等)の隣にlocale/は無いので、その場合は
 * 0を返し、呼び出し側がコンパイル時に決めたインストール先(BM_INSTALL_LOCALEDIR)を使う。
 * /proc/self/exeはLinux固有だが、本プロジェクトはepoll依存でそもそもLinux専用
 * (DESIGN.md §10)。
 */
static int find_exe_relative_localedir(char *buf, size_t buf_size)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0)
    {
        return 0;
    }
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash == NULL)
    {
        return 0;
    }
    *slash = '\0';

    static const char suffix[] = "/locale";
    if (strlen(exe) + sizeof(suffix) > buf_size)
    {
        return 0;
    }
    strcpy(buf, exe);
    strcat(buf, suffix);

    struct stat st;
    return stat(buf, &st) == 0 && S_ISDIR(st.st_mode);
}

void bm_cli_i18n_init(void)
{
    /* setlocale(LC_ALL, "")にしない理由: LC_NUMERICまで環境に合わせると、小数点が","の
     * ロケール(de_DE等)でcommon/json.cのstrtod/"%.17g"が"1,5"を読み書きするようになり、
     * daemonへ送るJSONが壊れる(引数の数値をパースするatof/strtodも同様)。訳の選択に要る
     * LC_MESSAGESと、訳(UTF-8)を端末の文字コードで出すためのLC_CTYPEだけを設定する。
     * LC_CTYPEがCのままだと、glibcのgettextは訳をASCIIへ変換しようとして"?"だらけにする。 */
    setlocale(LC_MESSAGES, "");
    setlocale(LC_CTYPE, "");

    /* 探す順: BM_LOCALEDIR環境変数(テストや手元で別の訳を試すとき用) → 実行ファイルの隣の
     * locale/(ビルドツリー) → インストール先 */
    const char *dir = getenv("BM_LOCALEDIR");
    char exe_relative[PATH_MAX];
    if (dir == NULL || dir[0] == '\0')
    {
        dir = find_exe_relative_localedir(exe_relative, sizeof(exe_relative)) ? exe_relative
                                                                               : BM_INSTALL_LOCALEDIR;
    }
    bindtextdomain(BM_TEXTDOMAIN, dir);
    textdomain(BM_TEXTDOMAIN);
}

#else

void bm_cli_i18n_init(void)
{
}

#endif
