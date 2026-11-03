#ifndef BM_CLI_I18N_H
#define BM_CLI_I18N_H

/*
 * §11 2026-11-03 項目54(国際化): bitmessage-cliのメッセージ翻訳(gettext)。
 *
 * ソース上の文字列(msgid)は英語で書き、_()で囲む。訳はpo/<lang>.po(現在はja.poのみ)に
 * 置き、ビルド時にmsgfmtで.moへ変換する。daemon(bitmessaged)側は翻訳しない方針なので
 * (DESIGN.md §11項目54)、このヘッダはsrc/cli/の中からだけincludeする。
 *
 * N_()は「翻訳対象としてxgettextに拾わせるが、その場では翻訳しない」印。静的な表
 * (main.cのコマンド一覧)のように、初期化時点ではまだロケールが決まっていない場所で使い、
 * 実際に表示するときに_()を通す。
 *
 * BM_ENABLE_NLSが未定義(CMakeでBM_ENABLE_NLS=OFF、またはlibintl/msgfmtが見つからない
 * 環境)なら_()は素通しになり、常に英語で表示される。
 */

#ifdef BM_ENABLE_NLS
#include <libintl.h>
#define _(s) gettext(s)
#else
#define _(s) (s)
#endif

#define N_(s) (s)

/* gettextのテキストドメイン名。po/CMakeLists.txt(.moのファイル名)と一致させること */
#define BM_TEXTDOMAIN "bitmessage"

/* setlocale・bindtextdomain・textdomainをまとめて行う。main()の先頭で1回だけ呼ぶ */
void bm_cli_i18n_init(void);

#endif
