#!/usr/bin/env bash
# §11 2026-11-03 項目54(国際化): 訳(po/*.po)がソースの文字列に追いついているかの検査。
#
# bitmessage-cliのメッセージを追加・変更したのに`cmake --build <dir> --target update-po`と
# 訳を忘れると、そのメッセージだけ黙って英語で表示される(gettextは訳が無ければmsgidを
# そのまま返すので、ビルドもテストも他には何も落ちない)。それを防ぐため、ソースから
# その場でxgettextしたテンプレートと突き合わせて次を確かめる。
#  (1) po/<lang>.poが、ソースの全msgidを訳済みで持っている(未訳・fuzzyはmsgcmpが
#      エラーにする)
#  (2) リポジトリのpo/bitmessage.pot(新しい言語を足すときの雛形)のmsgidが、ソースと
#      一致している(update-poのやり忘れ)
# 書式の食い違い(%dと%s等)はビルド時のmsgfmt --checkで別途弾いている
# (src/cli/CMakeLists.txt)。
#
# 使い方: test_po_up_to_date.sh <ソースツリー> <xgettext> <msgcmp>
set -euo pipefail

SRC="$1"
XGETTEXT="$2"
MSGCMP="$3"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# update-poターゲット(src/cli/CMakeLists.txt)と同じオプションで抜き出す
(cd "$SRC" && "$XGETTEXT" --language=C --from-code=UTF-8 --keyword=_ --keyword=N_ \
    --add-comments=TRANSLATORS: --add-location=file --sort-by-file \
    -o "$WORKDIR/current.pot" src/cli/main.c src/cli/i18n.c)

for po in "$SRC"/po/*.po; do
    "$MSGCMP" "$po" "$WORKDIR/current.pot" \
        || fail "$(basename "$po") is missing translations; run 'cmake --build <dir> --target update-po' and translate"
done

# --use-untranslated: potは訳を持たないので、未訳を「無い」と見なさないようにする。
# 両方向で比べ、ソースに増えた文字列も消えた文字列も検出する
"$MSGCMP" --use-untranslated "$SRC/po/bitmessage.pot" "$WORKDIR/current.pot" \
    || fail "po/bitmessage.pot lacks messages; run 'cmake --build <dir> --target update-po'"
"$MSGCMP" --use-untranslated "$WORKDIR/current.pot" "$SRC/po/bitmessage.pot" \
    || fail "po/bitmessage.pot has stale messages; run 'cmake --build <dir> --target update-po'"

echo "PASS: translations are up to date"
