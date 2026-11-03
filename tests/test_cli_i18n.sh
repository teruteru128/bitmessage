#!/usr/bin/env bash
# §11 2026-11-03 項目54(国際化): bitmessage-cliの表示言語の切り替えを検証する。
# daemonを起動しない(--help・引数エラー・接続失敗だけで、訳の選択と書式の埋め込みを
# 一通り確かめられるため)。
#
# 検証観点:
#  (1) LC_ALL=Cでは英語(msgid)のまま表示される。既存のtest_cli_integration.shはこの前提で
#      英語のメッセージをgrepしている
#  (2) 日本語ロケールでは、ビルドツリーの訳(実行ファイルの隣のlocale/、i18n.c参照)が
#      見つかって日本語で表示される。usageのコマンド説明(N_()で印を付けた静的な表を
#      表示時に訳すもの)も訳される
#  (3) 引数入りのメッセージで、訳文側の書式に値が正しく埋め込まれる(接続失敗の
#      host:port、IPv6の[]付き)
#  (4) BM_LOCALEDIRで訳の置き場所を上書きでき、訳が無ければ英語に戻る
#
# 日本語ロケール(ja_JP.UTF-8)が無い環境では(2)〜(4)を確かめられないのでskipする
# (終了コード77、tests/CMakeLists.txtのSKIP_RETURN_CODE)。C.UTF-8+LANGUAGE=jaでは
# 代用できない: glibcはC.UTF-8もCロケールとして扱い、LANGUAGEを無視するため(実際に
# 試して英語のままだった)。CIではjaロケールを入れている(.github/workflows/ci.yml)。
#
# 使い方: test_cli_i18n.sh <bitmessage-cli>
set -euo pipefail

CLI="$1"

fail() { echo "FAIL: $*" >&2; exit 1; }

# 他の環境変数(利用者のLANGUAGE=ja:en等)に結果を左右されないよう、毎回明示して呼ぶ
run_c() { env -u LANGUAGE LC_ALL=C "$@"; }

# --- (1) Cロケールでは英語 ---
HELP_C=$(run_c "$CLI" --help 2>&1)
echo "$HELP_C" | grep -q '^Usage: ' || fail "C locale --help should be English (got: $HELP_C)"
echo "$HELP_C" | grep -q '^Commands:' || fail "C locale --help should list commands"
# 訳が混ざっていない(非ASCIIのバイトが無い)こと
if LC_ALL=C grep -q '[^ -~]' <<<"$HELP_C"; then
    fail "C locale --help should be ASCII only"
fi

# --- (2)以降は日本語ロケールが要る ---
if ! locale -a 2>/dev/null | grep -qix 'ja_JP\.utf-\?8'; then
    echo "SKIP: ja_JP.UTF-8 locale is not available"
    exit 77
fi
run_ja() { env -u LANGUAGE -u BM_LOCALEDIR LC_ALL=ja_JP.UTF-8 "$@"; }

HELP_JA=$(run_ja "$CLI" --help 2>&1)
echo "$HELP_JA" | grep -q '^使い方: ' || fail "ja --help should be Japanese (got: $HELP_JA)"
echo "$HELP_JA" | grep -q '^コマンド:' || fail "ja --help should translate 'Commands:'"
# 静的な表(N_())の説明文も訳され、各行に字下げが付く
echo "$HELP_JA" | grep -q '^      onion peer(.onion宛)専用のoutbound SOCKS5プロキシ' \
    || fail "ja --help should translate command descriptions (got: $HELP_JA)"
# synopsisは翻訳しない
echo "$HELP_JA" | grep -q '^  unlock <address> <passphrase>$' || fail "synopsis should stay untranslated"

USAGE_JA=$(run_ja "$CLI" unlock 2>&1 || true)
[[ "$USAGE_JA" == *"使い方: "*" unlock <address> <passphrase>" ]] \
    || fail "per-command usage should be Japanese (got: $USAGE_JA)"

UNKNOWN_JA=$(run_ja "$CLI" no-such-command 2>&1 || true)
echo "$UNKNOWN_JA" | grep -q '^不明なコマンド: no-such-command$' \
    || fail "unknown command message should be Japanese (got: $UNKNOWN_JA)"

# --- (3) 書式への値の埋め込み。ポート1番には何も待ち受けていない前提 ---
CONN_JA=$(BM_API_HOST=127.0.0.1 BM_API_PORT=1 run_ja "$CLI" list-addresses 2>&1 || true)
[ "$CONN_JA" = "接続に失敗しました(127.0.0.1:1、bitmessagedは起動していますか?)" ] \
    || fail "connection error should embed host:port in the translation (got: $CONN_JA)"
CONN6_JA=$(BM_API_HOST=::1 BM_API_PORT=1 run_ja "$CLI" list-addresses 2>&1 || true)
[ "$CONN6_JA" = "接続に失敗しました([::1]:1、bitmessagedは起動していますか?)" ] \
    || fail "connection error should bracket IPv6 hosts (got: $CONN6_JA)"
CONN_C=$(BM_API_HOST=127.0.0.1 BM_API_PORT=1 run_c "$CLI" list-addresses 2>&1 || true)
[ "$CONN_C" = "Could not connect to 127.0.0.1:1 (is bitmessaged running?)" ] \
    || fail "connection error should be English in the C locale (got: $CONN_C)"

# --- (4) BM_LOCALEDIRの上書き。訳の無いディレクトリを指すと英語に戻る ---
EMPTY_DIR=$(mktemp -d)
trap 'rm -rf "$EMPTY_DIR"' EXIT
OVERRIDE=$(BM_LOCALEDIR="$EMPTY_DIR" env -u LANGUAGE LC_ALL=ja_JP.UTF-8 "$CLI" --help 2>&1)
echo "$OVERRIDE" | grep -q '^Usage: ' \
    || fail "BM_LOCALEDIR pointing to an empty dir should fall back to English (got: $OVERRIDE)"

echo "PASS: cli i18n"
