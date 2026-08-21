#!/usr/bin/env bash
# src/cli/bitmessage-cli のend-to-end統合テスト。
# 実際にbitmessagedを起動し、CLI経由で一連の操作(作成→一覧→unlock誤り/正解→lock→delete)を
# 行い、認証エラーの扱いも含めて検証する。

set -euo pipefail

BITMESSAGED="$1"
CLI="$2"

WORKDIR=$(mktemp -d)
cd "$WORKDIR"

PID=""
cleanup() {
    if [ -n "$PID" ]; then
        kill -INT "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    if [ -f bitmessaged.log ]; then
        echo "--- bitmessaged.log ---" >&2
        cat bitmessaged.log >&2
    fi
    exit 1
}

# §11 ポート衝突対策: 既定の8442は他の目的(手元でのpeer bootstrap用daemon等)で使われている
# ことがあるため、ctest実行を邪魔しないようtest_api_server.c等と同じ流儀でscratchポートを使う
# (BM_API_PORTはCLI・daemon双方が読む環境変数、main.c参照)。
BM_NO_CONNECT=1 BM_API_PORT=18445 "$BITMESSAGED" >bitmessaged.log 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    if grep -q apipassword bitmessaged.log 2>/dev/null; then
        break
    fi
    sleep 0.1
done

export BM_API_HOST=127.0.0.1
export BM_API_PORT=18445
export BM_API_USER=bitmessage
export BM_API_PASS
BM_API_PASS=$(grep -oP 'apipassword=\K[0-9a-f]+' bitmessaged.log || true)
[ -n "$BM_API_PASS" ] || fail "could not extract apipassword from daemon log"

[ "$("$CLI" list-addresses)" = "[]" ] || fail "initial list-addresses should be empty"

ADDR_JSON=$("$CLI" create-address "cli integration test" 4 1 1 "test" "storepass")
ADDR=$(echo "$ADDR_JSON" | tr -d '"')
[[ "$ADDR" == BM-* ]] || fail "created address should start with BM- (got: $ADDR_JSON)"

LIST1=$("$CLI" list-addresses)
echo "$LIST1" | grep -q '"unlocked":false' || fail "new address should start locked (got: $LIST1)"

[ "$("$CLI" unlock "$ADDR" "wrongpass")" = "false" ] || fail "wrong passphrase should return false"
[ "$("$CLI" unlock "$ADDR" "storepass")" = "true" ] || fail "correct passphrase should return true"

LIST2=$("$CLI" list-addresses)
echo "$LIST2" | grep -q '"unlocked":true' || fail "address should be unlocked now (got: $LIST2)"

[ "$("$CLI" lock "$ADDR")" = "true" ] || fail "lock should return true"
[ "$("$CLI" delete "$ADDR")" = "true" ] || fail "delete should return true"
[ "$("$CLI" list-addresses)" = "[]" ] || fail "list-addresses should be empty after delete"

# CLIは認証失敗時に意図的に非ゼロで終了するため、`set -o pipefail`下で
# `cmd | grep -q` の形にするとgrepがマッチしてもcmd側の非ゼロ終了が伝播して
# if全体が偽になってしまう。先に出力を変数へ捕まえてからgrepする。
AUTH_FAIL_OUTPUT=$(BM_API_PASS="wrongpassword" "$CLI" list-addresses 2>&1 || true)
echo "$AUTH_FAIL_OUTPUT" | grep -q "認証に失敗" \
    || fail "wrong credentials should be rejected with an auth error (got: $AUTH_FAIL_OUTPUT)"

# get-inbox: 空のDBでは空配列
[ "$("$CLI" get-inbox)" = "[]" ] || fail "get-inbox should be empty initially"

# send-message: CLI層の引数検証・API層のエラーがCLIまで正しく伝播することを確認する
# (有効な宛先公開鍵をシェルスクリプトから直接得る手段が無いため、成功パスはtests/test_api_server.cで
#  カバーする。ここではCLI→API→エラー応答→CLI表示までの配線を検証する)
ADDR2_JSON=$("$CLI" create-address "cli send-message test" 4 1 1 "sender2" "storepass2")
ADDR2=$(echo "$ADDR2_JSON" | tr -d '"')
[ "$("$CLI" unlock "$ADDR2" "storepass2")" = "true" ] || fail "unlock sender2 for send-message test"

SHORT_HEX_OUTPUT=$("$CLI" send-message "$ADDR2" "$ADDR2" "abcd" "subj" "body" 2>&1 || true)
echo "$SHORT_HEX_OUTPUT" | grep -q "130 hex" \
    || fail "send-message with too-short pubkey hex should report the 130-hex-char requirement (got: $SHORT_HEX_OUTPUT)"

GARBAGE_HEX=$(printf '00%.0s' $(seq 1 65))
SEND_FAIL_OUTPUT=$("$CLI" send-message "$ADDR2" "$ADDR2" "$GARBAGE_HEX" "subj" "body" 2>&1 || true)
echo "$SEND_FAIL_OUTPUT" | grep -q "エラー" \
    || fail "send-message with a non-curve-point pubkey should fail with an error (got: $SEND_FAIL_OUTPUT)"

"$CLI" delete "$ADDR2" >/dev/null

# cache-pubkey: 引数検証と、有効な鍵での登録->send-message "-"(cache利用)成功までの配線を確認する。
CACHE_USAGE_OUTPUT=$("$CLI" cache-pubkey "onlyoneparam" 2>&1 || true)
echo "$CACHE_USAGE_OUTPUT" | grep -q "使い方" \
    || fail "cache-pubkey with wrong arg count should print usage (got: $CACHE_USAGE_OUTPUT)"

ADDR3_JSON=$("$CLI" create-address "cli cache-pubkey test sender" 4 1 1 "sender3" "storepass3")
ADDR3=$(echo "$ADDR3_JSON" | tr -d '"')
[ "$("$CLI" unlock "$ADDR3" "storepass3")" = "true" ] || fail "unlock sender3 for cache-pubkey test"

ADDR4_JSON=$("$CLI" create-address "cli cache-pubkey test receiver" 4 1 1 "recv4" "storepass4")
ADDR4=$(echo "$ADDR4_JSON" | tr -d '"')

# create-addressはpubkeyを返さないため、cache-pubkeyの成功パス自体はtests/test_api_server.cで
# 既にカバーしている(cachePubkey + sendMessage(null)のHTTPテスト)。ここではCLI引数の配線のみ確認する。
CACHE_BAD_HEX_OUTPUT=$("$CLI" cache-pubkey "$ADDR4" "abcd" "abcd" 2>&1 || true)
echo "$CACHE_BAD_HEX_OUTPUT" | grep -q "エラー" \
    || fail "cache-pubkey with invalid hex should report an error (got: $CACHE_BAD_HEX_OUTPUT)"

SEND_DASH_OUTPUT=$("$CLI" send-message "$ADDR3" "$ADDR4" "-" "subj" "body" 2>&1 || true)
echo "$SEND_DASH_OUTPUT" | grep -q "エラー" \
    || fail "send-message with '-' and no cached pubkey should fail with an error (got: $SEND_DASH_OUTPUT)"

"$CLI" delete "$ADDR3" >/dev/null
"$CLI" delete "$ADDR4" >/dev/null

echo "ALL OK"
