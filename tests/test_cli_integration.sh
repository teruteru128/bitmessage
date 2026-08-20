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

"$BITMESSAGED" >bitmessaged.log 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    if grep -q apipassword bitmessaged.log 2>/dev/null; then
        break
    fi
    sleep 0.1
done

export BM_API_HOST=127.0.0.1
export BM_API_PORT=8442
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

echo "ALL OK"
