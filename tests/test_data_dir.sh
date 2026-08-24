#!/usr/bin/env bash
# §11 2026-08-24 backlog項目10の2/5: BM_DATA_DIR環境変数でDBファイル置き場を
# CWDから明示的なディレクトリへ切り替えられることを確認する統合テスト。
# 未設定時の既定動作(CWD、既存ユーザー・既存daemon Aへの影響ゼロ)がここでは崩れて
# いないことも別途確認する。

set -euo pipefail

BITMESSAGED="$1"

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

DB_NAMES="peers.db object_pool.db identity.db messages.db config.db"

# --- 1. BM_DATA_DIRを明示指定した場合: 指定先にのみDBファイルが作られ、CWD直下には
#     何も作られないことを確認する --- */
mkdir -p data
BM_NO_CONNECT=1 BM_API_PORT=18446 BM_DATA_DIR="$WORKDIR/data" "$BITMESSAGED" >bitmessaged.log 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    if grep -q "DB初期化完了" bitmessaged.log 2>/dev/null; then
        break
    fi
    sleep 0.1
done
grep -q "DB初期化完了" bitmessaged.log || fail "daemon did not report DB init within timeout"
grep -q "data_dir=$WORKDIR/data" bitmessaged.log || fail "daemon did not log the expected data_dir"

for name in $DB_NAMES; do
    [ -f "data/$name" ] || fail "expected $name to exist under BM_DATA_DIR (data/), it does not"
    [ -f "$name" ] && fail "$name leaked into CWD even though BM_DATA_DIR was set"
done

kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""

# --- 2. BM_DATA_DIR未設定の場合: 既定値は従来通りCWD(既存挙動を壊していないことの確認) --- */
rm -f bitmessaged.log
BM_NO_CONNECT=1 BM_API_PORT=18447 "$BITMESSAGED" >bitmessaged.log 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    if grep -q "DB初期化完了" bitmessaged.log 2>/dev/null; then
        break
    fi
    sleep 0.1
done
grep -q "(data_dir=.)" bitmessaged.log || fail "daemon did not default data_dir to '.' when BM_DATA_DIR is unset"

for name in $DB_NAMES; do
    [ -f "$name" ] || fail "expected $name to exist directly under CWD when BM_DATA_DIR is unset, it does not"
done

kill -INT "$PID"
wait "$PID" 2>/dev/null || true
PID=""

echo "ALL OK"
