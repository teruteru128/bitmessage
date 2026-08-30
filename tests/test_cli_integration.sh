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

# §11 2026-08-27発覚: bitmessagedは以前argvを一切見ずに常時daemon化していたため、
# `bitmessaged --version`のつもりの誤操作がそのまま通常起動してしまい、既存daemon Aと
# 同じポート/DBファイルへ二重に触れる事故が実際に起きた(経緯はDESIGN-LOG.md参照)。
# daemon起動より前に、--version/--helpがその場でexitしdaemon化しないことを確認する。
[[ "$("$BITMESSAGED" --version)" == "bitmessaged "* ]] || fail "bitmessaged --version should print a version string"
"$BITMESSAGED" --help >/dev/null || fail "bitmessaged --help should exit successfully"
[[ "$("$CLI" --version)" == "bitmessage-cli "* ]] || fail "bitmessage-cli --version should print a version string"
"$CLI" --help >/dev/null || fail "bitmessage-cli --help should exit successfully"

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
# (§11 2026-08-30 toPubEncryptionHexの直接指定はsendMessageの引数から廃止したため、宛先の鍵は
#  常にpubkey_cache経由で解決する。成功パスはtests/test_api_server.cでカバーする。ここでは
#  CLI→API→エラー応答→CLI表示までの配線を検証する)
ADDR2_JSON=$("$CLI" create-address "cli send-message test" 4 1 1 "sender2" "storepass2")
ADDR2=$(echo "$ADDR2_JSON" | tr -d '"')
[ "$("$CLI" unlock "$ADDR2" "storepass2")" = "true" ] || fail "unlock sender2 for send-message test"

ADDR2B_JSON=$("$CLI" create-address "cli send-message test recv" 4 1 1 "recv2b" "storepass2b")
ADDR2B=$(echo "$ADDR2B_JSON" | tr -d '"')

SEND_UNCACHED_OUTPUT=$("$CLI" send-message "$ADDR2" "$ADDR2B" "subj" "body" 2>&1 || true)
echo "$SEND_UNCACHED_OUTPUT" | grep -q "エラー" \
    || fail "send-message to an address with no cached pubkey should fail with an error (got: $SEND_UNCACHED_OUTPUT)"

"$CLI" delete "$ADDR2" >/dev/null
"$CLI" delete "$ADDR2B" >/dev/null

# cache-pubkey: 引数検証を確認する。
CACHE_USAGE_OUTPUT=$("$CLI" cache-pubkey "onlyoneparam" 2>&1 || true)
echo "$CACHE_USAGE_OUTPUT" | grep -q "使い方" \
    || fail "cache-pubkey with wrong arg count should print usage (got: $CACHE_USAGE_OUTPUT)"

ADDR4_JSON=$("$CLI" create-address "cli cache-pubkey test receiver" 4 1 1 "recv4" "storepass4")
ADDR4=$(echo "$ADDR4_JSON" | tr -d '"')

# create-addressはpubkeyを返さないため、cache-pubkeyの成功パス自体はtests/test_api_server.cで
# 既にカバーしている(cachePubkey + sendMessageのHTTPテスト)。ここではCLI引数の配線のみ確認する。
CACHE_BAD_HEX_OUTPUT=$("$CLI" cache-pubkey "$ADDR4" "abcd" "abcd" 2>&1 || true)
echo "$CACHE_BAD_HEX_OUTPUT" | grep -q "エラー" \
    || fail "cache-pubkey with invalid hex should report an error (got: $CACHE_BAD_HEX_OUTPUT)"

"$CLI" delete "$ADDR4" >/dev/null

# §11 2026-08-29 export-address/import-address/import-keys-dat/address-book: keys.dat
# インポート機能一式のCLI配線を確認する(成功パスの詳細検証はtests/test_api_server.cで
# カバー済みなので、ここではCLI→API→ファイルI/Oの配線のみ)。
ADDR5_JSON=$("$CLI" create-address "cli export/import test" 4 1 1 "sender5" "storepass5")
ADDR5=$(echo "$ADDR5_JSON" | tr -d '"')
[ "$("$CLI" unlock "$ADDR5" "storepass5")" = "true" ] || fail "unlock sender5 for export/import test"

EXPORT_JSON=$("$CLI" export-address "$ADDR5" "storepass5")
SIGNING_WIF=$(echo "$EXPORT_JSON" | grep -oP '"signingWIF":"\K[^"]+')
ENCRYPTION_WIF=$(echo "$EXPORT_JSON" | grep -oP '"encryptionWIF":"\K[^"]+')
[ -n "$SIGNING_WIF" ] && [ -n "$ENCRYPTION_WIF" ] || fail "export-address should return signingWIF/encryptionWIF (got: $EXPORT_JSON)"

EXPORT_WRONG_OUTPUT=$("$CLI" export-address "$ADDR5" "wrongpass" 2>&1 || true)
echo "$EXPORT_WRONG_OUTPUT" | grep -q "エラー" \
    || fail "export-address with wrong passphrase should fail with an error (got: $EXPORT_WRONG_OUTPUT)"

"$CLI" delete "$ADDR5" >/dev/null

# import-address: exportで取り出したWIFで再インポートし、新しいpassphraseでunlockできること
[ "$("$CLI" import-address "$ADDR5" "$SIGNING_WIF" "$ENCRYPTION_WIF" "reimported" "newpass5")" = "true" ] \
    || fail "import-address should succeed with the exported WIFs"
[ "$("$CLI" unlock "$ADDR5" "newpass5")" = "true" ] || fail "unlock after import-address should succeed"
"$CLI" delete "$ADDR5" >/dev/null

# import-keys-dat: PyBitmessage本家keys.dat形式(INI)のファイルを丸ごとインポートする
cat > test_keys.dat <<EOF
[bitmessagesettings]
port = 8444

[$ADDR5]
label = reimported via keys.dat
enabled = true
noncetrialsperbyte = 1000
payloadlengthextrabytes = 1000
privsigningkey = $SIGNING_WIF
privencryptionkey = $ENCRYPTION_WIF
EOF

# §7.4のvault方式ではimportAddressは共有vaultへ保存するため、最初のimport-address
# (上記、"newpass5")でvaultのpassphraseが確定している。以後のimport-keys-datも同じ
# passphraseでないとvault canary検証に落ちて失敗する(誤ったmaster KEKでの保存を防ぐ
# ための意図した挙動、DESIGN.md §7.4参照)ため、ここでも"newpass5"を使う。
IMPORT_KEYS_DAT_OUTPUT=$("$CLI" import-keys-dat test_keys.dat "newpass5")
echo "$IMPORT_KEYS_DAT_OUTPUT" | grep -q "成功1件, 失敗0件" \
    || fail "import-keys-dat should report 1 success (got: $IMPORT_KEYS_DAT_OUTPUT)"
[ "$("$CLI" unlock "$ADDR5" "newpass5")" = "true" ] || fail "unlock after import-keys-dat should succeed"

# import-keys-datの"chan = true"キー(§11 chan仕様)がisChanとして再現されること
LIST_AFTER_IMPORT=$("$CLI" list-addresses)
echo "$LIST_AFTER_IMPORT" | grep -q "\"isChan\":false" \
    || fail "non-chan entry should have isChan:false (got: $LIST_AFTER_IMPORT)"
"$CLI" delete "$ADDR5" >/dev/null

cat > test_keys_chan.dat <<EOF
[$ADDR5]
label = reimported chan via keys.dat
enabled = true
chan = true
noncetrialsperbyte = 1000
payloadlengthextrabytes = 1000
privsigningkey = $SIGNING_WIF
privencryptionkey = $ENCRYPTION_WIF
EOF

IMPORT_CHAN_OUTPUT=$("$CLI" import-keys-dat test_keys_chan.dat "newpass5")
echo "$IMPORT_CHAN_OUTPUT" | grep -q "成功1件, 失敗0件" \
    || fail "import-keys-dat (chan) should report 1 success (got: $IMPORT_CHAN_OUTPUT)"
LIST_AFTER_CHAN_IMPORT=$("$CLI" list-addresses)
echo "$LIST_AFTER_CHAN_IMPORT" | grep -q "\"isChan\":true" \
    || fail "chan = true entry should be imported with isChan:true (got: $LIST_AFTER_CHAN_IMPORT)"

# §11 2026-08-29 set-label/fix-labels-from-keys-dat: keys.datインポート時のUTF-8文字化け
# バグ修正後、既存アドレスのラベルを後から修正する手段のCLI配線を確認する。
[ "$("$CLI" set-label "$ADDR5" "手動ラベル")" = "true" ] || fail "set-label should return true"
LIST_AFTER_SET_LABEL=$("$CLI" list-addresses)
echo "$LIST_AFTER_SET_LABEL" | grep -q "手動ラベル" \
    || fail "set-label should update the label (got: $LIST_AFTER_SET_LABEL)"

cat > test_keys_fixlabel.dat <<EOF
[$ADDR5]
label = 修正後ラベル
privsigningkey = $SIGNING_WIF
privencryptionkey = $ENCRYPTION_WIF
EOF
FIX_LABEL_OUTPUT=$("$CLI" fix-labels-from-keys-dat test_keys_fixlabel.dat)
echo "$FIX_LABEL_OUTPUT" | grep -q "成功1件, 失敗0件" \
    || fail "fix-labels-from-keys-dat should report 1 success (got: $FIX_LABEL_OUTPUT)"
LIST_AFTER_FIX_LABEL=$("$CLI" list-addresses)
echo "$LIST_AFTER_FIX_LABEL" | grep -q "修正後ラベル" \
    || fail "fix-labels-from-keys-dat should update the label (got: $LIST_AFTER_FIX_LABEL)"

SET_LABEL_UNKNOWN_OUTPUT=$("$CLI" set-label "BM-2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK" "x" 2>&1 || true)
echo "$SET_LABEL_UNKNOWN_OUTPUT" | grep -q "エラー" \
    || fail "set-label on unknown address should fail with an error (got: $SET_LABEL_UNKNOWN_OUTPUT)"

"$CLI" delete "$ADDR5" >/dev/null

# アドレス帳(address_book) CRUD
[ "$("$CLI" list-address-book-entries)" = "[]" ] || fail "initial address book should be empty"
"$CLI" add-address-book-entry "$ADDR5" "book friend" >/dev/null
LIST_AB=$("$CLI" list-address-book-entries)
echo "$LIST_AB" | grep -q "\"address\":\"$ADDR5\"" || fail "address book should contain $ADDR5 (got: $LIST_AB)"

DUP_AB_OUTPUT=$("$CLI" add-address-book-entry "$ADDR5" "dup" 2>&1 || true)
echo "$DUP_AB_OUTPUT" | grep -q "エラー" \
    || fail "adding a duplicate address book entry should fail with an error (got: $DUP_AB_OUTPUT)"

"$CLI" delete-address-book-entry "$ADDR5" >/dev/null
[ "$("$CLI" list-address-book-entries)" = "[]" ] || fail "address book should be empty after delete"

echo "ALL OK"
