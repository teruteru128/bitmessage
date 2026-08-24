# CLAUDE.md

このリポジトリで作業するAIエージェント向けの最小限の指示。プロジェクトの経緯・設計判断・
未解決事項の全体像は [DESIGN.md](DESIGN.md)(特に§11「次にやること」)を参照すること。
本ファイルは「毎回のセッションで機械的に守るべきこと」だけに絞る。

## Build

```
cmake -S . -B build-Debug -DCMAKE_BUILD_TYPE=Debug   # build-Debugが無い初回のみ
cmake --build build-Debug --parallel
```

`build-Debug`がこのプロジェクトでのローカル開発時の既定ディレクトリ名(CIは別途`build`を使うが、
ローカルでは`build-Debug`に統一している)。

## Test

```
cd build-Debug && ctest --output-on-failure
```

**必ず全件(現在38件)が100%通過することを確認してから完了とすること。** 1件でも失敗した状態で
「実装できました」と報告しない。特定のテストだけ再実行する場合:

```
ctest -R <test_name> --output-on-failure   # 例: ctest -R object_sync
```

新機能を追加したら対応するテストを`tests/`に必ず追加し、`tests/CMakeLists.txt`へ登録すること
(既存のテストファイルの冒頭コメントが背景・検証観点を書く慣習になっているので倣うこと)。

## Lint

専用のlinter/formatterは導入していない。`-Wall -Wextra`(`CMakeLists.txt`)が実質的なlintで、
**ビルド時に警告が1件でも出たら直すこと**。フォーマットはAllmanスタイル(関数・制御構文とも
開き波括弧を次の行に置く)・4スペースインデントで統一されている。既存コードを目視して合わせる。

## コードスタイルで特に重視すること

- **時刻は必ず`int64_t now`等の明示引数で受け取り、関数内部で`time(NULL)`を直接呼ばない。**
  テストが実際の壁時計待ち無しで決定的に検証できるようにするため(`bm_peer_manager_cleanup`,
  `bm_dandelion_maybe_reshuffle`, `bm_object_sync_maybe_reannounce_onion_peer`等、全て同じ形)。
- **周期的なメンテナンス処理のために専用スレッドを新設しない。** 既存の`peer_connector_thread`の
  1秒間隔ポーリングループに相乗りさせる(Dandelion++のreshuffle/expire、onionpeer再announceが
  この方針で実装済み)。内部で「前回実行からN秒経過したか」を判定して間引くので、1秒ごとに
  呼んでも軽い。
- **PyBitmessage本家との一致・不一致は必ず実ソースを確認してから判断する。** ローカルに参照用
  クローンがあれば(`/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`、無い場合は
  ユーザーに確認)、`network/`以下のワイヤーフォーマット・タイムアウト値・rating更新ロジック等を
  該当ファイルで直接確認し、一致させる場合もあえて逸脱する場合も、その根拠をコメントと
  DESIGN.mdの両方に残す。「本家もこうだから」という推測だけで実装しない。
- **コメントは「なぜ」を書く。** このプロジェクトは日本語コメントで、変更の根拠(発覚した
  バグ・ユーザーとの議論・PyBitmessage本家との比較結果・既知のトレードオフ)を`/* §11
  YYYY-MM-DD ... */`の形でDESIGN.mdの節番号+日付とセットで残す慣習が徹底されている。一般的な
  「自明なら書かない」原則より、この「変更履歴が埋め込まれたコード」を優先すること。
- **DBスキーマへの列追加は`CREATE TABLE IF NOT EXISTS`を変更するだけでなく、`ALTER TABLE ...
  ADD COLUMN ... DEFAULT ...`を`init_schema`内に追記し、エラー(既存カラムとの重複)は無視する。**
  既に稼働中のDBファイルに新しい列を反映するための必須パターン(`is_self`, `last_attempt`等)。
- 新しいstruct/ctxフィールドが「単一スレッドからのみ触られる前提で排他制御をしない」場合は、
  必ずそれをコメントで明記する(`last_gc`, `last_onion_announce`等)。sqlite3ハンドルは
  `SQLITE_OPEN_FULLMUTEX`(`common/db_common.c`)でスレッド間共有が安全な前提。

## 作業の流れ(このプロジェクトで確立された標準サイクル)

1. 実装
2. `cmake --build build-Debug --parallel`(警告ゼロ)
3. `ctest --output-on-failure`(100%通過)
4. `DESIGN.md`の該当節(通常は§11、無ければ該当章)へ日本語で経緯・根拠を追記
5. `git commit`(日本語メッセージ、末尾に`Co-Authored-By: Claude Sonnet 5
   <noreply@anthropic.com>`)。コミットメッセージが長い/特殊文字を含む場合はheredocを避け、
   Writeツールで一時ファイルに書いてから`git commit -F <file>`する
6. `git push origin master`は実行前にユーザーへ確認する
7. **本番daemon(daemon A)の再起動は、push後であっても必ずユーザーに確認してから行う。**
   自動では絶対に再起動しない

## 安全に関する厳守事項

- **ユーザーの実onionアドレスを、公開/git管理下のいかなるファイル(コード・コメント・
  コミットメッセージ・テストフィクスチャ)にも書かない。** 一時的な表示が必要な場合は
  `sed -E 's/[a-z2-7]{16,60}\.onion/<redacted>.onion/g'`等で必ずマスクしてから出力する。
- **複数の`bitmessaged`プロセスが同時に存在しうるため、`pkill -f`のようなパターン一致での
  強制終了は絶対に使わない。** 必ず`pgrep -fa "build-Debug/src/bitmessaged$"`で実PIDを特定し、
  `kill <PID>`で個別に終了する。
- **`/var/lib/tor/`以下のパーミッション・所有者・ACLを一切変更しない。** 過去に`setfacl`で
  稼働中のTorサービスをクラッシュさせた実績あり。onionアドレスの取得は`bitmessage.conf`の
  `[tor] onion_address`(または`BM_ONION_ADDRESS`)経由で行い、Tor管理ファイルを直接読みに
  行く必要が生じたら、まずユーザーに相談する。
- git: force-pushは`--force-with-lease`+ユーザーの明示承認がある場合のみ。基本は新規commitを
  積む(`--amend`はユーザーが明示的に要求した場合のみ)。
