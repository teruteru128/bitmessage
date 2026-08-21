# bitmessage

Bitmessage P2Pメッセージングプロトコルの、C言語によるフルスクラッチ実装。

[PyBitmessage](https://github.com/Bitmessage/PyBitmessage) と実ネットワーク越しに相互運用できることを目標に、
暗号層(ECIES/ECDSA)・PoW・全objectワイヤーフォーマット・P2Pネットワーク層・JSON-RPC API・CLIを一から実装した。

設計・実装判断の詳細な経緯は [DESIGN.md](DESIGN.md) を参照。

## 現状: v1完成(2026-08-23)

以下が実装・実ネットワーク(testnet)で動作確認済み。

- **鍵ライフサイクル**: アドレス生成(v3/v4)、パスフレーズ由来KEKによる秘密鍵の暗号化保存、unlock/lock/delete
- **暗号層**: ECIES暗号化・ECDSA署名(SHA256)。PyBitmessage(pyelliptic/highlevelcrypto)とバイト完全一致を検証済み
- **全objectワイヤーフォーマット**の構築・解析: `getpubkey` / `pubkey`(v2/v3/v4) / `msg` / `broadcast` / `ack`
- **PoW計算エンジン**: マルチスレッド並列探索(NumCPU本)
- **P2Pネットワーク層**: version/verack/addr/inv/getdata/objectのハンドシェイクと配線。実testnetノードとの
  相互運用を確認済み。接続の常駐維持・再接続、受信objectの他peerへの中継(inv flooding)に対応
- **direct message送受信**: 送信時のPoW計算・ack機構、getpubkey要求の自動発行/自動応答、ack未着時の
  自動再送(間隔を倍々に、toPubEncryptionHexを直接指定した送信でも自動でpubkey_cacheへ登録され再送される)
- **broadcast購読・送信**: 購読先アドレスからのbroadcastを自動復号してinboxへ、`sendBroadcast`での送信
- **chan(私設グループチャンネル)**: 共有passphraseから同じアドレス・鍵を導出して複数人が
  参加(`joinChan`)、自分自身宛のsendMessageで投稿、他メンバーはtrial_decryptで自動復号
- **受信objectのPoW検証**: ネットワーク既定の最低難易度未満のobjectは受信時点で拒否
- **outbound SOCKS5プロキシ**: Tor等をoutbound接続に使う設定を`config.db`へ永続化(`set-socks-proxy`)。
  mainnetシード全滅時の代替経路確保が主な動機。設定変更はdaemon再起動なしで次の再接続
  サイクル(既定30秒以内)から反映される
- **v3 onionピア探索**: PyBitmessage準拠の`OBJECT_ONIONPEER`(専用object type)を受信し、
  ネットワーク上で生存しているv3 onionピアを`peers.db`へ自動登録(受信のみ、自身のonion
  hidden serviceの運用・announceはinbound Tor同様スコープ外)
- **addrホストのフィルタリング**: 受信した`addr`情報からprivate/loopback/link-local等の
  アドレスを除外(内部ネットワークへの誤接続防止)
- **getpubkey応答のスロットリング**: 同一宛先への短時間の連続要求に対し、有効期限内の応答を
  再利用しPoWを都度計算し直さない
- **DoS上限**: P2Pメッセージのlengthフィールド申告を実データ到着前に検査し、巨大な値を
  申告するpeerを即座に切断(受信バッファの無制限確保を防止)
- **JSON-RPC 2.0 API + CLI**: 上記すべてを`bitmessage-cli`から操作可能

### v1スコープ外(既知の制限、backlog)

- inbound接続(Tor hidden service実装まで見送り)、Dandelion++のstem機能、GPU PoW — 当初から明示的にスコープ外
- 手動peer追加(`addPeer`) —
  詳細は [DESIGN.md §11](DESIGN.md#11-次にやること引き継ぎメモ随時更新) 参照

## ビルド

### 依存

- CMake 3.25以降、Ninja(または他のCMake対応ビルドシステム)
- Cコンパイラ(GCC/Clang、C11)
- OpenSSL、SQLite3、pthread

```sh
cmake -B build-Debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
ninja -C build-Debug
```

## テスト

```sh
ctest --test-dir build-Debug --output-on-failure
```

## 使い方

daemon(`bitmessaged`)を起動すると、JSON-RPC APIの認証情報(ユーザー名は固定`bitmessage`、パスワードは
起動毎にランダム生成)が標準エラー出力に表示される(設定ファイル未実装のため)。

```sh
# 既定はmainnet。テストネットに繋ぎたい場合は BM_TESTNET=1 を指定
# JSON-RPC APIのポートは既定8442。他プロセスと衝突する場合は BM_API_PORT で変更可能
# (bitmessage-cli側も同じ環境変数を読むので揃えること)
./build-Debug/src/bitmessaged
```

別ターミナルから `bitmessage-cli` で操作する(`BM_API_USER`/`BM_API_PASS` は daemon 起動時の表示に合わせる)。

```sh
export BM_API_USER=bitmessage
export BM_API_PASS=<daemon起動時に表示されたパスワード>

CLI=./build-Debug/src/cli/bitmessage-cli

# アドレス作成・unlock
$CLI create-address "my passphrase" 4 1 1 "label" "store passphrase"
$CLI unlock BM-xxxxxxxx "store passphrase"
$CLI list-addresses

# 相手の公開鍵が未取得でも送信すればgetpubkeyが自動発行される(その回の送信は失敗するので、
# pubkeyが届いてから再送する)
$CLI send-message BM-fromAddress BM-toAddress - "subject" "body" 3600 1
$CLI get-inbox

# broadcast購読・送信
$CLI add-subscription BM-someAddress "label"
$CLI send-broadcast BM-fromAddress "subject" "body" 3600

# chan(私設グループチャンネル): 同じpassphraseで呼んだ全員が同じアドレス・鍵を共有する
CHAN=$($CLI join-chan "my chan passphrase" "my chan" "store passphrase" | tr -d '"')
$CLI unlock "$CHAN" "store passphrase"
$CLI send-message "$CHAN" "$CHAN" - "subject" "body" 3600 1

# outbound接続をSOCKS5プロキシ(Tor等)経由にする。次の再接続サイクル(既定30秒以内)で
# daemon再起動なしに反映される
$CLI set-socks-proxy 1 127.0.0.1 9050
$CLI get-socks-proxy

# その他
$CLI cache-pubkey BM-address <signingPubkeyHex> <encryptionPubkeyHex>
$CLI list-subscriptions
$CLI lock BM-address
$CLI delete BM-address
```

全コマンドは `bitmessage-cli` を引数無しで実行すると一覧表示される。

## ディレクトリ構成

```
src/
  common/   共通ユーティリティ(varint、hash、JSON、キュー等)
  core/     鍵管理・暗号・object構築/解析・送受信パイプライン・JSON-RPC API
  infra/    P2Pネットワーク層(接続管理・object同期・peer管理)
  pow/      PoW計算エンジン
  cli/      CLIクライアント
tests/      ctestベースのテストスイート
DESIGN.md   設計文書(グランドデザイン、随時更新される実装状況・決定事項)
```
