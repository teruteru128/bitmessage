# bitmessage

[![CI](https://github.com/teruteru128/bitmessage/actions/workflows/ci.yml/badge.svg)](https://github.com/teruteru128/bitmessage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | 日本語

Bitmessage P2Pメッセージングプロトコルの、C言語によるフルスクラッチ実装。

[PyBitmessage](https://github.com/Bitmessage/PyBitmessage) と実ネットワーク越しに相互運用できることを目標に、
暗号層(ECIES/ECDSA)・PoW・全objectワイヤーフォーマット・P2Pネットワーク層・JSON-RPC API・CLIを一から実装した。

設計(アーキテクチャ・現在のbacklog)は [DESIGN.md](DESIGN.md)、日付入りの開発経緯
(バグの発覚経緯・議論の顛末等)は [DESIGN-LOG.md](DESIGN-LOG.md)、リリースごとの
変更点は [CHANGELOG.md](CHANGELOG.md) を参照。

## 現状

最新リリースはv1.4.0(2026-11-05)。以下が実装済みで、後述の実験的なポスト量子拡張を除いて、
実ネットワークでの動作を確認している。

### プロトコル・暗号

- **鍵ライフサイクル**: アドレス生成(v3/v4)、パスフレーズ由来KEKによる秘密鍵の暗号化保存、unlock/lock/delete
- **暗号層**: ECIES暗号化・ECDSA署名(SHA256)。PyBitmessage(pyelliptic/highlevelcrypto)とバイト完全一致を検証済み
- **全objectワイヤーフォーマット**の構築・解析: `getpubkey` / `pubkey`(v2/v3/v4) / `msg` / `broadcast` / `ack` /
  `onionpeer`
- **PoW計算エンジン**: マルチスレッド並列探索(NumCPU本)。受信objectのPoWも検証し、ネットワーク既定の
  最低難易度未満のobjectは受信時点で拒否する

### メッセージング

- **direct message送受信**: 送信時のPoW計算・ack機構、getpubkey要求の自動発行/自動応答、ack未着時の
  自動再送(間隔を倍々に)。宛先の公開鍵は常に`pubkey_cache`経由で解決する(`cachePubkey`で
  事前登録可能。誤った鍵での暗号化・cache汚染を防ぐため、`sendMessage`への直接指定は廃止した)
- **broadcast購読・送信**: 購読先アドレスからのbroadcastを自動復号してinboxへ、`sendBroadcast`での送信
- **chan(私設グループチャンネル)**: 共有passphraseから同じアドレス・鍵を導出して複数人が
  参加(`joinChan`)、自分自身宛のsendMessageで投稿、他メンバーはtrial_decryptで自動復号
- **受信箱・送信済みボックス**: `getInboxMessages`/`getSentMessages`、`trashMessage`(論理削除)
- **アドレス帳**: 追加・削除・一覧(PyBitmessage本家と同じく重複登録は不可)
- **長文の送信**: `--body-file`で本文をファイルまたは標準入力から読む(本文を`ps`やシェル履歴に
  残さない)。subject+本文の上限はPyBitmessage本家と同じ261,644バイト

### 鍵の移行・大量運用

- **PyBitmessageからの移行**: `keys.dat`の一括インポート(`import-keys-dat`)、WIF鍵ペアによる
  個別のimport/export、chanの`keys.dat`設定の再現、文字化けしたラベルの修復(`fix-labels-from-keys-dat`)
- **一括unlock**: 2段階KDF(vault方式、DESIGN.md §7.4)で数千件規模のアドレスを1回の鍵導出で
  unlockできる。`unlock-all`(identity.dbの全件。10,000件まで)と`unlock-addresses`(ファイルで
  指定したアドレスだけ)。unlock中のアドレスが多いほど受信msgの試行復号が重くなるので、
  大量に持つ場合は必要なアドレスに絞って`unlock-addresses`を使う
- **v3→v4移行**: v3アドレスを同じ鍵のv4アドレスへ移す(`convert-to-v4`/`convert-all-v3-to-v4`)

### ネットワーク

- **P2Pネットワーク層**: version/verack/addr/inv/getdata/objectのハンドシェイクと配線。接続の
  常駐維持・再接続、受信objectの他peerへの中継、新規peerへの保有object一覧の送信。peerの選択は
  PyBitmessage本家と同じratingによる重み付きランダム
- **inbound接続**: TCPでの待ち受け(`BM_INBOUND_PORT`)。Tor ControlPort経由でのhidden service
  自動作成(`BM_TOR_CONTROL=1`)、または静的なtorrc設定(`BM_ONION_ADDRESS`)に対応。アイドル/
  ハンドシェイクのタイムアウト、keepalive、同時接続数・accept数のレート制限付き
- **Dandelion++**: stem/fluffの状態機械、`NODE_DANDELION` serviceビットの表明
- **onionピア**: PyBitmessage準拠の`onionpeer` objectを受信してv3 onionピアを`peers.db`へ登録し、
  自分のonionアドレスも定期的にannounceする
- **outbound SOCKS5プロキシ**: Tor等をoutbound接続に使う設定を`config.db`へ永続化。onion peer
  (`.onion`宛)専用設定(`set-socks-proxy-onion`)とクリアネットIP宛専用設定
  (`set-socks-proxy-clearnet`、既定disabled=直結)を分離しており、onionだけ有効化しても
  クリアネットIPへの接続は直結のまま維持される(PyBitmessage本家のsocksproxytype/
  onionsocksproxytype分離に合わせた設計、DESIGN.md §11参照)。設定変更はdaemon再起動
  なしで次の再接続サイクル(既定30秒以内)から反映される
- **手動peer追加・観測済みノードリスト**: 個人的に存在を確認したノードを`addPeer`で手動追加。
  加えて`seeds/observed_nodes.txt`(出自・限界を明記した別ファイル、公式seedとは別枠)を
  新規インストール時にmainnetシード全滅していても最初の1本を繋げるための足がかりとして同梱
- **防御**: `addr`で教えられたprivate/loopback/link-local等のアドレスの除外、getpubkey応答の
  スロットリング、P2Pメッセージの申告lengthの事前検査(巨大な値を申告するpeerを実データ到着前に
  切断)、自己接続の防止

### 運用

- **JSON-RPC 2.0 API + CLI**: 上記すべてを`bitmessage-cli`から操作できる。CLIのメッセージは
  日本語ロケールでは日本語、それ以外では英語で表示される(gettext)。daemonのログは英語
- **ログ**: 8段階のログレベル(`BM_LOG_LEVEL`)。systemd配下ではタイムスタンプをjournaldに任せる
- **インストール**: `cmake --install`、systemdユニットファイル(`systemd/bitmessaged.service`)

### 実験的: ポスト量子拡張(v5アドレス)

ML-DSA/ML-KEMとEd25519/X25519を併用するアドレス・object形式の提案で、`src/pq/`とdaemon本体に
実装している。OpenSSL 3.5以降でのビルドが必要で、有効にしない限り動かない(`[pq] enabled = 1`
または`BM_PQ_ENABLED=1`)。他のノードはv5のobjectを理解しないまま中継するので、読めるのは有効にした
ノードだけである。

- これは提案であって、Bitmessageプロトコルの一部ではない。PyBitmessage等の他のクライアントはv5アドレスを
  使えない。v5アドレスはv5アドレスとしかメッセージをやり取りできない。
- objectがv4より約7.4KB大きいので、PoWに時間がかかる。msg 1通あたり数倍、getpubkeyへの応答は16コアで
  30秒程度が目安。
- v5で使えないもの: ランダムなアドレス生成、chan、`export-address`。
- 実ネットワークではまだ使っていない。v5同士の往復と、v5を理解しないノード(PyBitmessageを含む)を経由した
  中継は、隔離したネットワークで確認した。

詳細は [DESIGN-PQ.md](DESIGN-PQ.md)。

### スコープ外(既知の制限、backlog)

- GPU/OpenCL PoW — §8で明示的にv1スコープ外と決めた項目、引き続き見送り
- LAN内UDP broadcastによるpeer発見 — 手動peer追加で代替可能なため当分見送り(凍結)
- `core/crypto.c`のEC_KEY/ECDSA系のEVP_PKEYベースAPIへの移行 — OpenSSLが実際に
  非推奨API削除を予告するまでは見送り(凍結)

詳細は [DESIGN.md §11](DESIGN.md#11-次にやること引き継ぎメモ随時更新) 参照

## ビルド

### 依存

- CMake 3.25以降、Ninja(または他のCMake対応ビルドシステム)
- Cコンパイラ(GCC/Clang、C11)
- OpenSSL、SQLite3、pthread
  (ポスト量子プロトタイプ`src/pq`はOpenSSL 3.5以降でのみビルドされる。それ未満では
  自動的に除外され、daemon本体には影響しない。DESIGN-PQ.md §6.1)
- libmicrohttpd、cJSON(JSON-RPC APIサーバーのHTTPトランスポートとJSON処理、
  `pkg-config`経由で検出する。DESIGN.md §6.3参照)
- gettext(任意。`bitmessage-cli`のメッセージの日本語訳をビルドする。無ければCLIは
  英語だけで動く。DESIGN.md §11項目54)

Debian/Ubuntu系なら以下で揃う。

```sh
sudo apt install cmake ninja-build build-essential pkg-config \
                 libssl-dev libsqlite3-dev libmicrohttpd-dev libcjson-dev gettext
```

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
起動毎にランダム生成)が標準エラー出力に表示される(意図的に非永続。認証情報だけは設定ファイルに書けない)。

起動時設定は`bitmessage.conf`(INI形式、`bitmessaged`のカレントディレクトリに置く。無ければ既定値で
起動する)で行う。`bitmessage.conf.example`をコピーして使うと早い。各項目は環境変数でも指定でき、
その場合は環境変数がファイルの値より優先される(優先順位: 環境変数 > `bitmessage.conf` > 既定値)。

```sh
cp bitmessage.conf.example bitmessage.conf
# 必要な項目だけ編集する(testnet切り替え、APIポート、Tor hidden service連携等)

# 環境変数での一時的な上書きも可能。例: 既定はmainnet、testnetに繋ぎたい場合は BM_TESTNET=1
# JSON-RPC APIのポートは既定8442。他プロセスと衝突する場合は BM_API_PORT で変更可能
# (bitmessage-cli側も同じ環境変数を読むので揃えること)
./build-Debug/src/bitmessaged
```

### 環境変数一覧

`bitmessaged`向け(`bitmessage.conf`の値をこの起動限りで上書きする。優先順位: 環境変数 >
`bitmessage.conf` > 既定値):

| 環境変数 | 既定値 | 説明 |
| --- | --- | --- |
| `BM_CONFIG_FILE` | `bitmessage.conf` | 起動時設定ファイルの場所 |
| `BM_DATA_DIR` | `.`(CWD) | DBファイル(`peers.db`等5種)の置き場所。systemd等での固定パス運用(例`/var/lib/bitmessage`)向け |
| `BM_SEEDS_FILE` | `seeds/observed_nodes.txt` | 「開発者が確認した身元不明のノード」リストの場所(§11、mainnetのみ・無くても起動には支障ない) |
| `BM_TESTNET` | (mainnet) | `1`でtestnetへ切り替え |
| `BM_NO_CONNECT` | (接続する) | `1`で実際のP2P接続を一切行わない(主にテスト用) |
| `BM_MAX_OUTBOUND` | `3` | 同時に確立する最大outbound接続数 |
| `BM_PQ_ENABLED` | (無効) | `1`で実験的なポスト量子拡張(v5アドレス)を有効にする。OpenSSL 3.5以降でのビルドが必要 |
| `BM_API_PORT` | `8442` | JSON-RPC APIのlisten port |
| `BM_INBOUND_PORT` | (無効) | Tor hidden service等からのinbound接続を受け付けるport。0または未設定で無効 |
| `BM_DEFAULT_NONCE_TRIALS_PER_BYTE` | `1000` | 新規アドレス作成時の既定PoW難易度(nonce trials/byte) |
| `BM_DEFAULT_PAYLOAD_LENGTH_EXTRA_BYTES` | `1000` | 同上(payload length extra bytes) |
| `BM_TOR_CONTROL` | (無効) | `1`でTor ControlPort経由のhidden service自動作成を試みる(`BM_INBOUND_PORT`が前提。systemd配下での実行時はTorのControlPortソケットへアクセスできるグループ権限が必要、下記systemd節参照) |
| `BM_TOR_CONTROL_SOCKET` | `/run/tor/control` | ControlPortのUnixドメインソケットパス(Debian/Ubuntu系torパッケージの既定パス。Fedora/Arch等では異なりうるため、他ディストリで`BM_TOR_CONTROL=1`を使う場合は実際のパスを明示指定すること) |
| `BM_TOR_CONTROL_HOST` | `127.0.0.1` | 上記に接続できない場合のTCPフォールバック先ホスト |
| `BM_TOR_CONTROL_PORT` | `9051` | 同上ポート |
| `BM_TOR_VIRTUAL_PORT` | `8444` | 他peerが自分のonionアドレスへ接続してくるポート番号 |
| `BM_ONION_ADDRESS` | (未設定) | 静的torrc設定を使う場合、自分のonionアドレスを直接指定(`BM_TOR_CONTROL`より優先) |
| `BM_LOG_LEVEL` | `INFO` | 出力する最低のログレベル。詳しい順に`DEBUG3`/`DEBUG2`/`DEBUG1`/`DEBUG`/`INFO`/`NOTICE`/`WARN`/`ERROR`(大文字小文字は区別しない) |
| `BM_LOG_TIMESTAMPS` | (自動) | `1`/`0`でログ行頭のタイムスタンプを付ける/付けない。未設定ならsystemd(journald)配下では付けず、それ以外では付ける |

`bitmessage-cli`向け:

| 環境変数 | 既定値 | 説明 |
| --- | --- | --- |
| `BM_API_HOST` | `127.0.0.1` | 接続先daemonのホスト |
| `BM_API_PORT` | `8442` | 接続先daemonのポート(daemon起動時と揃えること) |
| `BM_API_USER` | (必須) | JSON-RPC APIのユーザー名(daemon起動時の表示に合わせる) |
| `BM_API_PASS` | (必須) | 同パスワード |
| `BM_LOCALEDIR` | (自動) | メッセージの訳(.mo)を探すディレクトリ。未設定なら実行ファイルの隣の`locale/`(ビルドツリー)、無ければインストール先(既定`/usr/local/share/locale`) |

表示言語は通常のロケール設定(`LANG`/`LC_MESSAGES`/`LC_ALL`/`LANGUAGE`)で決まる。日本語環境で
英語表示にしたい場合は`LC_MESSAGES=C`等を指定する。

### systemdサービス化(`systemd/bitmessaged.service`)

`cmake --install`後、生成される`.service`ファイルは`DynamicUser=yes`でサービス専用ユーザーを
自動生成する。`BM_TOR_CONTROL=1`でTor ControlPortのUnixドメインソケット(既定
`/run/tor/control`、Debian/Ubuntu系torパッケージでは`debian-tor`グループ所有)へ接続する
場合、`DynamicUser`が生成するユーザーは既定でどのグループにも属さないため、ユニットファイル
側で`SupplementaryGroups=debian-tor`を指定してグループ参加させる必要がある(同梱の
`.service`ファイルには既に記載済み)。他ディストリでTorのControlPortソケットの所有グループが
異なる場合は、ここを実際のグループ名に置き換えること。BM_TOR_CONTROLを使わない
(SOCKS5 outboundのみ、またはTor自体を使わない)運用では不要だが、既定で入れておいても
実害は無い。

`.service`ファイルは`After=tor.service`/`Wants=tor.service`でTorの起動を待つ(Torを使わない
運用でも`tor.service`が無効/未インストールなら本体の起動を妨げないソフト依存)。

### CLIでの操作

別ターミナルから `bitmessage-cli` で操作する(`BM_API_USER`/`BM_API_PASS` は daemon 起動時の表示に合わせる)。

```sh
export BM_API_USER=bitmessage
export BM_API_PASS=<daemon起動時に表示されたパスワード>

CLI=./build-Debug/src/cli/bitmessage-cli

# アドレス作成・unlock
$CLI create-address "my passphrase" 4 1 1 "label" "store passphrase"
$CLI unlock BM-xxxxxxxx "store passphrase"
$CLI list-addresses

# BM_PQ_ENABLED=1のとき、version 5でポスト量子アドレスを作れる(上の「実験的」の節を参照)
$CLI create-address "my passphrase" 5 1 1 "label" "store passphrase"

# 相手の公開鍵が未取得でも送信すればgetpubkeyが自動発行される(その回の送信は失敗するので、
# pubkeyが届いてから再送する)
$CLI send-message BM-fromAddress BM-toAddress "subject" "body" 3600 1
$CLI get-inbox
$CLI get-sent

# 長文・改行を含む本文は--body-fileでファイル(pathが"-"なら標準入力)から読ませる。
# 位置引数で渡すと本文がps(1)から他ユーザーに見え、シェル履歴にも残る
$CLI send-message --body-file ./body.txt BM-fromAddress BM-toAddress "subject" 3600 1
$CLI send-message --body-file - BM-fromAddress BM-toAddress "subject" < ./body.txt

# broadcast購読・送信
$CLI add-subscription BM-someAddress "label"
$CLI send-broadcast BM-fromAddress "subject" "body" 3600
$CLI send-broadcast --body-file ./body.txt BM-fromAddress "subject" 3600

# chan(私設グループチャンネル): 同じpassphraseで呼んだ全員が同じアドレス・鍵を共有する
CHAN=$($CLI join-chan "my chan passphrase" "my chan" "store passphrase" | tr -d '"')
$CLI unlock "$CHAN" "store passphrase"
$CLI send-message "$CHAN" "$CHAN" "subject" "body" 3600 1

# PyBitmessageのkeys.datを一括インポートし、必要なアドレスだけまとめてunlockする
# (addresses.txtは1行1アドレス。"-"なら標準入力から読む)
$CLI import-keys-dat ~/.config/PyBitmessage/keys.dat "store passphrase"
$CLI unlock-addresses ./addresses.txt "store passphrase"

# onion peer(.onion宛)向けのoutbound接続をSOCKS5プロキシ(Tor等)経由にする。クリアネットIP
# 宛は既定disabled(直結)のまま維持される。次の再接続サイクル(既定30秒以内)でdaemon
# 再起動なしに反映される
$CLI set-socks-proxy-onion 1 127.0.0.1 9050
$CLI get-socks-proxy-onion
# クリアネットIP宛も匿名化したい場合のみ明示的に有効化する(Tor出口ノード経由になり
# 外部ノードへの接続性が悪化しうる、上記「outbound SOCKS5プロキシ」参照)
$CLI set-socks-proxy-clearnet 1 127.0.0.1 9050
$CLI get-socks-proxy-clearnet

# 個人的に存在を確認したノードを手動で追加する(mainnetシード全滅時の最後の手段)
$CLI add-peer 203.0.113.1 8444

# その他
$CLI cache-pubkey BM-address <signingPubkeyHex> <encryptionPubkeyHex>
$CLI list-subscriptions
$CLI list-connections
$CLI lock BM-address
$CLI delete BM-address
```

全コマンドは `bitmessage-cli --help`(または引数無し)で一覧表示される。

## ディレクトリ構成

```
src/
  common/   共通ユーティリティ(varint、hash、JSON、キュー、ログ等)
  core/     鍵管理・暗号・object構築/解析・送受信パイプライン・peer管理・JSON-RPC API
  infra/    P2Pネットワーク層(接続管理・object同期・Dandelion++・Tor連携)
  pow/      PoW計算エンジン
  cli/      CLIクライアント
  pq/       ポスト量子拡張(v5のアドレスとobject)
po/         bitmessage-cliのメッセージの訳(gettext)
tests/      ctestベースのテストスイート
seeds/      mainnetシード全滅時のフォールバック用ノードリスト(observed_nodes.txt)
systemd/    systemdユニットファイル
DESIGN.md       設計文書(グランドデザイン、実装状況・決定事項、backlog)
DESIGN-LOG.md   日付入りの開発経緯
DESIGN-PQ.md    ポスト量子拡張の提案
CHANGELOG.md    リリースごとの変更点
```

## 連絡先

Bitmessage: `BM-2cUcXwGMhcqfbbjrGE1Cxb92SBdQerarL6`

Bitmessage上のリリース告知はこのアドレスから送る。他のアドレスからの告知は、このプロジェクトのものではない。
