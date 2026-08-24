# Changelog

このプロジェクトの利用者向けリリースノート。[Keep a Changelog](https://keepachangelog.com/ja/1.0.0/)
に緩く準拠する。開発の詳しい経緯・設計判断の背景(「なぜ」)は [DESIGN.md](DESIGN.md) を参照。

## [1.2.0] - 2026-08-24

### 追加

- Dandelion++の完全実装(Stage 1〜3): stem/fluffの単一ホップ状態機械、inv/dinvの来歴による
  stem要否判定、`NODE_DANDELION` serviceビットの表明
- inbound接続対応の仕上げ: アイドル/ハンドシェイクタイムアウト・keepalive ping送信、
  DoS対策のレート制限(同時接続数上限・単位時間あたりaccept数上限)
- プロトコルバージョン互換性チェック・version messageの`timestamp`検証(いずれも
  基準を満たさない相手を`fatal` errorで切断)
- `listConnections`/`getNetworkStats` API(接続一覧・送受信バイト数、`bitmessage-cli
  list-connections`)
- 新規peer接続時の保有object一覧送信(sendBigInv相当)、outbound `addr`メッセージ送信
- onionpeer自己announceの定期再送(約2時間おき、PyBitmessage本家準拠)
- ログレベル(`DEBUG`/`INFO`/`WARN`/`ERROR`)、`BM_LOG_LEVEL`環境変数によるフィルタリング
- AddressSanitizer/UndefinedBehaviorSanitizer/ThreadSanitizerによる継続的な検査体制、
  GitHub Actions CIへ統合(`sanitize`/`sanitize-thread`ジョブ)
- Releaseビルド(`-O2`)の動作確認、`BM_DATA_DIR`環境変数によるDBファイル置き場の
  上書き、`cmake --install`対応、systemdユニットファイル(`systemd/bitmessaged.service`)
- CIにFedoraでのビルド確認ジョブを追加(Ubuntu以外での移植性の最低限の確認)
- 自己接続防止(`peers.db`の`is_self`フラグ)
- MITライセンス、GitHub Actions CI

### 修正

- **重大**: `varint`の複数バイト表現がリトルエンディアンで実装されていた(仕様はビッグ
  エンディアン)。ネットワーク上の全peerとの相互運用性に関わる問題だった
- **重大**: `send_big_inv`がDandelion++の判定機構を誤って毎回発火させ、自分が生成した
  objectを無限ループで再配信していた
- **重大**: SIGPIPEを無視していなかったため、相手が既に閉じたソケットへ書き込んだ瞬間に
  daemonが無言のまま(痕跡を一切残さず)終了することがあった
- 切断したoutbound接続のratingが更新されず、同じ死んだpeerに再接続し続ける問題(3回の
  修正を経て解決。原因はSOCKS5(Tor)プロキシ経由の接続でrating記録の前提が崩れていたこと)
- onion peerのrating/last_seen更新が内部バッファのサイズ不足で常に0行ヒットし失敗していた
- `bm_log`(旧ロガー)がマルチスレッドから同時に呼ばれるとログ行が混ざることがあった
- `addr`受信メッセージ由来の破損したIPv6アドレスが`peers.db`へ混入する問題
- Releaseビルド(`-O2`)で初めて顕在化した実バグ: `self_onion_address`がNUL終端されずに
  未初期化スタック領域を読むバッファオーバーリードになりうる状態だった
- ThreadSanitizerで発見: `dandelion.c`/`peer_registry.c`間のロック順序逆転(潜在的
  デッドロック)、`stop_flag`系のスレッド間可視性の不備(`_Atomic`型への変更で解消)

### 変更

- peer接続選定を、rating上位を機械的に選ぶ方式から確率的な重み付きランダムサンプリング
  (PyBitmessage本家のconnectionchooser.py準拠)へ変更
- Dandelion++のstemピア選定(hash探索)をO(n²)からO(1)平均のハッシュテーブルへ

## [1.1.0] - 2026-08-22

### 追加

- `addr`受信メッセージの`peers.db`への永続化
- outbound SOCKS5プロキシ(Tor経由接続)設定の永続化・動的リロード
  (`set-socks-proxy`、daemon再起動不要で次の再接続サイクルから反映)
- `addr`で教えられたホストのフィルタリング(private/loopback/link-local等を除外し、
  内部ネットワークへの誤接続を防止)
- getpubkey応答のスロットリング(同一宛先への短時間の連続要求に対しPoW再計算を回避)
- `toPubEncryptionHex`を直接指定した送信の自動再送対応
- chan(私設グループチャンネル)機能(`joinChan`)
- `OBJECT_ONIONPEER`(v3 onionピア探索)の受信側実装
- `peers.db`の低rating/古いノードのクリーンアップ
- 手動peer追加(`addPeer`)・観測済みノードリスト(`seeds/observed_nodes.txt`)
- inbound接続対応 Stage 1(汎用TCP listen/accept + handshake)・Stage 2(Tor ControlPort
  連携によるhidden service自動作成)
- `OBJECT_ONIONPEER`の自己announce送信側
- 静的torrc設定への対応(`BM_ONION_ADDRESS`、PyBitmessageの`onionhostname`相当)
- 起動時設定ファイル`bitmessage.conf`(INI形式)
- `BM_API_PORT`等の環境変数によるポート・PoW難易度既定値の変更

### 修正

- 非blockingソケットへの部分書き込み(short write)が未対応だった問題
- user agent文字列のバージョンが固定化石化していた問題

### 変更

- P2Pメッセージの申告`length`に上限を設け、DoS対策を見直し(巨大な値を申告するpeerを
  実データ到着前に切断)

## [1.0.0] - 2026-08-21

初回リリース。Bitmessageプロトコルの中核機能(鍵ライフサイクル、ECIES/ECDSA暗号層、
全objectワイヤーフォーマット、PoW計算エンジン、P2Pネットワーク層のoutbound接続、
direct message送受信・broadcast購読、JSON-RPC API + CLI)を実装。詳細は
[README.md](README.md)・[DESIGN.md](DESIGN.md) 参照。
