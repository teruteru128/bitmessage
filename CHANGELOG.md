# Changelog

このプロジェクトの利用者向けリリースノート。[Keep a Changelog](https://keepachangelog.com/ja/1.0.0/)
に緩く準拠する。開発の詳しい経緯・設計判断の背景(「なぜ」)は [DESIGN.md](DESIGN.md) を参照。

## [1.4.0] - 2026-11-05

### 互換性に関する注意

- **`sendMessage` APIと`send-message` CLIの引数が変わった。** `toPubEncryptionHex`を廃止したので、
  以降の引数の位置が1つ前へずれる(新: `[fromAddress, toAddress, subject, body, ttlSeconds?,
  ackStealthLevel?]`)。v1.3までの呼び方のままだと、公開鍵の文字列が件名として扱われるので、呼び出し側を
  必ず直すこと。渡された鍵が宛先と対応するかを検証しておらず、無関係の鍵で暗号化できてしまう問題への対応。
  相手の鍵は`cachePubkey`で登録するか、自動のgetpubkey要求で取得する
- **ビルドに必要なものが増えた。** libmicrohttpd・cJSON・pkg-config(JSON-RPC APIのHTTPとJSONの処理を
  これらへ移行した)。gettextは任意
- **daemonのログとusageが英語になった。** ログの文字列で検索している運用は見直しが必要
- User Agentを`/BitmessageC:…/`から`/CBitmessage:…/`へ変更
- `unlockAllAddresses`は10,000件を超えるidentityを断るようになった(受信msgごとの試行復号がネットワーク
  スレッドを止めるため)。必要なアドレスだけを`unlockAddresses`でunlockする
- `sendMessage`/`sendBroadcast`に本文長の上限を設けた(件名と本文の合計で2^18−500byte)。超えるとPoWの前に
  エラーを返す

### 追加

- **実験的: ポスト量子拡張(v5アドレス)。** ML-DSA-65+Ed25519の署名とML-KEM-768+X25519(X-Wing)の鍵
  カプセル化を使う、提案段階の形式。OpenSSL 3.5以降でのビルドと`[pq] enabled = 1`(`BM_PQ_ENABLED=1`)が
  必要で、既定では無効。v5同士でmsg・broadcastを送受信できる。PyBitmessage等の他のクライアントはv5を
  使えない(中継はする)。詳細は[DESIGN-PQ.md](DESIGN-PQ.md)
- 数千件規模の鍵の運用: `import-keys-dat`(keys.datの一括インポート、`importAddressesBulk`)、`unlock-all`
  (`unlockAllAddresses`)、`unlock-addresses`(`unlockAddresses`、指定したアドレスの一括unlock)、共通の
  passphraseから導出するvault方式(2段階KDF)
- WIFの`import-address`/`export-address`、`set-label`(`setAddressLabel`)、`fix-labels-from-keys-dat`
- アドレス帳(`addAddressBookEntry`/`deleteAddressBookEntry`/`listAddressBookEntries`)、
  `trash-message`(`trashMessage`)
- v3アドレスを同じ鍵のv4へ移す`convert-to-v4`/`convert-all-v3-to-v4`。移行後もv3の要求には応答する
- `send-message`/`send-broadcast`の`--body-file`(本文をファイルや標準入力から渡す)
- `bitmessage-cli`のメッセージの日本語訳(gettext)、READMEの英語版と日本語版、`--version`/`--help`
- ログレベルを8段階に拡張(`BM_LOG_LEVEL`)

### 変更

- 送信を接続ごとのキュー+EPOLLOUT駆動へ作り替え、getdataへの応答を保留+補充方式にした。遅い相手1本に
  ネットワークスレッド全体が止められない
- PoWを専用のワーカースレッドで行うようにした。getpubkeyへの自応答や送信のPoWの間も、ピア接続とAPIの
  他の呼び出しは止まらない。`sendMessage`の応答の形は変わらない(PoWの完了後に返る)
- 自分宛・chan宛の送信はackを作らず、再送の対象にせず、すぐinboxへ入れる(本家と同じ)
- `unlockAddress`後の過去msgの読み直しを、unlockした1件だけに限定した(keyring全体を試すと数千件の運用で
  APIが何時間も止まった)。`unlockAllAddresses`は読み直しをしない
- 期限切れobjectの受信とGCに本家と同じ猶予期間を入れた
- onionpeerの自己announceを、最初のピアが接続されてから行うようにした

### 修正

- **自応答のpubkeyとbroadcastのbitfieldにBITFIELD_DOESACKが立っていなかった。** 本家の送信者はこの場合
  ackを付けないので、この鍵で送られたmsgにackが返らなかった。修正前に作った応答は再利用せず作り直す
- **Dandelion++のstemのタイムアウトで、持っていないobjectのinvを無条件に流していた**
- `peer_registry`のマルチスレッド競合によるdouble free
- 同じ鍵のv3とv4のアドレスが共存すると、getpubkeyへの応答を取り違えていた
- versionメッセージのaddrFromがephemeralポートを漏らしていた(0.0.0.0を送るようにした)
- outbound接続数が`max_outbound`未満で頭打ちになっていた
- JSON文字列の非ASCII文字の二重エンコード
- `BM_TOR_CONTROL`を使う新規インストールでseedの投入が空振りしていた
- 接続開始時のハング(connect_initial)
- 時計のずれた相手による切断WARNを間引き、切断ログに理由を出すようにした

## [1.3.0] - 2026-08-26

### 追加

- 送信済みボックス一覧: `getSentMessages` API・`bitmessage-cli get-sent`
- outbound SOCKS5プロキシ設定をonion peer専用(`socks_proxy`)/クリアネットIP専用
  (`socks_proxy_clearnet`)に分離。`getSocksProxyOnion`/`Clearnet`等のAPI・
  `get/set-socks-proxy-onion`/`-clearnet` CLIサブコマンドを追加

### 修正

- **重大**: verack交換完了直後という早すぎるタイミングで能動的にaddr/big invを
  送り返すこと自体が、相手からの即時切断(RST/EOF)を誘発していた問題。送信を
  5秒遅延させることで即切断率が99%から6%まで改善した
- **重大**: `send_big_inv`が1万件超のhashを無間隔で一括送信すると、相手のTCP
  受信ウィンドウが数秒でゼロまで埋まりRSTで強制切断されていた問題。チャンク
  分割(1000件ずつ)+ペーシング(1秒間隔)送信に変更
- **重大**: outbound SOCKS5設定が単一だったため、有効化するとクリアネットIP宛の
  接続まで無条件でTor出口ノード経由になり、共有IPゆえのレート制限を招いていた
  問題(上記のonion/クリアネット分離で解消)
- `pong`受信が専用ハンドラを持たず"unhandled command"ログに落ちていた問題
  (実害は無いが、専用の空ハンドラを追加)
- `join-chan`(=unlockAddress)する前に既に`object_pool.db`へ届いていたchan宛
  msgオブジェクト(過去ログ)が、unlock後も自動でinboxに現れない問題
- systemdユニットがTor ControlPort用グループ(`debian-tor`)に属さず、
  `tor.service`への起動順序依存も無かった問題(`BM_TOR_CONTROL=1`利用時)

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
