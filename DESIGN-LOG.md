# DESIGN-LOG.md — セッション別の開発経緯記録

[DESIGN.md](DESIGN.md) の§11「次にやること」が肥大化しすぎたため、2026-08-24に分離した
(元は同じファイル内に「今も有効なアーキテクチャ資料(§0〜§10)」と「日付入りの
セッション経緯記録」が混在しており、後者がファイルの約7割を占めて見通しが悪くなっていた)。

**このファイルの位置づけ:** 日付入りの「なぜそう直したか」「何を調査してどう判断したか」の
時系列記録。バグの発覚経緯・議論の顛末・PyBitmessage本家との比較調査結果など、開発の
「経緯」を追う場合はこちらを参照する。

**[DESIGN.md](DESIGN.md) との役割分担:**
- アーキテクチャ・設計(スレッドモデル・DBスキーマ・暗号層・ワイヤーフォーマット等、§0〜§10)
  → DESIGN.md
- 現在のbacklog(次にやること一覧) → DESIGN.md §11
- 過去のセッションでの経緯記録(このファイル) → DESIGN-LOG.md(このファイル)
- リリースごとの利用者向け変更点 → [CHANGELOG.md](CHANGELOG.md)

以下、日付順(古い→新しい)。

---

### v1完成(2026-08-23)

`peer_connector`の常駐化・再接続維持ループ、`api_server`のgraceful shutdown、
`pow_engine`のマルチスレッド並列化、getpubkey要求の自動化(送信側の自動発行+受信側の
自応答+v4の候補照合)、再送(resend)ロジック、broadcast(type=3)の購読・復号+送信
(`sendBroadcast`)、受信object全般のPoW検証、が実装完了・push済み。これで
`network_epoll_thread`以外の全スレッドがpthread_joinできる状態になった(§1参照)。
ctest 16件全通過、実daemonで16コア環境の実ネットワーク難易度PoWが約0.35秒になったこと・
testnet接続中にgetpubkey要求の自動broadcastが実際に動くこと・購読管理/broadcast送信CLIが
実daemonで動作することを確認済み(§4.3, §5.1, §5.4)。

「v1完成」の基準として、2026-08-23にユーザーと合意した内容: 当初のグランドデザイン
(§0〜§10)で決めた機能一式(鍵ライフサイクル、全object種別の構築・解析、PoW、
実ネットワークとの相互運用、direct message送受信、broadcast購読・送信、JSON-RPC API+CLI)
に加え、`sendBroadcast`(受信側だけでは片手落ちなので)と受信object全般のPoW検証
(外部に公開する前提の最低限のセキュリティ)の2点を満たした時点をv1完成とする。
それ以外の既知のギャップ(下記)はv1.1以降のbacklogとして残す。

### addr受信のpeer_manager永続化(2026-08-21)

v1完成後、ユーザーが実際にmainnetへ接続したところ全く繋がらないという報告を受けて調査した
結果、PyBitmessage `knownnodes.py`のハードコードされたmainnetシード9件が2026-08-21時点で
全て(TCP接続自体が)到達不能になっていることを`/dev/tcp`での直接確認で特定した(testnet
シード・一般的なインターネットホストへの接続は正常に成功することと対比して切り分け済み)。
これはこの実装のバグではなく実際のネットワーク状況だが、それ以前から「シードが全滅したら
詰む」という設計上の弱点があった: 受信した`addr`メッセージが`bm_object_sync_dispatch`で
ログ出力されるだけで`peers.db`へ反映されておらず、シード以外の経路でpeerを発見する手段が
無かったため。この弱点を解消する目的で、addr受信を`peers.db`へ実際に永続化するよう実装した。

`peer_manager.c`に`bm_peer_manager_upsert_from_addr`を追加(既存の`bm_peer_manager_upsert`
とは別関数): `ip_address, port, stream`の複合PKで`ON CONFLICT DO UPDATE`するが、
`services`/`last_seen`のみ更新し`rating`/`source`は変更しない。これは「実際の接続実績で
積み上げたratingを、単なる伝聞情報(相手が`addr`メッセージで自己申告してきただけの情報)で
リセットしない」ため。新規行は`rating=0.0, source='addr_msg'`で挿入する。

`object_sync.c`側は`bm_object_sync_ctx`に`peers_db`フィールド(NULL可、未設定ならaddr
永続化を単にスキップ)を追加し、`addr`ディスパッチ分岐で`bm_parse_addr_message`の結果を
`inv`/`getdata`と同じ`BM_MAX_INVENTORY_ITEMS`(50000件)でキャップした上で全件について
`bm_peer_manager_upsert_from_addr`を呼ぶ。ワイヤー上の`ip[16]`(IPv4-mapped IPv6形式、
先頭12byte`00*10,FF,FF`+IPv4の4byte、またはIPv6そのもの)は`inet_ntop`でテキストIPへ
変換する(先頭12byteのプレフィックス一致で判定)。private/loopbackアドレス等のフィルタリングは
未実装のまま(下記backlog参照)。

実daemonでのtestnet接続による動作確認: `bitmessaged`起動後、testnetシードから受信した
`addr`メッセージ(2件)が実際に`peers.db`へ`source='addr_msg', rating=0.0`で挿入され、
既存のseed行(`source='seed'`)のratingは接続成功/失敗に応じて更新される一方
addr由来の新規行のratingは触られないことを確認済み。ctest 16件(新規のaddr受信テストを
`test_object_sync.c`へ追加)全通過。

### SOCKS5プロキシ(Tor outbound)対応(2026-08-21)

addr永続化に続く対策として、outbound接続をSOCKS5プロキシ(典型的にはTorのSocksPort)経由に
できるようにした。動機は2つ: (1) mainnetシード全滅のような状況でも、Tor経由なら別経路で
到達できる可能性がある、(2) 直接TCP接続がISP/ネットワーク事情で塞がれている環境でも
迂回できる。inbound(Tor hidden serviceでの着信待受)は引き続き§9の通りスコープ外。

設定の永続化そのものが未実装だった(§8/§9執筆時点のTODO)ため、今回は「設定の永続化」を
汎用のkey-valueストアとしてではなく、まずSOCKS5プロキシ設定1項目に絞って実装した
(汎用化は将来必要になった時点で改めて検討する、YAGNI)。

- `core/config_store.c/h`(新規)を追加。`config.db`に`socks_proxy`テーブル(id=1固定の
  単一行、`enabled`/`host`/`port`)を持つ。core層に置いたのは、core(api_server.c)・
  infra(peer_connector.c)の両方から参照する必要があり、infra→coreの片方向依存という
  既存の方針(DESIGN.md §1.2)に合わせるため。既定値はTorのSocksPort既定値に合わせ
  `host=127.0.0.1, port=9050, enabled=0`とした。
- `core/api_server.c`に`getSocksProxy`/`setSocksProxy(enabled, host, port)`を追加。
  `bm_api_server_config`に`config_db`フィールド(NULL可)を追加。設定変更は`config.db`へ
  即座に永続化されるが、**稼働中のpeer_connector_threadには反映されない**(起動時に
  読み込んだ値をスレッド生存期間中ずっと使い続ける設計。動的リロードはv1.1のスコープ外、
  反映にはbitmessadedの再起動が必要)。
- `infra/peer_connector.c`にSOCKS5(RFC1928)のno-auth CONNECTハンドシェイクを実装
  (`socks5_connect`ほか)。`bm_peer_connector_config`に`socks_proxy`フィールド(NULL可、
  またはenabled=0なら従来通り直結)を追加。宛先は常にATYP=domain name(0x03)で送る
  (`peers.db`の`ip_address`はIPv4/IPv6のテキスト表現だが、数字IP文字列であってもTor等の
  SOCKS5サーバーは正しく扱う。将来onionアドレスに対応する際もこの経路がそのまま使える
  設計)。プロキシ自体へのTCP接続は既存の`CONNECT_TIMEOUT_SEC`(5秒)、SOCKS5ハンドシェイク
  自体(特にCONNECT応答待ち、Tor circuit構築で数秒~十数秒かかりうる)は別途
  `SOCKS5_HANDSHAKE_TIMEOUT_SEC`(20秒)を設けた。
- `cli/main.c`に`get-socks-proxy`/`set-socks-proxy <enabled> <host> <port>`を追加。
- `tests/test_config_store.c`(新規)で、config_storeのget/set roundtrip・upsert確認に加え、
  ローカルに立てたモックSOCKS5サーバーへ`bm_peer_connector_connect_initial`から実際に
  CONNECTハンドシェイクさせて検証(実プロトコルバイト列のやり取りまで確認、宛先を実際に
  中継する必要は無いためモックで十分)。
- 実daemon・実Tor(ローカルの`tor`パッケージ、127.0.0.1:9050)での動作確認: CLIで
  `set-socks-proxy`した後にbitmessagedを再起動し、testnetの実ピアへ`(via SOCKS5)`経由で
  接続・version送信・addr受信までできることをログで確認済み。ctest 17件全通過。

### addrで教えられたホストのフィルタリング(2026-08-21)

backlogの優先順位付け(2026-08-21、ユーザーと合意): 1. addrホストフィルタリング、
2. getpubkey応答のスロットリング、3. 直接pubkey送信の自動再送、4. DoS上限の見直し、
5. chan仕様、6. 設定の動的リロード、の順で着手する。まず1番目を実施した。

`object_sync.c`に`is_routable_peer_address`を追加し、`addr`受信ハンドラでルーティング
不可能なアドレスを`bm_peer_manager_upsert_from_addr`する前に除外するようにした。除外対象:
IPv4は0.0.0.0/8・10.0.0.0/8・127.0.0.0/8(loopback)・169.254.0.0/16(link-local)・
172.16.0.0/12・192.168.0.0/16・224.0.0.0/4以降(multicast/reserved/broadcast)、IPv6は
未指定(::)・loopback(::1)・fc00::/7(ULA)・fe80::/10(link-local)・ff00::/8(multicast)。
port=0のエントリも合わせて除外する。動機は「addrで教えられた情報を鵜呑みにして内部
ネットワークへ接続を試みてしまう」ことの防止(SSRF的リスク)。`test_object_sync.c`の
addr受信テストへ、192.168.1.1宛のエントリを混ぜて「登録されない」ことを確認するcaseを
追加。実daemon・testnetでの動作確認では、実際に受信した2件のaddrは両方とも公開IPで
フィルタ対象0件だったこと(誤検知しないこと)をログで確認済み。ctest 17件全通過。

### getpubkey応答のスロットリング(2026-08-21)

backlog優先順位の2番目。同一宛先への短時間の連続getpubkey要求に対し、
`handle_incoming_getpubkey`(object_sync.c)が毎回PoWを計算し直してしまう問題
(正規のPoWを払われた場合の対策が無かった)への対応。

方式は「応答を都度作り直す」のではなく「直近作った応答をキャッシュして使い回す」
アプローチを取った。単純な時間ベースの拒否(冷却期間中は無視する)だと、別のノードが
直前に問い合わせた直後に来た正規の要求まで無応答になってしまい本末転倒なため、代わりに
「まだ有効期限内の応答objectがあればPoWを再計算せず、それをinv再broadcastするだけ」に
した。これなら正規の要求には常に応じつつ、2回目以降は実質無料(DB参照のみ)になる。

- `identity.db`に`self_pubkey_response_cache`テーブル(ripe BLOB PRIMARY KEY, object_hash
  BLOB, expires_time INTEGER)を追加(identity_store.c)。
- `core/pubkey_cache.c/h`に`bm_pubkey_cache_set_self_response`/
  `bm_pubkey_cache_get_self_response`を追加(pubkey_requestsと同じ「getpubkey関連の
  DB操作はpubkey_cache.cに置く」方針に合わせた)。
- `infra/object_sync.c`の`handle_incoming_getpubkey`を変更: identityを見つけた直後に
  必要なフィールド(ripe/pub_signing/pub_encryption/priv_signing等)をコピーして
  `OPENSSL_cleanse`で秘密鍵material(`id`)を即座に消去するようにした(従来はPoW計算
  ブロックの後で消去しており、鍵情報がPoW計算中も無駄にメモリ上に残っていた。副次的な
  改善)。その直後にキャッシュを確認し、有効な応答があればinv再broadcastのみで返す。
  無ければ従来通りbuild+PoW+object_pool.db挿入を行い、成功したらキャッシュへ記録する。
- `tests/test_getpubkey_automation.c`に、同じ宛先へ2回目のgetpubkey要求を送っても
  `object_pool.db`のpubkeyオブジェクト件数が増えない(=PoW再計算が発生しない)ことと、
  `self_pubkey_response_cache`に該当行が作られることを確認するcaseを追加。ctest 17件全通過
  (実ネットワーク難易度でのPoWタイミング確認は前回の28日TTL検証で既に実施済みのため、
  今回はキャッシュヒット時に新規PoWが走らないことのDB状態確認に留めた)。

### 直接pubkeyを渡した送信の自動再送(2026-08-21)

backlog優先順位の3番目。再送(`infra/object_sync.c`の`bm_object_sync_check_resends`)は
`to_pub_encryption=NULL`固定で`bm_send_pipeline_send_message`を呼ぶ(pubkey_cacheのみ参照
する設計)ため、`toPubEncryptionHex`を直接指定して送った場合はcacheに乗らず再送できない
という制約があった(2026-08-23発覚)。

修正は`core/send_pipeline.c`の`bm_send_pipeline_send_message`自身に実装した(当初
`api_server.c`のh_sendMessageだけに実装したが、`send_pipeline.c`を直接呼ぶ他の呼び出し元
[テスト等]にも効くよう、より根本のレイヤーへ移した)。呼び出し元が`to_pub_encryption`を
直接指定して送信に成功した時点で、pubkey_cacheにまだそのripeが登録されていなければ
自動でupsertする。`signing_pubkey`等`toPubEncryptionHex`だけでは分からない情報は既定値
(全0)で埋める(現状これらは受信pubkeyの検証用途にのみ使われ送信経路では未使用のため
実害は無い、`nonce_trials_per_byte`/`payload_length_extra_bytes`も0のままなら「宛先固有の
難易度は不明」として送信元自身の既定難易度にフォールバックする既存ロジックがそのまま働く)。
既にcacheへ登録済み(=実物のpubkeyオブジェクトから得られた、より質の高い情報)なら上書き
しない。

`tests/test_send_pipeline.c`・`tests/test_api_server.c`に、直接pubkey送信後にpubkey_cache
が自動で埋まっていることを確認するcaseを追加。`tests/test_resend.c`は元々あった「再送の
ためにcacheを事前に手動seedする」workaroundを削除し、自動upsertだけで再送が成功することを
確認する形に変更した。`test_send_pipeline.c`の既存の「cache空なら失敗する」検証は、
既に直接送信済みの宛先だとこの修正で自動的にcacheへ乗ってしまうため、まだ一度も送っていない
別の宛先を使うよう修正した。実daemon・CLI経由でも、送信前はpubkey_cache 0件・直接pubkey指定
でsend-messageした後は1件登録されることを確認済み。ctest 17件全通過。

### API portのBM_API_PORT対応(2026-08-21)

backlog番号無し、運用上の実害から緊急対応。`bitmessage-cli`は以前から接続先ポートを
`BM_API_PORT`環境変数で変更できたが、`bitmessaged`側にそれを上書きする手段が無く
非対称だった。実際に、knownnodes.datインポート(§11参照)によるpeer bootstrapを
バックグラウンドで動かし続けようとしたところ、両方とも既定の8442を使おうとして
ctestの`cli_integration`テストとポートが衝突する事態が発生した(2026-08-21、ユーザー
指摘により発覚)。

`main.c`で起動時に`BM_API_PORT`環境変数を読み、設定されていればapi_config.portへ反映する
ようにした(`BM_TESTNET`/`BM_NO_CONNECT`と同じ既存パターン)。起動時ログにもport番号を
追加した。`tests/test_cli_integration.sh`が自前で起動する`bitmessaged`もscratchポート
(18445、他のHTTPテストの18442-18444と同じ命名規則)を使うよう変更し、以後ctestが
バックグラウンドの8442常駐daemonと衝突しないようにした。実際にBM_API_PORT=19999で
起動したdaemonが8442の別daemonと同時にLISTENできることを確認済み。ctest 17件全通過
(バックグラウンドdaemonを止めずに実行して確認)。

### DoS上限の見直し(2026-08-21)

backlog優先順位の4番目。既存のDoS対策(`BM_MAX_INVENTORY_ITEMS`=50000件、
`BM_MAX_OBJECT_PAYLOAD_SIZE`=256KiB、JSON-RPCの`MAX_REQUEST_SIZE`=1MiB)を洗い出す中で、
より根本的な穴を発見した: P2Pメッセージの共通ヘッダ(`infra/protocol.h`の`bm_message`)の
`length`フィールドは32bit(理論上最大約4GiB)だが、`infra/network.c`の受信バッファは
その値をそのまま信用してrealloc doublingで追いつこうとする作りだった。悪意あるpeerが
巨大な`length`を申告するだけで、実データが1byteも届く前から受信側に無制限のメモリ確保を
強制できる(既存の`BM_MAX_OBJECT_PAYLOAD_SIZE`チェックは`handle_object`内、つまり
バッファ確保・full受信が終わった"後"にしか働かず、確保自体は防げていなかった)。

対応: `infra/protocol.h`に`BM_MAX_MESSAGE_LENGTH`(4MiB。この実装で正当に流通しうる
最大メッセージ[addr、`BM_MAX_INVENTORY_ITEMS`=50000件で約1.9MiB]に十分な余裕を持たせた値)
を追加し、`bm_parse_message`がヘッダ受信直後(実データを待つ前)にlengthを検査、超過して
いれば新設した`BM_PARSE_MESSAGE_TOO_LARGE`を返すようにした。呼び出し側
(`bm_network_handle_readable`)はこれを検知したら resync を試みずに即座に接続を切断する
(巨大な偽データを1byteずつresyncしようとすること自体もCPU消費のDoSになりうるため)。
さらに`infra/network.c`の受信バッファのdoubling処理自体にも上限(`MAX_RECV_BUFFER_SIZE`
=`2*(ヘッダ+BM_MAX_MESSAGE_LENGTH)`)を設け、二重に防御した。

`tests/test_network_testnet.c`に、上限超過のlength申告(ヘッダ24byteのみ、payload未着の
状態)が即座に`BM_PARSE_MESSAGE_TOO_LARGE`で拒否されること・ちょうど上限値なら
`BM_PARSE_INCOMPLETE`(正常系)のままであることを確認するcaseを追加。実daemon・実testnet
接続でも、version/verack/addr受信を含む通常のハンドシェイクが引き続き正常に動作すること
(誤検知なし)を確認済み。ctest 17件全通過。

### chan仕様(2026-08-21)

backlog優先順位の5番目。chan(PyBitmessageの私設グループチャンネル相当)は、暗号的には
通常のdeterministic addressと全く同じもの: 同じpassphraseから`bm_address_generate_
deterministic`を呼べば誰でも同一のアドレス・鍵ペアを導出できる(§7.1参照)。「参加」とは
ローカルでその鍵を導出してkeyringへ登録するだけの操作であり、新規のワイヤープロトコルは
不要だと判明した。既に`identities`テーブルに`is_chan`列が存在したが(§7.1設計時点で
先回りして用意されていた)、これを立てる経路が無く常に0固定だった。

- `core/api_server.c`に`joinChan(passphrase, label, storePassphrase)`を追加。
  `createDeterministicAddress`を固定パラメータ(addressVersion=4, stream=1,
  ripeNullBytes=1)で呼んだ上で`is_chan=1`を立てる薄いラッパー。同じpassphraseで複数の
  クライアントが呼べば全員が同じアドレスへ「join」したことになる。
  `core/identity_store.c`に`bm_identity_store_set_is_chan`、`core/keyring.c`に
  それを呼ぶ`bm_keyring_mark_as_chan`を追加(keyring.cは既存の方針通りidentity_store.c
  経由でのみDBを触る)。`listAddresses`の応答にも`isChan`を追加した。
- chanへの投稿は`sendMessage(fromAddress=chanAddress, toAddress=chanAddress, ...)`
  (自分自身宛の送信)で行う設計とした。これを動かすため`core/send_pipeline.c`の
  `bm_send_pipeline_send_message`に、`to_address`が`from_address`自身(=to_ripeが
  from_idのripeと一致)かつ`to_pub_encryption`省略時、pubkey_cacheを参照せず
  `from_id`自身の`pub_encryption`を直接使うfallbackを追加した(自分の鍵は既に手元にある
  ため、cacheに登録されている必要が無い)。
- 受信側は`core/trial_decrypt.c`が既にkeyring中の全identityを試す設計になっているため、
  chan用の鍵をunlockしてさえいれば新規の受信処理は一切不要だった(他メンバーの投稿も
  自動的に復号されinboxへ入る)。
- `cli/main.c`に`join-chan <passphrase> <label> <storePassphrase>`を追加。
- `tests/test_chan.c`(新規)で、独立した2回の`bm_address_generate_deterministic`呼び出し
  (2つの別々のidentity.db/keyring、"メンバーA"「メンバーB"を模す)が同一アドレス・鍵に
  なること、メンバーAが自分自身宛にtoPubEncryptionHex省略でsendMessageできること、
  メンバーBがその投稿をtrial_decryptで復号できること(実際のグループチャット動作)を
  end-to-endで確認。実daemon・CLI経由でも`join-chan`→`list-addresses`(isChan:true)→
  `unlock`→`send-message`(自分自身宛)の一連の流れが動作することを確認済み。
  ctest 18件全通過。

### 設定変更の動的リロード(2026-08-21)

backlog優先順位の6番目、これで洗い出していた項目は全て完了した。SOCKS5プロキシ設定
(config.db)は永続化されていたが、`peer_connector_thread`が起動時に読んだ値の
スナップショットを生存期間中ずっと使い続ける作りだったため、`setSocksProxy`での変更は
daemon再起動まで反映されなかった。

対応方針は「専用のreload機構(シグナルハンドラや別スレッド等)を新設する」のではなく、
既存の再接続ポーリングループ(`peer_connector_thread`、既定30秒間隔で
`bm_peer_connector_connect_initial`を呼び直す設計、§1.1参照)にただ乗りする形にした。
`bm_peer_connector_config`の`socks_proxy`(固定スナップショットへのポインタ)フィールドを
`config_db`(sqlite3ハンドル)に置き換え、`bm_peer_connector_connect_initial`が呼ばれる
たびに`bm_config_store_get_socks_proxy`で都度読み直すようにした。これにより、
`setSocksProxy`での変更はdaemon再起動なしで次の再接続サイクル(既定30秒以内)から
反映されるようになった。`main.c`は起動時ログ表示用に1回読むだけで、実際に
`peer_connector_thread`が使う値の受け渡しは`config_db`ハンドルそのものになった。

`tests/test_config_store.c`のSOCKS5経由接続テストも、`struct`に直接値を詰める代わりに
`bm_config_store_set_socks_proxy`でconfig.dbへ永続化してから`bm_peer_connector_config.
config_db`経由で渡す形に変更し、実際の動的リロード経路そのものを検証するようにした。
実daemon(testnet)でも、起動直後は直結で接続し、稼働中に`set-socks-proxy`した後
(daemon再起動なし)、次の再接続サイクルで`(via SOCKS5)`表示に切り替わることをログで
確認済み。ctest 18件全通過。

### outbound Tor経路の強化・検証(2026-08-21)

backlog完了後、ユーザーからの追加要望。2点調査・対応した。

**knownnodesフルスキャンの要否について**: `peer_connector_connect_initial`は「空いている
スロット分だけ次の候補を試す」設計のため、`max_outbound`件の接続を維持できている間は
新しい候補を試しに行かない。4400件超のknownnodes_2020_importを抱えていても全件を
積極的に走査する仕組みは無いが、意図的にこの設計を維持する判断をした: 生きているpeerを
見つける本来の仕組みは`addr`伝播であり、静的な過去データを総なめにすることではないため
(gossip型ネットワークでは接続数もそこまで多く要らない)。フルスキャンが要る場面は
「今すぐ4400件がどれだけ生きてるか知りたい」という一回限りの調査目的だけであり、
それは常設コードではなく都度スクリプトで行う方が適切と判断し、実装しなかった。

**onion peer探索の可否について**: PyBitmessageの実際のワイヤーフォーマット(`bmproto.py`
の`decode_payload_node`、GitHub上のv0.6ソースで確認)を調べたところ、`addr`メッセージの
16byte IPフィールドはOnionCat方式(`fd87:d87e:eb43::/48`プレフィックス + 残り80bit)で
onionアドレスを表現できるが、これは80bit(10byte)しか余裕が無くv2 onion(80bit鍵)専用の
仕組みで、v3 onion(2021年以降の標準、32byte ed25519鍵ベース)を表現する術が無いと判明した。
Tor自体が2021年にv2 onion serviceを完全に廃止済みのため、`addr`経由でのonion peer探索は
現在の実ネットワーク上では原理的に無価値(生きているv3 onion peerを表現する手段が
プロトコルに存在しない)と結論し、実装を見送った。`knownnodes.py`にもonion bootstrap
シードはハードコードされていない(自分自身のonionhostname申告機能のみ)ことも確認した。

上記調査の副産物として、SOCKS5経由接続の失敗診断を強化した: `infra/peer_connector.c`の
`socks5_connect`に、どの段階(proxy到達不能/greeting拒否/CONNECT失敗)で失敗したかを
`[peer_connector] socks5: ...`のログとして出力するようにし、CONNECT失敗時はRFC1928の
REPコード(host unreachable/connection refused等)を人間可読な文字列に変換して出力する
ようにした。実daemon・実Torで、(1)正常系(実testnetノードへSOCKS5経由で成功、ログに
ノイズ無し)、(2)異常系(プロキシ自体が到達不能なポートを指定、クラッシュ・ハングせず
診断ログを出して次の候補へ継続すること)の両方を確認済み。ctest 18件全通過(既存挙動に
変更なし、診断ログの追加のみ)。

### v3 onionピア探索(OBJECT_ONIONPEER)の実装(2026-08-21)

上記調査で「onion peer探索はaddr/versionメッセージ経由では原理的に無価値」と結論したが、
ユーザーの指摘(自身の2020年当時のkeys.datに残っていた`onionhostname`設定を手がかりに
`knownnodes.py`を辿るよう指示)を受けて再調査した結果、これは誤りだったと判明した。

PyBitmessage実ソース(`class_singleWorker.py`の`sendOnionPeerObj`、`class_objectProcessor.py`
の`processonion`、`protocol.py`)を精読すると、`OBJECT_ONIONPEER`(`0x746f72`、ASCII "tor")
という**専用のobject type**が存在し、これはaddr/versionメッセージの16byte固定node encoding
とは別経路であることが分かった。version messageのnode encodingだけが`encodeHost(host)[:16]`
で明示的に16byteへ切り詰めているのに対し、onionpeer objectの`objectPayload = encodeVarint
(peer.port) + protocol.encodeHost(peer.host)`にはこの切り詰めが無く、objectペイロードの
残り全体を可変長のホストバイト列として使う。受信側`processonion`も`checkIPAddress`へ
残りバイト全部を渡すため、v2(10byte→16文字)でもv3(35byte→56文字)でも、base32
encode/decodeがそのまま正しく往復する。つまりこのobject typeは`getpubkey`/`pubkey`/`msg`/
`broadcast`と同じ`inv`/`object`のPoW付き配信に乗る形で、実際に生きているv3 onionピアを
ネットワークから発見できる設計だった。

自分自身のonionピア情報をannounceする送信側(`sendOnionPeerObj`)は、inbound Tor
(hidden service)自体がスコープ外のため今回は実装しない。**受信側のみ**実装した:

- `infra/object.h`に`BM_OBJECT_ONIONPEER = 0x746f72`を追加。
- `infra/object_sync.c`に`base32_encode_lower`(RFC4648小文字・パディング無し、v2=10byte
  →16文字/v3=35byte→56文字はどちらも5bit境界にきれいに乗るため実装は単純)と
  `handle_incoming_onionpeer`を追加。ワイヤーフォーマット(varint(port) ||
  0xfd87d87eeb43[OnionCat prefix] || onion鍵バイト列)をパースし、prefix+35byte
  (v3)の場合のみ`peers.db`へ登録する(v2の10byteはTorが2021年に廃止済みで無価値のため
  無視)。`handle_object`の既存dispatch chain(PoW検証・重複排除・object_pool.db挿入・
  inv再broadcastは全object type共通で既に適用済み)に新しいtype分岐を追加するだけで済んだ。
- `infra/peer_manager.c/h`の`bm_peer_manager_upsert_from_addr`を`bm_peer_manager_upsert_
  learned`に一般化し(`source`を引数化)、addrメッセージ由来(`'addr_msg'`)とonionpeer
  object由来(`'onionpeer_obj'`)を両方この1関数で扱えるようにした。
- `tests/test_object_sync.c`に、ユーザー自身の実在した(2020年当時の)v3 onionアドレス
  `f4bouzoomfsvlcx4bfrj36zkcecbr6xlp4np4v7v4gdbgaebrvgfd3id.onion`を使い、実際のワイヤー
  フォーマット通りに組み立てた実PoW付きobjectを受信させ、`peers.db`へ`source=
  'onionpeer_obj'`で正しく登録されることを確認するcaseを追加(base32エンコード/デコードの
  往復も含めて実データで検証済み)。実daemon(testnet)でも60秒間の通常稼働(3peer接続・
  version/addr処理)に新しいdispatch分岐が悪影響を与えないことを確認済み(この短時間の
  試行では実際のonionpeer objectには遭遇しなかったが、実装自体は上記の実データテストで
  検証済み)。ctest 18件全通過。

### user agent文字列のバージョン化石化を修正(2026-08-21)

`main.c`のP2P version messageに載せるuser agent文字列(`BM_USER_AGENT`)が
`"/bitmessage-c:0.1.0/"`のままハードコードされており、v1.0.0タグ後もずっと更新されて
いなかった(ユーザー指摘)。再発防止のため、ハードコード文字列を都度手で直す代わりに、
`src/CMakeLists.txt`で`target_compile_definitions(bitmessaged PRIVATE
BM_PROJECT_VERSION="${PROJECT_VERSION}")`によりルートの`project(bitmessage VERSION ...)`
を単一の情報源として注入し、`main.c`側は`#define BM_USER_AGENT "/bitmessage-c:"
BM_PROJECT_VERSION "/"`と組み立てるだけにした。以後はCMakeLists.txtのバージョンを
上げれば自動的に反映される。実バイナリに`/bitmessage-c:1.0.0/`が正しく埋め込まれること
を`strings`で確認、実daemon(testnet)での動作にも影響が無いことを確認済み。ctest 18件全通過。

### peers.dbの低rating/古いノードのクリーンアップ(2026-08-21)

`bm_peer_manager_record_result`はratingを-1.0で下限クランプするだけで、`hosts`テーブルから
行を削除する処理が無いことが判明した(ユーザー指摘、検索した限りDELETE文が1つも無いことを
確認済み)。rating DESC順で候補を選ぶ設計上、死んだノードが新しい候補の選定を直接妨げることは
無いが(常に一番下に沈む)、DB内に永久に残り続ける。

PyBitmessage(`network/knownnodes.py`)の実装を参考にした: `singleCleaner`スレッドが5分間隔
(`cycleLength=300`)で`cleanupKnownNodes`を呼び、(1) `lastseen`から28日(2419200秒)経過した
ノードはrating問わず無条件削除、(2) `lastseen`から3時間(10800秒)経過かつ
`rating <= knownNodesForgetRating`(定数`-0.5`)のノードを削除、(3) streamごとに最低1ノードは
残す、という方式だった。

この実装では同じ2条件(28日/3時間+rating<=-0.5)を`peer_manager.c`に
`bm_peer_manager_cleanup(db, now)`として追加した。「streamごとに最低1ノードは残す」安全弁は
実装していない: `bm_peer_manager_seed_bootstrap`が`hosts`テーブル完全空の場合のみ既定シードを
再投入する既存の仕組みが、テーブル全体が空になった場合の実質的な安全弁として機能するため
(そもそもv1スコープでは実質streamは1のみで、複数streamの共存自体を想定していない)。
`bm_peer_manager_cleanup`は§11設定変更の動的リロードと同じパターンで
`bm_peer_connector_connect_initial`(`bm_peer_manager_seed_bootstrap`の直前、テーブルが
空になった場合に同じ呼び出し内で再シードされるように)から毎回(再接続サイクルの既定30秒
間隔)呼ばれる。

`tests/test_network_testnet.c`に、28日超・3時間超+rating<=-0.5・境界値未満・新しい低rating・
新しい高rating、の5パターンを仕込んで削除対象が正確に2件だけになることを確認するcaseを
追加。実daemonでも劇的な効果を確認できた: 稼働中のbootstrap daemon(4484件、うち9件の死んだ
mainnetシード全てrating=-1.0・4422件のknownnodes_2020インポートの大半が組織的な再試行で
既にrating<=-0.5まで減衰済み)を新バイナリで再起動したところ、起動直後の1サイクルで
4431件が一括削除され、59件(生存確認済み3件+新鮮なaddr伝播56件)まで整理された。その後も
生存ノードへの接続・addr受信が正常に継続することを確認済み。ctest 18件全通過。

### 手動peer追加(`addPeer`)と「開発者が確認した身元不明のノード」リストの実装(2026-08-21)

mainnetシード9件全滅への一連の対応(addr永続化・SOCKS5・knownnodes_2020インポート・
OBJECT_ONIONPEER)を経て、実際に3件の生存ノードを発見できた。しかしこれは**このユーザーの
2020年当時のバックアップという偶然のデータ**に依存した復旧であり、バックアップを持たない
新規インストールでは全く再現できない(公式seedが全滅している以上、addr伝播も
OBJECT_ONIONPEER発見も「既に1本繋がっていること」が前提の仕組みのため、最初の1本を
繋ぐ手段自体が無い)ことが判明した。

対策として2つを検討した:
1. 発見した3件の生存ノードを`peer_manager.c`のハードコードされた公式seed一覧へ直接混ぜる
2. `addPeer`(ユーザーが個別に保証したノードを手動追加するAPI/CLI)を実装する

しかし1点、ユーザーから重要な指摘があった: 「発見した3件の運営者が誰なのか、いつまで
稼働し続けるのかは全く分からない」という点で、これはPyBitmessageのGitHub issue #2310で
「身元不明の匿名申告アドレスリストは信用できない」という理由により開発者が拒否した状況と
本質的に同じ構造の問題だった(唯一の違いは、今回は実際に自分たちでP2Pハンドシェイクまで
確認したという点だが、運営者の身元・永続性が不明という核心部分は変わらない)。

この緊張関係を解決するため、「無条件にハードコードされた公式seedと同格として紛れ込ませる」
のではなく、**出自と限界を明記した別ファイル(`seeds/observed_nodes.txt`)として同梱し、
別のsource ('observed_seed')でpeers.dbへ登録する**という設計にした:

- `seeds/observed_nodes.txt`(新規): 3件のIP:portと、冒頭に「2026-08-21にメンテナが直接
  ハンドシェイクして生存確認しただけで、運営者の身元・永続性は保証しない」という注意書きを
  記載した平文ファイル。`core/peer_manager.c`の`bm_peer_manager_load_observed_nodes(db, path)`
  が読み込む(`#`コメント・空行を無視、1行「ip port」形式)。ファイルが無くても非致命的
  (配布形態によっては同梱しない選択肢も残す)。`bm_peer_manager_seed_bootstrap`が
  mainnet時のみ、公式seed投入と同じ「hostsテーブルが完全に空の場合だけ」というゲートで
  自動的に読み込むようにした。
- **peer_manager.c/hをinfra層からcore層へ移動した**: `addPeer`をAPI経由(`core/api_server.c`)
  で提供するには、api_server.cがpeer_manager.cの機能を呼べる必要があるが、既存の
  「infra→coreの片方向依存(circular importを避ける)」方針(§1.2)により、core層の
  api_server.cがinfra層のpeer_manager.cを直接呼ぶことはできなかった。peer_manager.c自体は
  実際にはsqlite3操作のみでinfra固有の依存(ソケット・P2Pメッセージパース等)が無かった
  ため、config_store.cと同じ判断(§11「outbound Tor経路の強化」参照)でcore層へ移動する
  のが正しい解決だった。`src/infra/peer_manager.c/h` → `src/core/peer_manager.c/h`、
  `src/infra/CMakeLists.txt`から削除・`src/core/CMakeLists.txt`へ追加、6ファイルの
  includeパスを更新。
- `core/api_server.c`に`addPeer(ipAddress, port, stream?)`を追加。
  `bm_peer_manager_upsert_learned`をsource='manual'で呼ぶ薄いラッパーで、rating=0.0
  からスタートする(手動追加だからといって無条件に信用するわけではなく、他の候補と同じく
  実際の接続実績でratingを積み上げていく設計を維持)。`bm_api_server_config`に
  `peers_db`フィールド(NULL可)を追加。
- `cli/main.c`に`add-peer <ipAddress> <port> [stream]`を追加。

`tests/test_network_testnet.c`に`bm_peer_manager_load_observed_nodes`(コメント・空行・
不正な行の無視、有効な行だけの登録)の、`tests/test_api_server.c`に`addPeer`(正常系・
不正なport)のcaseを追加。実daemonで新規インストールを模した検証(空のpeers.db、
`seeds/observed_nodes.txt`を同梱)を行い、公式seed9件は全滅する一方、observed_nodes.txt
由来の3件全てに実際に接続できることを確認した(「新規インストールでもmainnetへ繋がれる」
という当初の目的を実証)。`add-peer` CLIコマンドの実daemonでの動作、不正な値の拒否も
確認済み。ctest 18件全通過。

### 「failed to send getdata」の原因調査・修正(2026-08-21)

バックグラウンドで動かし続けていたbootstrap daemonのログに`[object_sync] failed to send
getdata`が繰り返し出ていることにユーザーが気づき、調査した。

原因は非blockingソケットへの部分書き込み(short write)を考慮していなかったこと。
`peer_connector.c`の`connect_with_timeout`は接続確立後もソケットをO_NONBLOCKのまま
epollへ渡す設計(§1参照)だが、`infra/object_sync.c`のgetdata送信・object応答送信、
`infra/peer_registry.c`のinv broadcast、`infra/network.c`のverack/pong返信・version送信は
いずれも単発の`write()`を呼び、戻り値が要求バイト数と一致しなければ即座に「失敗」として
扱い黙ってデータを捨てていた。非blockingソケットのwrite()は、送信バッファが一時的に
埋まっていると短い書き込みや`EAGAIN`を返すのが正常な挙動であり、1回のwrite()で全部
送れることを仮定してはいけない(単発の`write()`呼び出しはその前提に反していた)。

`infra/network.c`に`bm_network_write_all(fd, data, len, timeout_sec)`を追加し、
EAGAIN/EWOULDBLOCK時は`select()`で書き込み可能になるのを待ちながらループする実装にした
(peer_connector.cのSOCKS5クライアント実装で既に使っていた`socks5_send_all`と同じパターン)。
タイムアウトは呼び出し元のスレッド文脈によって使い分ける: `network_epoll_thread`
(単一の共有スレッドが全接続のディスパッチを直列に処理する設計)上で呼ばれるもの
(verack/pong返信・object_sync.cのgetdata/object応答・peer_registry.cのinv broadcast)は
`BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS`(2秒、詰まったpeer1本が他の全接続の処理を
長時間ブロックしないため)、`peer_connector_thread`自身のスレッド上で呼ばれる
`bm_post_version`は`BM_NETWORK_WRITE_TIMEOUT_LONG_SECONDS`(5秒、他接続を巻き込まないため)。

`peer_registry.c`のinv broadcastは元々`reg->lock`を持ったまま全peerへ順にwrite()していたが、
ブロッキング呼び出しに変えるとロック保持時間が長くなり他スレッドのregistry操作を止めて
しまう。単純にfdだけコピーしてロックを解放する案は、書き込み前に元の接続がepoll thread側で
close()されfd番号が別の用途に再利用された場合に誤った相手へ書き込む競合を生むため、
ロックを持っている間に`dup()`した複製fdを使うことでこの競合を避けつつロックを早期解放
できるようにした。

`tests/test_network_testnet.c`に`bm_network_write_all`専用のテストを追加した:
1MiBペイロードをnon-blocking socketpairへ送り、受信側をわざと間欠的に(2msずつ待ちながら)
読ませることで実際に複数回のEAGAINを経験させ、最終的にバイト単位で欠落・破損なく
送り切れることを確認するcase、および受信側が全く読まない場合に短いタイムアウトで
ちゃんと諦める(無限に待たない)ことを確認するcaseの2つ。実daemon(bootstrap daemon)で
修正前後を比較し、修正後は約85秒の稼働で新規の「failed to send」発生が0件だったことを
確認した(修正前に累積していた27件は全て過去の実行分)。ctest 18件全通過。

### inbound接続 Stage 1: 汎用TCP listen/accept + 双方向handshake(2026-08-21)

inbound接続対応を2段階に分けて実装することにした。Stage 1は本項目、Tor非依存の
一般的なTCP listen/accept + プロトコル上のhandshake。Stage 2(Tor ControlPortを使った
hidden service自動作成・鍵永続化)は未着手で、次回以降に着手する。

開発者の自宅回線がCGNAT相当でグローバルIPへの直接listenができないため、外部からの
到達性は最終的にTor hidden serviceのフォワーディングに頼る前提(§8で最初にinbound見送りと
決めた理由もこれ)。そのためStage 1は`bind_address`に常に`127.0.0.1`のみを渡す設計とし、
グローバルIPへのbindは行わない(意味がないため)。Stage 1自体はTor固有のコードを一切含まず、
プレーンなloopback TCPだけで決定的にテストできる。

**実装した内容:**

- `enum bm_fd_type`に`BM_FD_LISTEN_SOCKET`を追加(`network.h`)。既存の`BM_FD_SERVER_SOCKET`
  (accept()された側、これまでコード中で未使用だった)を「相手からの接続」の意味で使うことにし、
  `BM_FD_CLIENT_SOCKET`(自分からconnect()した接続)と役割を明確に分離した。
- `bm_network_listen(bind_address, port)`(`network.c`)。`getaddrinfo`+`bind`+`listen`
  (backlog 16)+`SO_REUSEADDR`+`O_NONBLOCK`、`peer_connector.c`の`connect_with_timeout`と
  同じスタイル。
- `bm_fd_data_new`の既存バグを修正: 無条件に`getpeername()`を呼んでいたため、listen中の
  ソケット(相手がいないので`ENOTCONN`になる)を渡すと必ずNULLを返して失敗していた。
  `type == BM_FD_LISTEN_SOCKET`の場合は`getpeername()`をスキップするよう修正。
- `network.c`に`handle_accept`を追加。`accept()`をEAGAINになるまでループし、
  (Linuxでは`accept()`されたfdはlistenソケットの`O_NONBLOCK`を継承しないため)各fdへ
  個別に`O_NONBLOCK`を設定、`bm_fd_data_new(BM_FD_SERVER_SOCKET, ...)`でepollへ登録、
  `bm_peer_registry_add`(registryがNULLでなければ)する。`bm_network_epoll_thread`は
  readableになった接続の`type`が`BM_FD_LISTEN_SOCKET`ならこちらを呼ぶよう分岐した。
- handshakeの非対称性を修正: outboundは接続確立直後に`peer_connector.c`が自分から
  versionを送信済みなので、相手のversionを受け取った時点ではverackを返すだけでよい。
  一方inboundは自分からversionを送っていないため、相手のversionを受け取ったらverackに
  加えて自分自身のversionも送り返す必要がある(そうしないと相手が自分を認識できない)。
  `bm_object_sync_ctx`に`user_agent`フィールドを追加し(`ctx_init`の8番目の引数)、
  `object_sync.c`の`"version"`分岐で`conn->type == BM_FD_SERVER_SOCKET`かつ
  `ctx->user_agent != NULL`の場合のみ`bm_post_version`を追加送信するようにした。
- `main.c`: 環境変数`BM_INBOUND_PORT`が設定されている場合のみ`127.0.0.1:<port>`でlistenし
  epollへ登録する。未設定時はinbound無効(v1のoutbound専用動作を変えないための既定)。

**テスト:** `tests/test_inbound.c`を新規追加。実ソケット(loopback TCP)を使い、
`bm_network_listen`→クライアントconnect→`bm_post_version`→`accept()`→
`bm_object_sync_dispatch`→クライアント側でverack・versionの両方を受信、の一連を検証する。

作成時に見つけたテストヘルパーのバグ: `read_one_message(fd)`は呼び出しごとに
ローカル/スタックバッファを使い捨てる設計だったため、1回の`read()`にverack+versionの
2メッセージがまとまって届くと2個目のバイト列を静かに読み捨ててしまい、2回目の
`read_one_message`呼び出しが永遠にブロックする(`ctest`がハングし、手動で
プロセスをkillして原因を特定した)。fdをまたいでバッファとoffsetを保持する
`struct msg_reader`+`reader_next_message`を追加し、1回の受信に複数メッセージが
含まれていても取りこぼさないようにして解消した。本番コードの
`bm_network_handle_readable`は元々この問題を正しく扱っている(受信バッファに
残った未消費バイトを次回に持ち越す設計)ため、production側に同種のバグはない。

**実daemonでのスモークテスト:** 独立した一時ディレクトリで`BM_INBOUND_PORT`と
`BM_NO_CONNECT=1`を指定して`bitmessaged`を起動し(バックグラウンドで動かし続けている
bootstrap daemonのDB/ポートとは完全に分離)、単純なPythonスクリプトから生TCPで
versionメッセージを送信。ログに`[network] accepted inbound connection`
`[object_sync] version: ...`が出て、クライアント側にverack(24byte)とversion(103byte)の
両方が返ってくることを確認した。

**注記:** 開発者はこの実装の動作確認のため、自身の環境で実際のTor hidden service
(静的torrc設定)を用意して`127.0.0.1:8444`へフォワーディングしているが、その
onionアドレス自体はユーザーの明示的な指示によりこのファイル・コミットメッセージ・
コード中を含め、一切の公開ドキュメントに記載しない。

### inbound接続 Stage 2: Tor ControlPort連携によるhidden service自動作成(2026-08-22)

Stage 1(上記)の上に、Tor Control Protocol(control-spec.txt)経由でhidden serviceを
自動作成・再利用する層を実装した。`src/infra/tor_control.c`/`.h`。

**ControlPortへの到達方法(TCP/Unixドメインソケット両対応):** ユーザーの環境で確認したところ、
Debian/Ubuntu系のtorパッケージは既定でControlPortをUnixドメインソケット
(`/run/tor/control`、Cookie認証ファイルは`/run/tor/control.authcookie`)としてのみ有効化しており、
TCP(既定`127.0.0.1:9051`)は無効だった。一方Tor Browser Bundleや手動設定・他OS(特にWindows)では
TCPが一般的なため、両対応にした: `bm_tor_control_connect_and_authenticate`はまずUnixソケット
パス(既定`/run/tor/control`、`BM_TOR_CONTROL_SOCKET`で上書き可)への接続を試み、失敗したら
TCP(既定`127.0.0.1:9051`、`BM_TOR_CONTROL_HOST`/`BM_TOR_CONTROL_PORT`で上書き可)へフォール
バックする。認証はCookie認証のみ対応(`PROTOCOLINFO`で`COOKIEFILE`パスを取得し、その内容を
16進数化して`AUTHENTICATE`する)。SAFECOOKIEのHMACチャレンジ/レスポンスは実装していない
(ControlPortが同一ホスト上にあり、Cookieファイルを読めること自体が既にローカルの信頼された
立場の証明になっているため、SAFECOOKIEが本来防ぎたい「ネットワーク越しの盗聴」はここでは
当てはまらないと判断)。HASHEDPASSWORDのみの構成(Cookie認証が無効化された設定)は
v1のスコープ外として非対応。

ちなみにこの環境では`teruteru`ユーザーが既に`debian-tor`グループに所属していたため、
sudoでの`/etc/tor/torrc`編集やtorサービス再起動をせずに、システムのTorデーモンへ実際に
接続してテストできた。

**ADD_ONIONの`Flags=Detach`は意図的に使わない:** 実装当初`Flags=Detach`を付けて実装したが、
実Tor環境で検証したところ、「control接続を閉じてもhidden serviceは残り続ける」ため、
永続化した鍵を使って次回起動時に再度`ADD_ONION`すると`550 Onion address collision`で
失敗することが分かった(実際にこのエラーを再現させてから設計を修正した)。
`Flags=Detach`を外し、代わりにTor ControlPortへの接続(fd)をbitmessagedプロセスの生存期間
ずっと開いたままにする設計にした(`listen_conn`や`object_sync_ctx`と同じ、main()が
sigwaitでブロックしている間ずっと生存するスタック変数`tor_control_fd`)。こうすると
正常終了・クラッシュのどちらでもプロセス終了時にOSがfdを閉じ、Torがcontrol接続の切断を
検知して自動的にhidden serviceを削除してくれるため、次回起動時に同じ永続化済みの鍵で
`ADD_ONION`しても衝突しない。

**鍵の永続化:** `core/config_store.c`に`tor_onion`テーブル(`private_key`列1つ、socks_proxy
テーブルと同じ1行upsertパターン)を追加。`bm_config_store_get_tor_onion_key`/
`bm_config_store_set_tor_onion_key`。初回起動時は`ADD_ONION NEW:ED25519-V3`で新規鍵生成し、
返ってきた`PrivateKey=ED25519-V3:...`をconfig.dbへ保存する。2回目以降の起動では保存済みの
鍵を`ADD_ONION`にそのまま渡すことで、Torが同じ鍵から決定的に同じonionアドレスを再現する
(control-spec準拠。鍵を再利用する場合Torは`ServiceID`は返すが`PrivateKey`行は返さない)。

**main.cへの配線:** `BM_TOR_CONTROL=1`(既存のBM_TESTNET/BM_NO_CONNECT等と同じ環境変数
opt-inパターン)かつStage 1のinbound listenが成功している場合のみ試みる(転送先の
ローカルポートが無ければADD_ONIONする意味が無いため)。外部から見えるポート番号は
Bitmessageの慣習で`BM_TOR_VIRTUAL_PORT`(既定8444)。失敗時は診断ログを出すだけで
daemon自体は起動を続ける(SOCKS5プロキシ等、他の「あれば使う」外部依存と同じ非fatal方針)。

**テスト:** `tests/test_tor_control.c`を追加。実環境のTor ControlPortに接続できる場合のみ
実際に`ADD_ONION`を発行して検証し(接続できない環境ではSKIP相当でEXIT_SUCCESSする)、
このマシンでは実際にTorに接続して: (1)新規鍵での`ADD_ONION`が有効な`.onion`アドレスと
`ED25519-V3:`形式の鍵を返すこと、(2)control接続を閉じてから別の接続で同じ鍵を渡すと
同一のonionアドレスが決定的に再現されること、を確認した。

**実daemonでのスモークテスト:** 独立した一時ディレクトリ(既存のbootstrap daemonとは
完全に分離)で`BM_INBOUND_PORT`+`BM_TOR_CONTROL=1`を指定して`bitmessaged`を2回連続で
起動し、1回目・2回目とも同一のonionアドレスが`[tor_control] hidden service ready: ...`
ログに出ること、`550 Onion address collision`等のエラーが出ないことを確認した。ctest
20件(新規`tor_control`含む)全通過。

### OBJECT_ONIONPEERの自己announce送信側(2026-08-22)

Stage 2までで自分のonionアドレスは手に入るようになったので、それを`OBJECT_ONIONPEER`
objectとしてネットワークへ告知する送信側(PyBitmessageの`sendOnionPeerObj`相当)を実装した。
受信側(`handle_incoming_onionpeer`、peers.dbへ学習ピアとして登録)は既存実装済みだった。

**`core/message_builder.c`に`bm_build_onionpeer`を追加:** 他のbuild関数(`bm_build_getpubkey`
等)と同じ「PoW前のペイロードを返す」規約に揃えた。onion_addressは"xxxx.onion"(v3、56文字+
".onion")形式の文字列で受け取り、base32部分をデコードして35byte(ed25519公開鍵32byte+
チェックサム2byte+バージョン1byte)へ戻し、OnionCat prefix(`0xfd87d87eeb43`)を前置した
ホストバイト列として埋め込む。これは`infra/object_sync.c`の受信側`handle_incoming_onionpeer`
(base32エンコードで文字列へ戻す処理)のちょうど逆変換。base32デコーダはmessage_builder.c
(core層)に新規実装した(object_sync.c、infra層のエンコーダとは層が違うため共有できず、
element単体としては小さいので許容)。

**`infra/object_sync.c`に`bm_object_sync_announce_onion_peer`を追加:** `handle_incoming_
getpubkey`の自己pubkey応答生成と同じ「build→PoW→object_pool.dbへ挿入→peer_registry経由で
inv broadcast(除外無し)」パターン。誰宛でもない匿名objectなのでPoW難易度はack objectと
同じくネットワーク既定の最低値(1000,1000)を使う。TTLは当初pubkeyと同じ28日にしていたが、
テストでPoW計算に非常に時間がかかった(28日という長いttlがそのままbm_pow_get_targetの
難易度に跳ね返るため)ため、恒久的なアイデンティティ情報ではなく一時的なピア発見情報である
ことを踏まえ、api_server.cのgetpubkey要求と同じ2日に短縮した(この方がdaemon起動時の
PoW計算負荷も軽い)。

**`main.c`への配線:** Stage 2のADD_ONION成功直後に1回呼ぶ。この時点ではpeer_connector_thread
がまだ起動しておらずpeer_registryは空なので、inv broadcast自体は実質no-opになるが、
object_pool.dbへは登録されるため以後getdataで配れる状態にはなる(新規接続時に全inv同期を
行う仕組みはこの実装に無く、これは他の自己生成object種別と共通の既知の制約であり
onionpeer固有の問題ではない)。

**テスト:** `tests/test_object_sync.c`に検証を追加。(1)`bm_build_onionpeer`が生成する
ペイロードが、既存の受信側テスト(同ファイル内、同じonionアドレス文字列を使用)が手組みした
ワイヤーフォーマットとport・OnionCat prefix・鍵バイト列まで完全一致すること(相互運用性の
直接証明)、(2)不正なonion文字列に対してNULLを返すこと、(3)`bm_object_sync_announce_onion_
peer`が実際にobject_pool.dbへ`BM_OBJECT_ONIONPEER`型のobjectを挿入すること、を確認した。
実daemon(独立した一時ディレクトリ)でも、Stage 2のhidden service作成に続けて
`[object_sync] announced our onion peer: ...`が出て後続の起動処理(peer_connector等)を
ブロックしないことを確認した。ctest 20件全通過。

### 静的torrc設定への対応: BM_ONION_ADDRESS(2026-08-22)

Stage 2(ControlPort自動化)を実装した後、「ユーザーが自分でtorrcにHiddenServiceDir/
HiddenServicePortを静的に設定し、Tor自体はdaemonと一切やり取りしない」という運用
(まさに開発者自身がこの一連の実装の動作確認のために最初からやっていた構成)についても
確認された。この場合、Stage 1(`bm_network_listen`、Tor非依存)だけで接続受付自体は
既に機能していたが、`OBJECT_ONIONPEER`の自己announce(前項)はStage 2のADD_ONION応答から
得たonionアドレス文字列にしか発火しないため、静的torrc運用単体では自分のonionアドレスを
ネットワークへ告知できないという抜けがあった。PyBitmessageの`keys.dat`の`onionhostname`
設定(stemによる自動作成を使わず、ユーザーが直接教えたonionアドレスをそのまま使う)と
同じ位置づけの機能が必要と分かり、`BM_ONION_ADDRESS`環境変数として追加した。

**main.cでの優先順位:** `BM_ONION_ADDRESS`が設定されていれば、ControlPort連携(Stage 2)を
完全にスキップし、そのアドレスをそのまま`bm_object_sync_announce_onion_peer`で告知する
(`else if`でStage 2と排他)。PyBitmessageも`onionhostname`設定時はstemによる自動作成を
試みないため、同じ優先順位に揃えた。外部から見えるポート番号(`BM_TOR_VIRTUAL_PORT`、
既定8444)はStage 2と共通の変数をそのまま使う(「他のpeerが自分のonionアドレスのどの
ポートへ接続してくるか」という意味は経路によらず同じであるため)。

**検証:** 実daemon(独立した一時ディレクトリ)でテスト専用のダミーonionアドレス
(実オニオンアドレスではなく、tests/test_object_sync.cで使っているのと同じテスト用文字列)を
`BM_ONION_ADDRESS`に指定して起動し、ControlPortへは一切接続せずに
`[tor_control] using statically configured onion address: ...`
`[object_sync] announced our onion peer: ...`
の両方が出て、後続の起動処理(peer_connector等)もブロックしないことを確認した。ctest
20件全通過(既存のbm_object_sync_announce_onion_peer自体のテストで実質カバーされている
ため、このBM_ONION_ADDRESS配線自体に対する新規ctestは追加していない。main.cの環境変数
分岐という薄い配線のみのため)。

### 起動時設定ファイル bitmessage.conf(2026-08-22)

env varがBM_TESTNET/BM_API_PORT/BM_INBOUND_PORT/BM_TOR_(CONTROL等)/BM_ONION_ADDRESS/
BM_NO_CONNECTという6系統・計9個まで増え、実運用で毎回同じ設定を手打ちするのは非現実的に
なったため、ユーザーとの合意でINI形式の起動時設定ファイルを導入した。

**設計方針:** 「起動時にしか意味を持たない設定」はこのファイル、「実行時にAPI経由で変更
できる設定」(SOCKS5プロキシ等)は引き続き`config.db`(`core/config_store.c`)を使う、と
役割分担する。静的ファイルにAPI経由のホットリロードまで持たせると複雑になりすぎるための
判断。優先順位は「環境変数 > 設定ファイル > 組み込みの既定値」とし、env var自体は削除せず
テスト/CI用の上書き手段として残した(既存の`BM_NO_CONNECT`等の使われ方をそのまま活かす
ため。実際`tests/`配下のシェルスクリプト・Cテストは全てenv var経由でdaemonを制御しており、
env varを優先させることでカレントディレクトリにたまたま`bitmessage.conf`があっても
テストの決定性が壊れない)。

**形式選定(YAML vs INI):** ユーザーと検討し、外部依存無しで安全に自前パーサを書ける・
今回の設定がフラットなkey-valueの集まりでネスト/リストが不要・PyBitmessageの`keys.dat`
(Pythonの`configparser`、INI形式)と同じ伝統に乗れる、という理由でINIを選んだ。

**実装:** `core/config_file.h`/`.c`(`bm_config_file_load(path, &cfg)`)。`[section]`・
`key = value`・`#`/`;`行コメントのみの最小限のパーサ(約150行)。ファイルが存在しない場合は
既定値のまま0を返す(必須ファイルではない)。認識できないキー/`=`の無い行は1行ごとに
警告を出すだけで処理を継続する(1行の誤りで起動全体を止めないため)。

セクション構成: `[network]`(testnet, no_connect)・`[api]`(port)・`[inbound]`(port、0=無効)・
`[tor]`(control, control_socket, control_host, control_port, virtual_port, onion_address)。
API認証情報(ユーザー名/パスワード)は意図的に含めない: 起動毎のランダム生成・非永続という
既存の設計はセキュリティ上の判断であり、平文設定ファイルへ持ち出す変更は別途の判断が必要な
ため今回のスコープでは行わなかった。

`main.c`に`env_flag_or`/`env_or_int`/`env_or_str`という3つの小さなヘルパーを追加し、
既存の9箇所のenv var読み取り(testnet, no_connect, api_port, inbound_port, tor_control,
tor_control_socket/host/port, tor_virtual_port, onion_address)を全て「設定ファイルの値を
既定にしつつenv varで上書き」という形に置き換えた。`BM_INBOUND_PORT`は挙動を少し変更した:
従来は「env varが設定されていること」自体で判定していたが(値が0でも listen を試みた)、
設定ファイルとの共存のため「値が0以外」で判定するよう統一した(0=無効という約束を両方の
入力元で共通化するため。既存のctest/シェルスクリプトはどちらも`BM_INBOUND_PORT=0`を
使っていないことをgrepで確認済みで、後方互換上の実害は無い)。

ファイルの置き場所は`BM_CONFIG_FILE`環境変数で変更でき、既定は`bitmessaged`のカレント
ディレクトリの`bitmessage.conf`(他の全てのDBファイルと同じくカレントディレクトリ基準、
という既存の一貫性に合わせた。XDG設定ディレクトリ等、他のファイルが使っていない新しい
置き場所の慣習は導入していない)。テンプレートとして`bitmessage.conf.example`をリポジトリ
直下に追加し、実際に使う`bitmessage.conf`自体は`.gitignore`へ追加した(ユーザーが実onion
アドレス等の個別設定を誤ってcommitしないため)。

**テスト:** `tests/test_config_file.c`を追加。存在しないパスで既定値のまま0を返すこと、
実際のINIファイルの全セクション/キーが正しく反映されること(コメント・空行・前後の空白の
無視も含む)、不明なキーや`=`の無い行があっても残りの行の解析が継続することを確認した。
実daemon(独立した一時ディレクトリ)でも、env var無しで設定ファイルの値
(testnet/no_connect/api port/inbound port)だけが実際に反映されること、`BM_API_PORT`env
varが設定ファイルの値を正しく上書きすることの両方を確認した。ctest 21件全通過。

### PyBitmessage keys.dat由来の追加項目: maxoutboundconnections・PoW難易度既定値(2026-08-22)

`bitmessage.conf`導入後、PyBitmessageのkeys.datにあってこちらに無い項目のうちGUI系を除いて
洗い出し、価値がありそうな2つをユーザーと合意の上で追加した(SOCKS5認証・Namecoin連携・
帯域制限・ブラックリスト等は別途大きな機能が必要、またはTorがSOCKS5認証を要求しないため
実質価値が薄いと判断し見送った)。

**`[network] max_outbound_connections`(PyBitmessageの`maxoutboundconnections`相当):**
`main.c`にハードコードされていた`BM_MAX_OUTBOUND 3`を`bitmessage.conf`/`BM_MAX_OUTBOUND`
env varから読むよう変更。既定値は変えず3のまま。

**`[identity] default_nonce_trials_per_byte`/`default_payload_length_extra_bytes`
(PyBitmessageの`defaultnoncetrialsperbyte`/`defaultpayloadlengthextrabytes`相当):**
調べたところ、`api_server.c`の`h_createDeterministicAddress`/`h_joinChan`が新規identity
作成のたびに`1000, 1000`を直接ハードコードしており、**ネットワーク最低難易度より高いPoWを
自分宛のメッセージに要求する手段が(CLIにもAPIにも)一切無かった**。これはPyBitmessageに
ある簡易的なスパム対策機能の欠落だったため、`struct bm_api_server_config`に
`default_nonce_trials_per_byte`/`default_payload_length_extra_bytes`(共にuint64_t)を
追加し、両ハンドラのハードコード値をこれに差し替えた。

**0除算対策:** `pow_engine.c`の`bm_pow_get_target`は`nonce_trials_per_byte`で除算するため、
この値が0だと即座にクラッシュする(未定義動作)。設定ファイル由来の値が万一0になる経路を
断つため、`config_file.c`の`apply_kv`はこの2項目(および`max_outbound_connections`)に
0以下の値が指定されたら警告を出して既定値を維持するガードを入れた。加えて、
`bm_api_server_config`を直接組み立てている3つのテスト(`test_api_server.c`・
`test_broadcast.c`・`test_getpubkey_automation.c`)は`memset`で0初期化した後に個別フィールドを
設定する書き方だったため、この2つの新フィールドを明示的に`1000`で埋めるよう修正した
(でなければテストがクラッシュしていた)。

**テスト:** `tests/test_config_file.c`に新規セクション`[identity]`の値の反映、および
`max_outbound_connections`/PoW難易度2項目への0や負の値が拒否され既定値のまま維持される
ことの検証を追加。実daemon(独立した一時ディレクトリ)で`default_nonce_trials_per_byte=2000`
`default_payload_length_extra_bytes=1500`を設定し、`bitmessage-cli create-address`で
作成した実際のアドレスの`identity.db`の値が2000/1500になっていることを確認した。
ctest 21件全通過。

### バグ修正: 切断したoutbound接続のratingが更新されず同じ死んだpeerに再接続し続ける(2026-08-22)

v1.1.0リリース後、ユーザーが`bitmessaged_bootstrap.log`(長時間稼働のbootstrap daemon)を
見て「ずっと同じpeerに接続しに行ってresetされていないか」と指摘。確認したところ、
特定の1peer(`179.191.207.222:8444`)への接続が9700行超のログ中3474回にわたって
繰り返されており、実際にバグだった。この指摘から、3段階の修正(本セクション・rating
successの記録場所の修正・SOCKS5プロキシ越しのip:port解決の修正)と`error`メッセージの
可視化改善(後述)を経て実際にratingが正常に機能するまで、3日間を要した。

**原因:** `peer_connector.c`はconnect()+version送信が成功した時点で
`bm_peer_manager_record_result(..., 1, 1)`を呼びrating+0.1(上限1.0)を記録するが、
その直後に相手からECONNRESET等で切断されても、それをratingへフィードバックする経路が
どこにも無かった。「TCPは繋がりversionも送れるが、直後に切断してくる」peerは
一度でも接続に成功すればratingが上がる一方で、その後何度切断されても下がることが無い。
結果としてこのようなpeerのratingが上限の1.0に張り付き、`bm_peer_manager_list_top`
(rating降順)で毎回のreconnectサイクルの最上位候補になり続け、outbound接続枠を
無限に消費し続けていた。

**修正:** `infra/network.c`の`bm_network_epoll_thread`に、接続切断(`bm_network_handle_
readable`が非0を返す=EOFまたは読み取りエラー)を検知した際の処理を追加した。対象の接続が
`BM_FD_CLIENT_SOCKET`(こちらから選んで繋いだoutbound接続。相手から繋いできた`BM_FD_
SERVER_SOCKET`はこちらが選んだ相手ではないため対象外)であれば、`conn->peer_addr`から
ip/portを取り出し`bm_peer_manager_record_result(peers_db, ip, port, 1, 0)`を呼んで
failureとして-0.1を記録する。これにより繰り返し切断してくるpeerは他の不安定なpeerと
同様ratingが下がっていき、既存の低rating cleanup機構の対象にもなり得るようになった。

`struct bm_epoll_thread_args`に`peers_db`(NULL可)を追加し、`main.c`から配線した。

**テスト:** `tests/test_peer_rating_on_disconnect.c`を新規追加。実TCP接続+実際に
`bm_network_epoll_thread`をpthreadで起動し、peers.dbへrating=0.5で登録済みのpeerへ
outbound接続した直後に相手側がEOFで切断した場合、rating列が実際に0.4(0.5-0.1)へ
更新されることを確認した(`tests/test_inbound.c`と同じ「実ソケット+実スレッドで
決定的に検証する」方針)。ctest 22件全通過。

再起動が必要なbootstrap daemon自体への適用はユーザーの明示的な指示を待って行う
(前回誤って`pkill -f`で巻き込んで停止させてしまった経緯があるため、今回はPIDを
明示的に指定してのみ操作する)。

**追記: 上記修正だけでは不十分だった。** 実際にbootstrap daemonをこの修正版で再起動し、
かつoutbound SOCKS5(Tor)プロキシも有効化して観察したところ、`179.191.207.222:8444`
`95.49.240.98:8444`への接続が依然として1サイクルあたり最大回数近く繰り返されており、
`peers.db`を直接確認するとratingが**1.0のまま**だった。

**真因:** `peer_connector.c`が「TCP接続+自分のversion送信が成功」した時点で無条件に
success(+0.1)を記録していた。これは相手が実際に応答したかとは無関係な弱い基準で、
「繋がるが相手からは一切応答が無いまま切断される」peerでも毎サイクル必ずsuccessが
記録される。この状態で上記1回目の修正(切断時にfailure -0.1)が効いても、
success(+0.1)とfailure(-0.1)が**同じサイクル内で必ず1回ずつ発生して相殺**してしまい、
ratingが上限1.0に張り付いたまま永久に下がらなかった。

**2回目の修正:** successを記録する場所を`peer_connector.c`(自分の送信が成功した時点)から
`infra/object_sync.c`の`bm_object_sync_dispatch`内、version/verackを実際に受信した時点
(=相手が応答した確かな証拠が得られた時点)へ移した。`record_outbound_success`という
静的関数を追加し、`conn->type == BM_FD_CLIENT_SOCKET`(outbound、こちらが選んだ相手。
`BM_FD_SERVER_SOCKET`は対象外、1回目の修正の切断時failure記録と対称にした)かつ
`ctx->peers_db != NULL`の場合のみ、version/verackどちらの受信でも(相手が最初にどちらを
送ってくるかは実装依存のため両方で拾う)`bm_peer_manager_record_result(..., 1)`を呼ぶ。
`ip:port`の取り出しには`network.c`の`extract_ip_port`を`bm_network_extract_ip_port`として
公開し、`network.c`自身と`object_sync.c`の両方から共有した。

これにより「応答が一切無いまま切断される」peerは二度とsuccessを得られず、failureだけが
積み重なって実際にratingが下がっていくようになった(既存の1.0に張り付いた2peerも、
今後は接続のたびにfailureのみが記録され続けるため、数サイクルかけて自然に下がっていく
想定。DB上のratingを即座にリセットする対応はせず、修正の効果が実際の運用で自然に
表れることを優先した)。

**テスト:** `tests/test_peer_rating_on_disconnect.c`にシナリオ2を追加。
`bm_object_sync_dispatch`へ実際にverackメッセージを渡し、outbound(`BM_FD_CLIENT_SOCKET`)
では`rating`が+0.1(0.3→0.4)される一方、inbound(`BM_FD_SERVER_SOCKET`)では記録されない
(0.3のまま)ことを確認した。ctest 22件全通過。

### バグ修正(3回目): SOCKS5(Tor)プロキシ越しだと1回目・2回目の修正が両方とも無効化されていた

2回目の修正版をbootstrap daemonへ適用し、続けてoutbound SOCKS5(Tor、`127.0.0.1:9050`)を
有効化して観察したところ、`179.191.207.222`/`95.49.240.98`(1回目・2回目の修正前から
rating 1.0に張り付いていた既存2peer)に加えて、新たに`158.69.63.42`/`85.114.135.102`も
同様にrating 1.0へ張り付き毎サイクル再接続され続ける状態になった。ログには
`unhandled command: error`(相手からのerrorメッセージ受信、こちらからの応答ではない)が
頻発しており、これが調査の糸口になった。`peers.db`を直接確認したところ、これら5peerは
全て**rating=1.0のまま一切動いていなかった**。

**真因:** `bm_fd_data.peer_addr`は`getpeername()`で取得するが、SOCKS5プロキシ経由の
接続ではOSレベルのTCP接続相手は**プロキシ自身**(`127.0.0.1:9050`)であり、実際の
Bitmessage peerのアドレスではない(SOCKS5のCONNECT先はアプリケーション層のネゴシエーション
でしか分からず、OSソケット層からは見えないため)。1回目・2回目の修正はどちらも
`bm_network_extract_ip_port(&conn->peer_addr, ...)`でip:portを抽出していたため、SOCKS5
有効時は常に`127.0.0.1:9050`を対象にratingを更新しようとしていた。`peers.db`に
そのような行は存在しないため、`bm_peer_manager_record_result`のUPDATE文が0行にヒットし、
エラーにもならず**静かに何も更新されない**状態になっていた。つまりSOCKS5有効化以降、
success/failureどちらの記録も実質的に機能を失っていたことになる(直接接続時代に貯まった
30peerのrating=-0.1は、SOCKS5と無関係な、peer_connector.cの既存のTCP接続失敗パス
(`candidates[i].ip_address`を直接使う、今回の変更が及んでいない箇所)によるものだった)。

**3回目の修正:** `struct bm_fd_data`に`logical_peer_ip`/`logical_peer_port`を追加した。
これは`peer_connector.c`がoutbound接続(`BM_FD_CLIENT_SOCKET`)を作成した直後に、
SOCKS5経由かどうかに関わらず常に正しい「本来選んだ接続先」(`candidates[i]`)を明示的に
書き込むフィールドである。`network.h`に`bm_network_resolve_peer_ip_port(conn, ...)`を
追加し、`logical_peer_ip`が設定されていればそちらを優先し、未設定(テストや将来の別経路)
の場合のみ従来通り`peer_addr`由来のip:portへフォールバックするようにした。1回目
(`network.c`の切断時failure記録)・2回目(`object_sync.c`のverack/version受信時success記録)
の両方をこの新ヘルパー経由に変更した。

**テスト:** `tests/test_peer_rating_on_disconnect.c`にシナリオ3を追加。`conn->peer_addr`を
ダミーの"プロキシアドレス"(`127.0.0.1:9060`)に、`conn->logical_peer_ip`をTEST-NET-3の
予約アドレス(`203.0.113.9:8444`、実在しないためテストとして安全)に設定した状態で
verackをdispatchし、(1)本来の接続先(`203.0.113.9:8444`)のratingが正しく+0.1されること、
(2)プロキシのアドレス(`127.0.0.1:9060`)がpeers.dbに一切登録されないこと、の両方を
確認した。ctest 22件全通過。

再起動が必要なbootstrap daemonへの適用はユーザーの指示を待ってから、PIDを明示的に
指定して行う。

3回目の修正版をbootstrap daemonへ適用し数分観察したところ、`179.191.207.222`(1.0→0.8)・
`95.49.240.98`(1.0→0.7)・`158.69.63.42`(1.0→0.7)・`85.114.135.102`(1.0→0.7)と、
問題のあった4peer全てのratingが実際に下がり始めることを確認した。他のpeer(-0.1が30件、
0.4が3件等)も含め、SOCKS5経由でsuccess/failureの両方が正しく記録されていることも
確認できた。

### errorメッセージの中身をログに出すよう改善(2026-08-22)

上記のrating調査中、`[object_sync] unhandled command: error`というログが頻発している
ことにユーザーが気づいた。Bitmessageプロトコルの`error`メッセージ(`fatal(varint) ||
banTime(varint) || vector(varstr) || errorText(varstr)`)は相手が接続を切る前に理由を
伝えるためのものだが、これまで中身を一切見ずに「unhandled command」として捨てていたため、
rating調査全体を通して相手が実際に何を嫌がっていたのか(protocol不整合、接続過多、
banされている等)が全く分からないままだった。

`infra/object_sync.c`の`bm_object_sync_dispatch`に専用の`error`分岐を追加し、
`fatal`/`banTime`/`errorText`をパースして`[object_sync] error message from peer: fatal=%d
banTime=%d text="..."`としてログに出すようにした(`vector`フィールドは診断上重要度が低いため
読み飛ばすだけで値は使わない)。手書きのvarint/varstrパースなので、データ不足時に
size_tの引き算でアンダーフローしないことを重視した(各ステップで`bm_varint_decode`の
戻り値が0でない=十分なデータがあることを確認してから次のフィールドへ進む設計)。

**テスト:** `tests/test_object_sync.c`に section 9として、正常な形式のerrorメッセージが
クラッシュ無くパースされること、空ペイロード・1byteだけの極端に短いペイロードでも
(bounds checkのアンダーフローなどで)クラッシュしないことを確認した。パース結果の
文字列内容自体はstderr出力なのでテストの枠組みでは検証していない(実行時に目視確認、
実際に`text="too many connections"`のようなテスト用文字列が正しく出力されることを確認)。
ctest 22件全通過。

### バグ修正: SOCKS5プロキシ越しだとpeer_registryの二重接続防止も機能していなかった

上記`error`メッセージの可視化で「Too many connections from your IP.」という実際の
拒否理由が判明した後、ユーザーから「うちの実装にも同様の受付制限があるか」と質問された
のをきっかけに(無い、と回答)、rating関連の3回目の修正(SOCKS5経由だと`conn->peer_addr`が
プロキシのアドレスになる)と同じ根本原因を持つ兄弟バグが`infra/peer_registry.c`にも
無いか確認したところ、実際に見つかった。

**原因:** `bm_peer_registry_has_peer(reg, ip, port)`(`peer_connector.c`の
`bm_peer_connector_connect_initial`が「既に接続済みの相手には二重接続しない」ために使う)は、
`reg->conns[i]->peer_addr`(getpeername)をそのまま`"ip:port"`文字列化して比較していた。
SOCKS5(Tor)経由の接続ではこれがプロキシ自身のアドレス(`127.0.0.1:9050`)になるため、
候補の本来のip:portとは絶対に一致せず、SOCKS5有効時は「既に接続済み」判定が常に偽になり、
二重接続防止が機能していなかった。

**修正:** `bm_network_resolve_peer_ip_port`(3回目の修正で追加した、`logical_peer_ip`優先で
本来の接続先を解決するヘルパー)を使うよう変更した。副次的に、この関数専用だった
`format_peer_addr`static関数は不要になったため削除した。

**テスト:** `tests/test_peer_registry_proxy.c`を新規追加。(1)SOCKS5経由を模した接続
(`peer_addr`=ダミーのプロキシアドレス、`logical_peer_ip`=本来の接続先)が本来の接続先で
正しく重複検知されること、プロキシ自身のアドレスは重複検知の対象にならないこと、
(2)直接接続(`logical_peer_ip`未設定)でも従来通り`peer_addr`ベースのフォールバックで
重複検知できること、(3)削除後は重複検知されなくなること、を確認した。ctest 23件全通過。

なお`bm_post_version`が`conn->peer_addr`/`conn->local_addr`をversion messageの
`addr_recv`/`addr_from`フィールドへエンコードする箇所もSOCKS5経由だと厳密には不正確に
なるが、これらのフィールドを検証・利用している実装は確認できておらず情報提供以上の
意味を持たないため、優先度が低いとして今回は対応しなかった(ユーザーとの合意)。

### 自己接続の防止: peers.dbのis_selfフラグ(PyBitmessage knownnodes myself相当、2026-08-22)

一連のrating調査の中で、ユーザーから「version messageの`nonce`による自己接続検知は
やっていないのか」と質問された。確認したところ`bm_create_version_payload`は呼ぶたび
`getrandom()`で新しいnonceを生成しており(プロセス全体で使い回す固定値ではない)、
受信側でも`nonce`を一切比較していないため、自己接続検知の仕組みは存在しないことが
判明した。

実際にこれは机上の空論ではなく具体的なリスクがある: 自分自身の`OBJECT_ONIONPEER`
自己announce(既存実装)がgossip経由で自分のpeers.dbへ戻ってくると、次の再接続サイクルで
自分自身のonionアドレスへ接続しに行ってしまう可能性がある。

**nonce使い回し方式を採用しなかった理由:** Bitcoin/Bitmessageの一般的な実装は、
プロセス起動時に1個だけnonceを生成し全接続で使い回すことで自己接続検知を実現する
(でなければ「送った値と一致するか」を確認する対象が無くなる)。しかしこれはclearnet
(IPアドレス自体が既に相手を特定できる情報)を前提にした設計判断であり、Tor経由の匿名性が
前提のこの実装でnonceを使い回すと、「同一ノードが複数circuitから接続している」という
Tor自体が隠したいはずの相関情報を漏らしてしまう。ユーザーと議論した結果、この
トレードオフを避けるため採用しなかった。

**採用した方式:** PyBitmessageのknownnodes `myself`フィールドと同じ発想で、
`core/peer_manager.c`の`hosts`テーブルに`is_self`列(既定0)を追加した。
`bm_peer_manager_mark_self(db, ip_address, port, stream)`で自分自身のonionアドレスを
`is_self=1`としてマークし(既存行があればrating/source等の履歴を保ったままis_selfだけ
立てる、gossip等で自分のアドレスが既に学習済みだった場合に履歴を破棄しないため)、
`bm_peer_manager_list_top`(接続候補選定)のSQLに`AND is_self = 0`を追加して除外する。
`main.c`から、Stage 2(ControlPortのADD_ONION成功後)・`BM_ONION_ADDRESS`(静的torrc設定)
の両方の経路で、自分のonionアドレスが判明した直後に呼ぶ。

**マイグレーション:** `is_self`列は追加時点で既に稼働中の(3日間動かし続けている)
bootstrap daemonの`peers.db`には存在しない。`CREATE TABLE IF NOT EXISTS`はテーブルが
既に存在する場合まるごとno-opのため、`SCHEMA_SQL`を変更しただけでは既存DBに列が
増えない。`bm_peer_manager_init_schema`に`ALTER TABLE hosts ADD COLUMN is_self ...`を
追加し、新規DB(`CREATE TABLE`時点で既に`is_self`列を含むため必ず発生する
"duplicate column name"エラー)は戻り値を見ずに無視することで両対応した。

**テスト:** `tests/test_peer_manager_self.c`を新規追加。(1)新規行としての`mark_self`が
`list_top`から除外されること、(2)gossipで学習済みだった行を`mark_self`した場合、
事前に`record_result`で積んだrating(0.5)とsourceが保持されたまま`is_self`だけ立ち
`list_top`から除外されるようになること、(3)`is_self`列を持たない古いスキーマの
DBに対しても`init_schema`のマイグレーションが正常に働き、既存行を保ったまま
`mark_self`/`list_top`が使えるようになることを確認した。ctest 24件全通過。

### セッションまとめ: v1.1完成(inbound Tor対応・設定ファイル・Dandelion++)(2026-08-19〜2026-08-23)

v1.0.0リリース後、複数日にわたる1つの連続したセッションで以下を完了した。詳細は
各節を参照(このまとめは索引専用、内容はここには繰り返さない)。

- **inbound接続**: Stage 1(汎用TCP listen/accept、Tor非依存)・Stage 2(Tor ControlPort
  自動化・onion鍵永続化)・`BM_ONION_ADDRESS`(静的torrc設定への対応、PyBitmessageの
  `onionhostname`相当)・`OBJECT_ONIONPEER`自己announce送信側。全て完了(§11「inbound接続」
  各節、上記参照)。
- **起動時設定ファイル`bitmessage.conf`**: INI形式の自前パーサ、`env var > 設定ファイル >
  既定値`の優先順位、PyBitmessage keys.dat由来の`max_outbound_connections`・
  `default_nonce_trials_per_byte`/`default_payload_length_extra_bytes`を追加。
- **バージョンを1.1.0へ引き上げ**(`v1.1.0`タグ)。
- **peer rating/接続まわりのバグ4連発**(いずれもユーザーが実際のbootstrap daemonの
  ログを見て気づいた): (1) 切断したoutbound接続のratingが更新されず同じ死んだpeerに
  再接続し続ける、(2) success記録のタイミングが早すぎて(1)の修正を打ち消していた、
  (3) SOCKS5(Tor)プロキシ越しだと(1)(2)の修正が両方とも無効化されていた
  (`conn->peer_addr`がプロキシ自身のアドレスになるため。`bm_fd_data.logical_peer_ip`+
  `bm_network_resolve_peer_ip_port`で解決)、(4) 同じ根本原因の兄弟バグが
  `bm_peer_registry_has_peer`(二重接続防止)にもあった。実daemonで4peerのratingが
  実際に1.0から下がっていくことまで確認済み。
- **errorメッセージの中身をログに出すよう改善**: 上記調査中、相手が実際に
  「Too many connections from your IP」で拒否していたことが分かった(こちらの実装には
  同種の受信側レート制限は無い、backlog参照)。
- **自己接続の防止**: `peers.db`に`is_self`フラグ(PyBitmessage `knownnodes` `myself`
  相当)を追加。version messageの`nonce`使い回しによる自己接続検知は、Tor経由だと
  「同一ノードが複数circuitから接続している」という相関情報を漏らすため採用しなかった。
- **Dandelion++**: Stage 1(`dinv`配線)・Stage 2(単一ホップのstem/fluff状態機械、
  600秒毎のstem successor再抽選、固定10秒+平均30秒の指数分布タイムアウト)・Stage 3
  (inv/dinvの来歴を区別し、既に公開済みのobjectはstemせず即fluff)・自分の`services`へ
  `NODE_DANDELION`を表明(双方向の参加者化)。実装前に、実際に観測した85件のversion
  messageが100%Dandelion対応を表明していることを確認してから着手した。

**現在進行中:** ユーザー実機の静的torrc設定(実onionアドレス、内容は非公開)を使い、
inbound・outbound Tor・Dandelion++・`is_self`を全て有効にした状態でbootstrap daemonの
エンドツーエンド運用テストを継続中。onionアドレス自体はこのファイル・commit message・
コード中を含め一切記載しない(ユーザーの明示的な指示)。次セッションでは
`bitmessaged_bootstrap.log`(リポジトリルート、git管理外)でinbound接続受信の有無・
rating推移・Dandelion動作を確認できる。

### バグ修正: ログ上のIPv6アドレスがportと区切れない(2026-08-23)

運用テスト中のログをユーザーが確認していて発見。`[peer_connector] connecting to
2604:8b40:f9:0:1:::1 (via SOCKS5)...`のように、IPv6アドレスを`"%s:%d"`でそのまま
host:portのログに埋め込むと、アドレス自体が含む`:`区切りとhost/port境界の`:`が
区別できなくなる問題があった。

`infra/network.h`/`.c`に`bm_network_format_host_port(host, port, out, out_len)`を
新設し、hostに`:`が含まれる場合(IPv6リテラル)はRFC 3986慣習に従い`[host]:port`の
形にbracketで囲むようにした(含まれない場合はIPv4/ホスト名/onionアドレスなので
従来通り素通しで`host:port`)。`infra/peer_connector.c`(outbound接続先・SOCKS5
プロキシ先の全ログ)、`infra/tor_control.c`(ControlPort接続失敗ログ)、
`core/api_server.c`(JSON-RPC APIのbind先ログ)を該当ヘルパー経由に置き換えた。
`bitmessage-cli`(`cli/main.c`)はbm_infraを一切linkしない独立した小さな実行体の
ため、ヘルパーを共有せず同等のロジックを1箇所だけインラインで複製した。
ctest 27件全通過、クリーンなbuildディレクトリでの再ビルドも確認済み。

### バグ修正: addr_msg由来の破損したように見えるIPv6がpeers.dbへ混入する(2026-08-23)

運用テスト中のpeers.dbをユーザーが確認していて発見。`e001:1a00::ffff:aa54:3013`や
`::ea:f035:c8c2:7d86`のような、明らかに正規のBitmessage peerとは思えないIPv6アドレスが
`addr_msg`由来で登録されていた(実際に混入していたのは346件中7件)。`infra/object_sync.c`の
`is_routable_peer_address`はloopback/ULA(fc00::/7)/link-local(fe80::/10)/multicast
(ff00::/8)しか弾いておらず、たまたまそれ以外の範囲に収まったgarbageな16バイト値は
素通りしてしまっていた。

実ネットワーク上で本物のIPv6 peer(非IPv4-mapped)の利用実績が観測できていないこと
(inbound listenは127.0.0.1固定、outboundもTor/SOCKS5前提)を踏まえ、`§9.6`の
`NODE_SSL`非対応と同じ「実利用の裏付けが無いものは対応しない」方針で、`addr`受信時に
素のIPv6エントリを一律filterするよう変更した(狭い許可範囲へ絞り込むのではなく、
そもそも受け付けない)。`is_routable_peer_address`は`is_routable_ipv4_peer_address`に
簡素化し、IPv4-mappedの判定と組み合わせて`is_ipv4_mapped`でない場合は即filterする。
既に混入していた7件は既にratingが-0.1〜-0.2まで下がっており、既存のクリーンアップ処理で
自然に消えるため手動削除はしていない。ctest 27件全通過(素のIPv6を一律filterする
回帰テストを`test_object_sync.c`に追加)。

### 重大バグ修正: varint(0xfd/0xfe/0xff以降)がリトルエンディアンで実装されていた(2026-08-23)

ユーザーが`peers.db`を`sqlite3`で直接見ていて発見。`onionpeer_obj`由来のportが全件
`64544`になっていた。8444(2進数表現で0x20FC)をswap16すると0xFC20=64544になり一致する
ことから、`common/varint.c`の`bm_varint_decode`/`bm_varint_encode`の多バイト部分の
バイトオーダーを疑い、PyBitmessage本家(`addresses.py`)の`encodeVarint`/`decodeVarint`を
確認したところ`pack('>H'/'>I'/'>Q', ...)`(ビッグエンディアン)だった。うちの実装は
リトルエンディアンで、これは表示上の問題ではなく本物のプロトコル仕様違反だった。

**気付かれなかった理由**: stream番号・addr/inv件数・user agent長といった他のvarint
利用箇所は実運用でほぼ常に253未満(1byte varint)に収まるため、多バイト部分の
バイトオーダーが試される機会がほとんど無かった。ポート番号(既定8444)は必ず253以上
になるため、OBJECT_ONIONPEERのvarint(port)フィールドで初めて顕在化した。

**移植元(libstudy)の状況**: `study/libstudy/src/bm_sonota.c`の`encodeVarint`にも
同じバグがあり(`bm_protocol.c`の`decodeVarint`も同様)、しかも
`// TODO endian関数使ってエンコーディング`というコメントが当時から付いたまま
放置されていたことが判明。移植時に紛れ込んだものではなく、libstudy時代からの
既存バグだった。ユーザーの指示でこちらも修正・commit・push済み(`htobeXX`/`beXXtoh`
を使う形に書き換え、libstudyの既存ctest 9件全通過を確認)。

**永続化データへの影響範囲の洗い出し**: `bm_varint_decode`の全利用箇所を確認した結果、
実際にDBへ保存され後に残る形で壊れていたのは`peers.db`の`hosts.port`
(`source='onionpeer_obj'`)だけと判断した。object header の`stream`もvarint経由だが
実運用ではstream=1で固定されており(peers.db/object_pool.db双方で確認)実害無し。
addr/inv message件数やerror messageのフィールド長はその場限りの解析にしか使わず
DBに残らないため、当時パースし損ねていたとしても今から直す対象が無い。

**修正内容**: `common/varint.c`の該当3箇所(0xfd/0xfe/0xff)を全てビッグエンディアンに
修正。回帰テスト`tests/test_varint.c`を新設(実際に壊れていた8444のワイヤーバイト列
`0xfd 0x20 0xfc`を含む固定期待値テスト+全サイズクラスのround-trip)、ctest 28件全通過。
既存の壊れたpeers.dbエントリ(`onionpeer_obj`、17件、port値は64544/38667/3144の3種)は
`UPDATE hosts SET port = ((port & 255) << 8) | ((port >> 8) & 255) WHERE
source = 'onionpeer_obj';`で一括修正(swap16は自己逆写像なので同じ操作を再適用するだけで
正しい値に戻る)。修正後は8444(14件)/2967(2件)/18444(1件)に復元された。

### バグ修正: addr_msgのlast_seenが未来の値でも無検証で登録されていた(2026-08-23)

ユーザーが`peers.db`で`last_seen`が2^31(2147483648)を超える行が70件あるのを発見。中身を
見ると、3つのIP(82.10.174.236等)に対してport 8444〜65535近辺までの隣接する
ephemeralポートを19〜21個ずつ生成し、かつ全entryに同一の巨大な(一部は2^63近くまである)
last_seenを仕込んだgossip spamと判明した(ユーザーが「addr_msgスパムでは」と即座に
見抜いた)。

**実害**: `bm_peer_manager_cleanup`の年齢判定は`now - last_seen > max_age`で、
last_seenが未来(=nowより大きい)だとこの差が常に負になり、ratingがどれだけ下がっても
年齢起因のクリーンアップに一切引っかからなくなる。つまりこの種のspam entryは通常の
IPv6 garbage(§参照)と違って**自然には消えない**、恒久的にDBへ居座る性質だった。

**原因**: `addr`受信ハンドラ(`infra/object_sync.c`)がpeer申告の`time`フィールドを
無条件に信用して`last_seen`へ書き込んでいた。PyBitmessage本家の`bmproto.py`
`bm_command_addr`を確認したところ、`time.time() - seenTime > 0`(=未来なら弾く)という
検証が入っていた。うちにはこれが無かった。

**修正**: addr受信時、`e->time`が現在時刻より未来のentryを他のfilter条件
(IPv4-mapped判定・routable判定)と同列に扱い、一律filterするようにした。
回帰テストを`test_object_sync.c`に追加(未来1年のtimeを持つentryが登録されないことを
確認)、ctest 28件全通過。既存の壊れた70件はspamであり正しい値を逆算する手段も無いため、
`DELETE FROM hosts WHERE last_seen > <now>;`で削除した(本物のpeerだった場合は今後の
正常なaddr/onionpeer受信で自然に再登録される)。

### バグ修正: SIGTERM後の終了処理が数分単位で長引く(2026-08-23)

再起動のたびにSIGTERM送信後の終了までの時間が不安定(3分台のこともあれば11分かかった
こともあった)だったのを、`infra/peer_connector.c`の`bm_peer_connector_connect_initial`を
調査して特定。候補peerを順に試す`for`ループが`stop_flag`を一切見ておらず、SIGTERM後も
「今回のバッチの残り候補全部」を試し終えるまで(1件あたりCONNECT_TIMEOUT_SEC(5秒)+
SOCKS5_HANDSHAKE_TIMEOUT_SEC(20秒)=最大25秒)`bm_peer_connector_thread`が
pthread_joinできない状態だった。`bitmessage.conf`で`max_outbound_connections = 8`と
設定していたため、再起動直後(まだ0件も接続していない状態)にSIGTERMが来ると
最大8×25秒=200秒(実測220秒のケースとほぼ一致)かかりうる計算になる。

**修正**: `struct bm_peer_connector_config`に`stop_flag`フィールドを追加(NULL可、他の
optionalフィールドと同じ扱い)。`bm_peer_connector_thread`が自身の`stop_flag`を
`config.stop_flag`へ伝播し、`bm_peer_connector_connect_initial`の候補ループは各候補を
試す前に`*stop_flag`を確認、非0なら残り候補を一切試さず即座にループを抜ける。ただし
「今まさに接続/SOCKS5ハンドシェイク中の1件」だけは中断できないため、終了処理の残り時間は
最大25秒程度に短縮される(ゼロにはならない)。回帰テスト`tests/test_peer_connector_shutdown.c`
を新設(stop_flagを事前にセットした状態で呼ぶと、候補のratingが一切変化しない=1件も
接続を試みていないことを確認)、ctest 29件全通過。

### outbound addrメッセージ送信の実装(2026-08-23)

`addr`メッセージは受信(→peers.db登録)のみ実装済みで、自分から送信する処理が無かった
(受信専用)。onionpeer objectの中継について調べていた際に判明したギャップで、real
Bitmessageネットワークとの相互運用性向上のため実装した。設計はPyBitmessage本家
(`network/tcp.py`の`set_connection_fully_established`/`sendAddr`)に準拠。

**送信タイミング**: version/verack handshake完了時(=`verack`受信時)に1回だけ、その接続へ
返す(PyBitmessageの`set_connection_fully_established`と同じ)。周期的な再送や、新規学習した
addrのリアルタイム中継は行わない(PyBitmessage側もリアルタイム中継はflood/leak対策で
無効化されている)。

**候補フィルタ**(PyBitmessageの`sendAddr`準拠): `is_self=0`・`rating>=0`・`last_seen`が
直近3時間以内(`maximumAgeOfNodesThatIAdvertiseToOthers=10800`)・onionアドレス除外
(addrワイヤーフォーマットは固定16byte IPフィールドしか持たずonionアドレスを表現できない。
PyBitmessageも`not k.host.endswith('.onion')`で同様に除外)。rating降順で上限500件
(PyBitmessageの`maxaddrperstreamsend`既定値)。

**実装**: `core/peer_manager.c`に`bm_peer_manager_list_shareable`(既存の`list_top`に
上記フィルタを追加した専用クエリ)、`infra/protocol.c`に`bm_create_addr_message`
(`bm_parse_addr_message`と対称の、`bm_create_inventory_message`と同じ流儀のエンコーダ)、
`infra/object_sync.c`に`send_addr_reply`(候補取得→IPv4-mapped形式へ変換→wire化→送信、
`verack`受信ブランチから呼ぶ)を追加。`tests/test_object_sync.c`に回帰テストを追加
(rating<0・3時間超過・onionの3種を除外し、条件を満たす1件だけが送信されることを確認)、
ctest 29件全通過。

**副次的な発見**: PyBitmessage本家の`sendOnionPeerObj`は必ず空引数(`''`)で呼ばれており、
「knownnodesの他人のonion peerを代理でannounceし直す」機能は仕様上も実装上も無いことを
確認した(`peer`引数を明示的に渡すコードパスは存在するが実際には未使用)。伝播はあくまで
「各ノードが自分の分だけannounceし、それがobject floodingで中継される」方式のみ。うちの
実装(`bm_object_sync_announce_onion_peer`)もこれと一致している。
また、PyBitmessageは起動時1回に加え`class_singleCleaner.py`の約2時間おきの周期処理でも
onionpeer自己announceを再送しており(TTLも7日、うちは2日固定)、うちには無い定期再送が
本家には存在することが分かった。これは今回のaddr送信とは別件のため、backlogへ追記した
(次のセッションで別プランとして着手予定)。

### 重大バグ修正: `error`メッセージ受信がratingに一切反映されていなかった(2026-08-23)

実オニオンアドレスでの11時間超の連続稼働テスト中に、ユーザーが`peers.db`の`rating`が
ほとんど-0.5〜0の間で塩漬けになっていることに気づいた。ログを詳しく追ったところ、
`194.164.163.84`や`170.75.173.70`のような一部のpeerが、毎接続サイクルごとにversion/verack
ハンドシェイクまでは成功する(→`+0.1`)のに、直後に必ず`error message from peer: fatal=2
... "Server full, please try again later."`を送って切断してくる(→最終的な切断で`-0.1`)、
という状態を発見した。成功クレジットと失敗クレジットがサイクルごとにほぼ相殺するため、
**明確に接続を拒否されているpeerのratingが高いまま維持され、毎サイクル優先的に
再接続され続ける**実害があった(実際、過去のあるrun区間では1つのpeerに1789回も
再接続していた)。この少数のpeerが`bm_peer_manager_list_top`の上位を占拠し続ける一方で、
他の413件の候補には順番がなかなか回ってこず、初回の`-0.1`〜`-0.3`のまま塩漬けになる、
という見た目上の「大半がマイナス」という状態を作り出していた。

**修正**: `infra/object_sync.c`のerrorメッセージ受信ハンドラで、`fatal>=1`
(ワイヤーフォーマット仕様上0=Warning/1=Error/2=Fatal)を受信した時点で追加のペナルティ
(`-0.1`)を与えるようにした。これにより1サイクル全体(成功+error受信+最終的な切断)が
正味マイナスへ傾くようになり、明確な拒否を繰り返すpeerは自然にratingが下がって
他の候補に順番が回るようになる。`test_object_sync.c`に回帰テストを追加(専用の
`logical_peer_ip`付き接続でfatal=2のerrorを受信させ、rating 0.9の行が実際に下がることを
確認)、ctest 29件全通過。

### バグ修正: ログ上でonionアドレスのportが空になる(host:portバッファが62文字onionに対し小さすぎた)(2026-08-23)

上記調査中、`[peer_connector] connecting to xxxxx.onion: (via SOCKS5)...`のようにonion
アドレス宛のログでportが空になっているのに気付いた。v3 onionアドレスは56文字+".onion"で
62文字あり、当日夜のIPv6ログ修正(§11参照)で導入した`bm_network_format_host_port`の
呼び出し側バッファが`char addr_buf[64]`だったため、62文字のホスト名+":"で63文字使い
切ってしまい、port桁が入る余地が無く無言で切り捨てられていた。実際の接続処理自体は
`candidates[i].ip_address`/`.port`を直接使っており影響を受けていなかった(ログ表示のみの
問題)ため実害は無かったが、診断ログとしては機能していなかった。`peer_connector.c`
(3箇所)・`api_server.c`・`tor_control.c`・`main.c`の該当バッファを全て64→80byteに拡張。
回帰テスト`tests/test_network_format_host_port.c`を新設(IPv4/IPv6/62文字onionアドレスの
3パターンでport桁が切り捨てられないことを確認)、ctest 30件全通過。

### ログ行への時刻付与(`common/logging.c`、2026-08-23)

11時間超の連続稼働テスト中、ユーザーが「ログのどの行がいつのものか分からない」ことに
気付いた。`fprintf(stderr, ...)`には時刻が一切無く、実際にどの起動(run)のログなのか
行番号と`DB初期化完了`の区切りから推測するしかなかった(今夜の調査でも何度もこれで
手間取った)。

実運用ではsystemd配下での起動を想定しており、その場合journaldがログ受信時刻を別途
正確に記録するため、こちらで時刻を埋め込むと二重になってしまう。systemdはjournald接続の
stdout/stderrに対して環境変数`JOURNAL_STREAM`をセットするので、これを起動時に一度だけ
確認する薄いロガー`common/logging.c`(`bm_log_init()`/`bm_log()`)を新設した。

- `JOURNAL_STREAM`が未設定(手動nohup運用等) → 既定で`[YYYY-MM-DD HH:MM:SS] `を先頭に付与
- `JOURNAL_STREAM`が設定済み(systemd/journald配下) → journald側が記録するため付与しない
- `BM_LOG_TIMESTAMPS=0/1`で明示上書き可能(自動判定が外れた場合の保険)

`main.c`/`infra/*.c`(全ファイル)/`core/config_file.c`・`api_server.c`・`peer_manager.c`・
`common/db_common.c`の`fprintf(stderr, ...)`診断ログ呼び出し(約120箇所)を`bm_log(...)`へ
一括置換した。`cli/main.c`(`bitmessage-cli`のUsage/エラー出力、対話コマンドの直接応答であり
daemonのログストリームとは性質が違う)は対象外とした。ログレベル(DEBUG/INFO/WARN/ERROR)の
導入は今回スコープ外とし、別途backlogとした(既存呼び出し箇所を1つずつ分類し直す作業が
必要で、機械的な今回の置換とは規模が違うため)。回帰テスト`tests/test_logging.c`を新設
(`BM_LOG_TIMESTAMPS`明示指定・`JOURNAL_STREAM`検出・既定値の4パターンを確認)、
ctest 31件全通過。

### 重大バグ修正: onion peerのrating/last_seenが一切更新されていなかった(`logical_peer_ip`が62文字onionアドレスに対し小さすぎた)(2026-08-23)

ユーザーが「logで接続したonion peerと時刻が、peers.dbのonion peerの時刻と一致していない」
ことに気付いた。実際に稼働中daemonのログとDBを突き合わせたところ、直近(数分以内)に
onion peerとのverack受信が複数回成功しているにもかかわらず、`peers.db`のonion peer行の
`last_seen`は40分以上前(今回の起動より前)のまま一切更新されていないことを確認した。

**原因**: `infra/network.h`の`struct bm_fd_data.logical_peer_ip`が`char[46]`
(`INET6_ADDRSTRLEN`相当)で、v3 onionアドレス(56文字base32+".onion"=62文字)を
保持できるサイズが無かった。`peer_connector.c`が`candidates[i].ip_address`
(`peer_manager.h`の`bm_peer_entry.ip_address[64]`、正しく62文字収まるサイズ)を
`logical_peer_ip`へ`strncpy`する際、45文字+NULへ黙って切り捨てられていた。この
切り捨てられた文字列が`bm_peer_manager_record_result`等のSQL`WHERE ip_address = ?`
の照合キーに使われるため、peers.dbの本物の行(フルの62文字)とは絶対に一致せず、
0行ヒットのままrating/last_seen更新が静かに失敗し続けていた(同種の切り捨てバグは
当日夜の別のログ表示バグ(`peer_connector.c`のhost:portバッファ)と同根で、いずれも
「IPv4/IPv6用に想定したサイズがv3 onionアドレスの長さを見落としていた」パターン)。

**影響範囲**: `bm_network_resolve_peer_ip_port`の戻り値を受け取る全ての箇所が同様に
影響を受けていた: `network.c`(切断時のrating失敗記録)、`peer_registry.c`
(`bm_peer_registry_has_peer`の二重接続防止・Dandelion stem peer選定)、
`object_sync.c`(`record_outbound_success`・error受信ペナルティ)、`dandelion.c`
(stem successorの記憶・比較)。dedup/stem比較は「切り捨てられた同じ45文字同士」を
比較するため偶然壊れずに機能していたが、peers.dbとの照合を伴うrating/last_seen更新は
確実に0行ヒットで失敗していた。

**修正**: `network.h`に`#define BM_PEER_IP_STRLEN 64`(`bm_peer_entry.ip_address[64]`と
揃えたサイズ)を新設し、`logical_peer_ip`本体および上記全箇所のローカルバッファを
`INET6_ADDRSTRLEN`/`46`から`BM_PEER_IP_STRLEN`へ置き換えた。回帰テストを
`tests/test_peer_rating_on_disconnect.c`へ追加(シナリオ4: 62文字onionアドレスを
`logical_peer_ip`に設定してverackを流し込み、peers.dbの該当行のratingが実際に
更新されることを確認)、ctest 31件全通過。

### バグ修正: `bm_log`がマルチスレッドから同時に呼ばれるとログ行が混ざる(2026-08-23)

ユーザーが実daemonのログで以下のような出力を発見:

```
[2026-08-23 15:31:45] [2026-08-23 15:31:45] [object_sync] error message from peer: ...
[peer_connector] connected to xxxxx.onion:8444, version sent
```

時刻が2つ並んだ行と、時刻が全く無い行が隣接している。原因は`common/logging.c`の
`bm_log`が「時刻部分」と「本文部分」を別々の`fprintf`呼び出しに分けていたこと。
bitmessagedはマルチスレッド(`object_sync`/`peer_connector`/`network`等)であり、
stdioの個々の呼び出し自体はストリームごとの内部ロックでスレッドセーフだが、
「呼び出しをまたいだ」順序は保証されない。そのため2回の呼び出しの間に別スレッドの
`bm_log`が丸ごと割り込み、時刻2つ+片方のメッセージが1行に、もう片方のメッセージが
時刻無しで次行に、という形で混ざっていた。

**修正**: `vsnprintf`で本文を一旦バッファ(4096byte)へ組み立ててから、時刻込みで
単一の`fprintf`(または`fputs`)呼び出しにまとめるよう変更した。これにより1回の
`bm_log`呼び出しが単一のstdio呼び出しになり、他スレッドの出力と混ざらなくなる。
回帰テストを`tests/test_logging.c`へ追加(8スレッド×200回、それぞれ
`threadN-iterM`という一意な内容を同時に書き込み、全600行が一切混ざらず・欠落せず・
重複せず出力されることを確認)、ctest 31件全通過。

### peer接続選定を確率的な重み付きランダムサンプリングへ変更(2026-08-23)

11時間超の運用テスト中、ユーザーが「rating上位の少数peerだけが毎サイクル(~30秒おき)
接続され続けている」ことに気付いた。実測では直近5分間で40件の候補中、9件が11回以上
(最大222回、ほぼ毎サイクル)再接続される一方、25件は1回しか試されていなかった
(平均すると1サイクルあたり約3.56件の新規接続が発生、`194.164.163.84:8444`は
観測した223サイクルのほぼ全てで再接続されていた)。

**原因**: `infra/peer_connector.c`の`bm_peer_connector_connect_initial`が、
`bm_peer_manager_list_top`(`ORDER BY rating DESC LIMIT 32`)で取得した「rating上位32件」を
毎回そのまま順に接続候補として使っていた。これらの上位peerの一部は接続してもすぐ
切断される(原因未特定、明示的なerrorメッセージが伴わないサイレントな切断も含む)が、
verack成功(+0.1)と切断失敗(-0.1)がサイクルごとにほぼ相殺するためratingは高いまま
維持され、永久に上位を占拠し続ける「強者総取り」状態になっていた。また`MAX_CANDIDATES`
(32)自体もpeers.dbの大半(実測417件中385件)を選定対象からこぼしていた。

**修正**: PyBitmessage本家(`network/connectionchooser.py`の`chooseConnection`)を
調査したところ、決定的な「rating上位N件」ではなく確率的な重み付きランダムサンプリングを
使っていることが分かった: 候補から毎回一様ランダムに1件選び、ratingに応じた確率
(`0.05/(1-rating)`、rating=0で5%、rating=0.9で50%、rating>=1.0で無条件採用)で
採用するかどうかを判定し、棄却されたら別の候補を再度試す(最大50回)。これを
`bm_peer_connector_choose_candidate_index`として移植した(`infra/peer_connector.c`/`.h`)。
`MAX_CANDIDATES`も32→256へ拡大した。既存の`bm_peer_manager_list_top`(SQL・契約とも
他のテストが依存しているため)は変更せず、`peer_connector.c`の選定ロジックだけを
差し替えるスコープに閉じた。PyBitmessageの「discovered peer(LAN発見)優先」「bootstrap
serverモード用cooldown」「onion rating強制ブースト」は今回は対象外(前者2つは無関係、
onion優遇は実データで既に自然に高rating傾向のため見送り)。

回帰テスト`tests/test_peer_connector_choose.c`を新設(rating 0.9×5件・-0.9×5件・0.0×240件を
用意し20000回選定を繰り返して分布を集計。下位候補にも非ゼロな確率で順番が回ること、
上位候補の方が1件あたり明確に高い頻度(実測で約19倍、理論値の`0.5/0.0263`とほぼ一致)で
選ばれることを確認)、ctest 32件全通過。

### inbound接続のアイドル/ハンドシェイクタイムアウト + keepalive ping送信(2026-08-23)

backlog項目1(2026-08-21洗い出し)に着手。`infra/network.c`の`bm_network_epoll_thread`は
`epoll_wait(..., -1)`で無限待機固定で、TCP接続だけ確立して何も送ってこない相手を
切断する仕組みが無かった。inbound(Stage 1/2)を有効化した以上、実質的なslowloris
タイプのリソース枯渇経路になりうる懸念があった。

**設計**: PyBitmessage本家(`network/connectionpool.py`のメインループ)を調査したところ、
「ハンドシェイク未完了のまま20秒経過したら切断、fully established後はidleTimeout
(既定300秒)経過ごとにpingを送るだけ(切断はしない)」という仕組みを持っていた。この
値・方針をそのまま踏襲した。`lastTx`(最終活動時刻)は本家では読み書き両方で更新される
が、うちでは簡略化してREAD成功時のみ更新(central dispatch点である
`bm_network_handle_readable`の1箇所で済む)し、pingを送った直後だけその場で
`last_activity`を更新することで「無応答の相手へping spamし続ける」のを防ぐ、という形にした。

**実装**: `struct bm_fd_data`(`network.h`)に`last_activity`/`handshake_complete`を追加。
`handshake_complete`は`object_sync.c`のverack受信ブランチで立てる(inbound/outbound
問わず、verack受信時点で双方向のversion/verack交換が完了しているため)。
`bm_network_epoll_thread`の`epoll_wait`タイムアウトを`-1`→5秒に変更し、socket活動が
無くても定期的に`bm_network_idle_sweep(args, now)`(新設、`now`を明示引数に取り
テストが壁時計待ちせず呼べるようにした、`bm_peer_manager_cleanup`等と同じ慣習)を
呼ぶようにした。既存の「切断時クリーンアップ」処理(rating失敗記録・registry除去・
epoll登録解除・close・free)は`close_connection`として切り出し、読み取り失敗時の
既存パスと新設のアイドルタイムアウトパスの両方から共有する。`peer_registry.c`に
汎用イテレータ`bm_peer_registry_for_each`を新設(ロック中はポインタのスナップショット
だけ取り、実処理はロック解放後に行うことでcallbackが`bm_peer_registry_remove`を
呼んでも再帰ロックにならないようにした)。

回帰テスト`tests/test_idle_sweep.c`を新設(固定の`now`を使い、ハンドシェイク未完了
接続が境界の前後で切断される/されないこと、fully established接続がタイムアウト後に
実際に`ping`パケットを送信しつつ切断はされないことを確認)、ctest 33件全通過。

### inbound接続のレート制限(DoS対策)(2026-08-23)

backlog項目2に着手。実際に相手ノードから「Too many connections from your IP」で
拒否される場面をログ上で観測していた一方、こちら側には対応する制限が無かった。
実ネットワーク上の未知のnodeからの着信を受け付ける以上、素朴なリソース枯渇型DoSの
入口になりうるという懸念から、実際のinbound到達実績(daemon-b-inbound-testでの
2件の成功接続確認)を待たずに先に着手した。

**設計上の制約**: Tor hidden service経由のinboundは`accept()`で見える接続元が
常にTorのローカル転送(`127.0.0.1:<ephemeral>`)になり、生IPベースのレート制限は
originally intended targetを区別できず機能しない(全接続が同一IPに見えるため、
早期に全遮断するか無意味になるかのどちらかになる)。そのためIPに依存しない
2種類の制限を設けた。

**実装**:
- 同時接続数の上限(`BM_MAX_INBOUND_CONNECTIONS`=64、`network.h`)。
  `peer_registry.c`に`bm_peer_registry_count_by_type`を新設(既存の
  `bm_peer_registry_count`はoutbound/inbound合算のため、inbound専用の上限判定には
  使えなかった)。
- 単位時間あたりのaccept数の上限(`BM_INBOUND_ACCEPT_MAX_PER_WINDOW`=20 /
  `BM_INBOUND_ACCEPT_WINDOW_SECONDS`=10秒、固定窓カウンタ)。`struct
  bm_inbound_rate_limiter`(`network.h`)として新設し、`bm_network_epoll_thread`の
  1ループぶんの`now`(idle_sweepと共有、`time(NULL)`呼び出しを1回に節約)を明示引数に
  取る(`bm_inbound_rate_limiter_allow`、他の時刻依存ロジックと同じテスト容易性の慣習)。
  状態は`struct bm_epoll_thread_args`に`inbound_rate_limiter`フィールドとして持たせ、
  `main.c`起動時に`bm_inbound_rate_limiter_init`で初期化する。
- どちらの上限も超過時は`accept()`自体は行った上で即座に`close()`する(listen
  backlogキューに溜め続けさせず、次の接続試行にすぐ空きを渡すため。recv_buffer確保や
  handshake処理は一切しない)。
- 既存のprivate関数`handle_accept`を`bm_network_handle_accept`として公開した
  (`bm_network_idle_sweep`と同様、テストがepollスレッド自体を起動せず直接呼べるように
  するため)。

**テスト**: `tests/test_inbound_rate_limit.c`を新設。単体テスト(窓カウンタの境界値・
リセット)に加え、実listenソケット+実クライアント接続を使った統合テストも書いた。
統合テストの初版では、同時接続数上限のケースを検証するために
`BM_MAX_INBOUND_CONNECTIONS+2`本(66本)ものTCP接続を先にqueueさせてから
`bm_network_handle_accept`を1回呼ぶ実装にしたが、`bm_network_listen`のlisten
backlog(16)を大幅に超えるconnect()を同時に発行することになり、backlogに
入りきらない分の`connect()`がカーネルのSYNリトライで長時間ブロックし、ctest全体が
13分以上ハングする事故を起こした(ユーザーからの「長いですね……」の指摘で発覚)。
実際に大量のTCP接続を同時にqueueさせる方式は避け、`bm_peer_registry_add`で
registryへ合成のinbound接続(socketpair)をあらかじめ上限ぶん直接投入して「既に
上限に達している」状態を決定的に作った上で、実クライアントを1本だけ接続して
検証する方式に書き直した(レート制限側の検証も同様に、`bm_inbound_rate_limiter_allow`
を直接呼んで窓を使い切ってから実クライアント1本で検証)。ctest 34件全通過。

DESIGN.md執筆時点でのユーザーからの申し送り: 各定数(`BM_MAX_INBOUND_CONNECTIONS`
等)は現状ハードコードのままとした。実運用でこの上限に頻繁に到達するようであれば、
`core/config_store.c`(SOCKS5プロキシ設定と同じ枠組み)への設定化を検討する
(未着手、次回以降の判断待ち)。

### 運用メモ: daemon再起動時のonionアドレス復元手順(2026-08-23)

上記のレート制限機能をdaemon Aへ反映する再起動作業中に判明した運用上の注意点。
`BM_ONION_ADDRESS`は環境変数としてのみ渡す設計(§11「自己接続の防止」節参照、
onionアドレス自体は一切git管理下に置かない方針)のため、プロセスを一度落とすと
`/proc/<pid>/environ`からの復元経路も失われる。この場合、Tor hidden serviceの
`HiddenServiceDir`配下の`hostname`ファイルから読み直す必要があるが、以下2点に
注意する。

1. **`HiddenServiceDir`は`debian-tor:debian-tor`所有・`0700`で非対話的に読めない**。
   `sudo -n cat`はパスワードキャッシュが無ければ失敗する(このリポジトリの操作環境は
   `sudo`にTTYを割り当てられないため、Claude Code側からの`sudo`実行は原理的に不可能)。

   **`setfacl`による回避は失敗、絶対にやらないこと**: 当初
   `sudo setfacl -m u:<user>:x /var/lib/tor`等でACLを付与し非rootでの読み取りを
   実現したが、その状態で(権限確認のため)`systemctl restart tor@default.service`
   した結果、Torが`Permissions on directory /var/lib/tor/bitmessage/ are too
   permissive.` / `Failed to parse/validate config` でCONFIG読み込みに失敗し
   `tor@default.service`が起動不能になった(実際に発生させてしまった障害)。
   Torの`check_private_dir`はオクテット表記のパーミッションだけでなく拡張ACL
   エントリの存在自体を「too permissive」として拒否する。`setfacl -b`で全ACLを
   削除し`systemctl restart tor@default.service`することで復旧したが、
   **Tor管理下のディレクトリ・ファイルへのパーミッション変更(ACL含む)は
   一切行わないこと**。恒久的な解決策は次回セッションで検討する(候補:
   onionアドレスをTorのファイルからではなくユーザー管理の非追跡ファイル
   (例: `~/.bitmessage_onion`、0600、非Tor所有)に複製して保持する、または
   このcatコマンド1つに限定したsudoers NOPASSWDルールを設ける、等。
   いずれも未着手)。
2. **`hostname`ファイルの内容には末尾に空白文字(おそらく`\r`)が1文字混入しており、
   単純な`$(cat hostname)`だと62文字であるべきv3 onionアドレスが63文字になり、
   `bm_object_sync_ctx`の`OBJECT_ONIONPEER`自己announce構築が
   `failed to build onionpeer object (malformed onion address?)`で毎回黙って
   失敗し続ける**(daemonの起動自体は成功するため気づきにくい)。
   `tr -d '[:space:]'`で明示的にトリムしてから`BM_ONION_ADDRESS`へ渡すこと。

**恒久的な解決策として採用したもの(2026-08-23、ユーザー提案)**: `main.c`の
起動時設定読み込みには元々`env var(`BM_ONION_ADDRESS`) > bitmessage.confの
`[tor] onion_address` > 組み込みの既定値`という優先順位が実装済みだった
(`core/config_file.c`の`onion_address`フィールド、既存コード。今回新規実装した
ものではない)。`bitmessage.conf`自体は`.gitignore`で最初から除外されている
(`git check-ignore`で確認済み)ため、ここへ一度書いておけば以後の再起動では
`BM_ONION_ADDRESS`を毎回用意する必要が無く、Torの`hostname`ファイルにも
(パーミッション変更は言うまでもなく、読み取りすら)一切触れずに済む。今回は
稼働中daemon Aの`/proc/<pid>/environ`から(生きているプロセスの環境からなら
`setfacl`等の危険な回避策無しに読める)値を1回だけ複製し、`bitmessage.conf`へ
追記して解決した。今後onionアドレスが変わる(Tor hidden serviceを作り直す等)場合を
除き、この節の1.の問題自体を再び踏む必要は無くなったはず。

### プロトコルバージョン互換性チェック(2026-08-23)

backlog項目3に着手。これまで`ver.version`を受信してログに出すだけで、
最低対応バージョンを下回るnodeを弾く処理が無かった。

**設計**: PyBitmessage本家(`network/bmproto.py`の`peerValidityChecks`)を調査した
ところ、`remoteProtocolVersion < 3`の相手には`fatal=2`のerrorメッセージ
(`"Your is using an old protocol. Closing connection."`、原文ママのタイプミースも
含め忠実に踏襲)を送った上でverackを送らずに切断する、という実装だった
(`peerValidityChecks`は同時に`timeOffset`検証・共有stream有無・重複IP接続も
チェックしているが、今回はbacklog項目3の範囲であるバージョンチェックのみ移植した)。
この関数は同じファイルの`bm_command_version`(受信したversionのパース直後、
verack送信より前)から呼ばれている。

**実装**:
- `infra/protocol.h`に`BM_MIN_PROTOCOL_VERSION`(=3)を追加。
- `infra/protocol.c`に`bm_create_error_message(fatal, ban_time, error_text,
  out_len)`を新設(既存の受信側パース処理と対称のエンコーダ、`bm_create_packet`を
  内部で使う。vectorは常に空文字列固定、接続全般への苦情ではobjectのhashを指す
  意味が無いため)。
- `infra/network.h`の`struct bm_fd_data`に`should_disconnect`フラグを追加。
  コマンドハンドラ(`object_sync.c`)がメッセージ処理の結果「この接続を切るべき」と
  判断した場合に立てる、汎用の仕組みとして設計した(今回のバージョンチェック専用に
  せず、将来同様の「受信した内容次第で切断すべき」判定が増えても使い回せるように
  した)。ハンドラ自身はfdをcloseせず、必要なerrorメッセージを書き込んだ上でこの
  フラグだけ立てて返る。`network.c`の`bm_network_handle_readable`がハンドラ呼び出し
  直後にこのフラグを見て、戻り値-1(既存の読み取りエラー経路、`close_connection`
  経由でrating失敗記録・registry除去・epoll登録解除・closeまで一括処理される)へ
  合流させる。
- `infra/object_sync.c`の`version`コマンド処理の先頭(ログ出力の直後、
  `conn->services`設定より前)でバージョンチェックを行う。閾値未満ならerror送信+
  `should_disconnect=1`を立てて即returnし、以降の通常処理(services記録・rating
  成功記録・verack返信)を一切行わない。

**テスト**: `tests/test_object_sync.c`にシナリオ11を追加(専用socketpair、他
シナリオとの取り違え防止)。(a) version=2を送ると`should_disconnect`が立ち、
verackではなくfatal=2のerrorメッセージだけが返ること、(b)
version=`BM_MIN_PROTOCOL_VERSION`(境界値)では従来通りverackが返ること、の両方を
`bm_new_version_message`で実際のwireパケットを組み立てて確認した。ctest 34件全通過。

### version messageのtimestamp検証(2026-08-23)

backlog項目4に着手。`ver.timestamp`はパースするだけで一切使っていなかった。

**設計**: PyBitmessage本家の`peerValidityChecks`(前項のバージョンチェックと同じ関数)
には、バージョンチェックのすぐ後に`timeOffset`(相手のtimestamp - 自分の現在時刻)が
`MAX_TIME_OFFSET`(`protocol.py`で3600秒=1時間)を超えたら(未来・過去どちらの方向でも)
`fatal=2`のerrorを送って切断する処理があった。これをそのまま移植した。PyBitmessage側は
併せて`timeOffsetWrongCount`という「時計がズレたpeerが一定数を超えたらGUIの
ステータスバーに『あなたの時計がズレているかも』と警告する」仕組みも持っているが、
これは完全にGUI専用の機能でこのヘッドレスdaemonには対応するUIが無いため移植対象外とした
(`BM_MIN_PROTOCOL_VERSION`のバージョンチェックと同様の理由でスコープを絞った)。

**実装**: `infra/protocol.h`に`BM_MAX_TIME_OFFSET_SECONDS`(=3600)を追加。
`infra/object_sync.c`の`version`コマンド処理で、前項のバージョンチェックの直後に
`time_offset = (int64_t)ver.timestamp - (int64_t)time(NULL)`を計算し、
`|time_offset| > BM_MAX_TIME_OFFSET_SECONDS`ならバージョンチェックと全く同じ
パターン(fatal=2のerrorメッセージ送信+`conn->should_disconnect=1`+即return)で
切断する。未来方向/過去方向でエラーメッセージの文言をPyBitmessageに合わせて
出し分けた。この時点で`bm_create_error_message`(前項で新設)と`should_disconnect`
フラグ(同じく前項で新設した汎用の切断シグナル)の両方をそのまま再利用でき、
新規のインフラ追加は不要だった。

**テスト**: `tests/test_object_sync.c`にシナリオ12を追加。`bm_new_version_message`は
常に`time(NULL)`をtimestampに使うため、意図的な時計ズレを再現する専用ヘルパー
`build_version_packet_with_timestamp`(`bm_create_version_payload`で組み立てた後、
timestampフィールドだけ`htobe64`で上書き)を新設した。(a)未来方向に大きくズレた
timestampで切断されること、(b)過去方向に大きくズレたtimestampで切断されること、
(c)境界値(ちょうど`BM_MAX_TIME_OFFSET_SECONDS`)は許容されverackが返ることの3点を
確認した。ctest 34件全通過。

### バグ修正: onionアドレスが不正でもis_self行がpeers.dbへ書き込まれていた(2026-08-23)

ユーザーがobject_pool.db/peers.dbの中身を`sqlite3`で直接調べていて発覚。今夜の
onionアドレス復旧トラブル(前述の運用メモ参照)の過程で、`BM_ONION_ADDRESS`が
空文字列だった回・末尾に空白が混入した63文字の回、それぞれの起動時に`peers.db`へ
`is_self=1`の壊れた行(`ip_address`が空文字列/63文字)が作られていたことが分かった。

**原因**: `main.c`の`bm_peer_manager_mark_self()`呼び出しが、直前の
`bm_object_sync_announce_onion_peer()`の成功可否(`bm_build_onionpeer`の長さ検証)を
見ずに無条件で呼ばれていた。ログ出力だけが成功時条件付きになっており、DB書き込みは
条件から漏れていた。

**実害**: `bm_peer_manager_list_top`(接続候補選定)は`is_self = 0`でしか絞り込まないため、
壊れた`is_self`行が接続候補として選ばれることは無く、機能的な実害は無かった(単なる
DBの汚れ)。

**修正**: `bm_peer_manager_mark_self`呼び出しを`bm_object_sync_announce_onion_peer`の
成功分岐(`== 0`)の内側へ移動した。稼働中daemon Aの`peers.db`から既存の壊れた行2件
(空文字列/63文字)も直接`DELETE`で削除し、正しい62文字の行(以前から存在していた)
だけを残した。ctest 34件全通過(既存テストの回帰確認のみ、専用の新規テストは追加
していない。理由: `bm_peer_manager_mark_self`自体の単体動作は既に
`tests/test_peer_manager_self.c`で検証済みで、今回のバグは「呼ぶかどうかの条件分岐」
というmain.c内の配線ミスであり、main.cの起動シーケンス全体は自動テストの対象外
(cli_integration.shが実バイナリの起動はカバーするが、onion関連の分岐は
BM_ONION_ADDRESS未設定のCI環境では通らない)。

### listConnections API(MVP)(2026-08-23)

backlog項目5に着手。ユーザーと相談し、まずPyBitmessage本家と同等のMVP(host/port/
fullyEstablished/userAgent)のみを実装し、送受信バイト数(前セッションで設計だけ
詰めていた発展項目)は別タスクとして切り出すことにした。

**設計**: PyBitmessage本家(`api.py`の`HandleListConnections`)の戻り値形式
`{"inbound": [...], "outbound": [...]}`(各要素`{host, port, fullyEstablished,
userAgent}`)をそのまま踏襲した。

**実装**:
- `infra/network.h`の`struct bm_fd_data`に`char *user_agent`を追加。
  `object_sync.c`のversion受信処理(プロトコルバージョン/timestampチェックを
  通過した後)で、`bm_free_version_message`する前に`strdup`して複製する。
  `bm_fd_data_free`でfreeする。
- `infra/peer_registry.c`に`bm_peer_registry_for_each_locked`を新設。既存の
  `bm_peer_registry_for_each`はロックを早期解放してからcallbackを呼ぶ設計だが、
  これは呼び出し元がnetwork_epoll_threadという単一スレッドの中だけで動く前提
  (idle_sweep等)だったため安全だった。api_server.cのlistConnectionsは別スレッド
  (APIサーバのaccept loop)からconnのフィールドを読むため、ロック解放後に
  network_epoll_thread側で該当connがclose_connection経由でfree()される
  use-after-freeを起こしうる。`for_each_locked`はロックを持ったままcallbackを
  呼ぶことでこれを防ぐ(callback側がbm_peer_registry_remove等、同じmutexを
  再度lockする関数を呼ばないことが前提の変種)。
- `core/api_server.h`の`struct bm_api_server_config`に`struct bm_peer_registry
  *registry`(NULL可)を追加。`core/api_server.c`に`h_listConnections`を実装し
  `METHODS[]`へ登録した。
- `main.c`: `peer_registry`の初期化(元は`api_server`スレッド起動より後だった)を
  `api_config`構築より前へ移動する必要があった(`api_config.registry`が
  そのアドレスを持つため、未初期化の変数のアドレスを渡すわけにはいかない)。

**テスト**: `tests/test_api_server.c`にlistConnectionsシナリオを追加。socketpairで
outbound 1本(handshake完了・user agent設定済み)・inbound 1本(handshake未完了)を
registryへ直接登録し、それぞれが正しい配列・フィールドで返ることを確認した。ctest
34件全通過。

**CLI連携の抜け(ユーザー指摘、同日中に追加)**: 既存の全APIメソッドは
`bitmessage-cli`に1:1でサブコマンドが用意されている慣習があったが、
listConnections実装時にそこを見落としていた。`cli/main.c`へ`list-connections`
(引数無し、`listConnections`をそのまま呼ぶだけ)を追加し、usageにも追記した。
実daemon Aに対して動作確認済み。ctest 34件全通過(既存の`cli_integration.sh`が
`bitmessage-cli`バイナリ自体のビルドはカバーするが、個々のサブコマンド網羅は
対象外のため専用の新規テストは追加していない)。

### ログ改善: 読み取りエラー/EOFによる接続切断が無言だった(2026-08-23)

listConnections APIの動作確認中にユーザーが発見。実daemon Aへ`listConnections`を
何度呼んでも`inbound`/`outbound`とも空配列ばかり返ってきたため調査したところ、
`/proc/<pid>/net/tcp`で見るとoutbound接続のfdが確認するたびに入れ替わっており、
接続が数秒〜十数秒単位の高頻度で切断されていることが判明した(`listConnections`
自体は正確にその瞬間の空を反映していただけで、バグではなかった)。

この調査で副次的に見つかったのが、`bm_network_epoll_thread`の読み取りエラー/EOFに
よる切断経路(`rc != 0`分岐)が`close_connection`を呼ぶだけで一切ログを出していない
という非対称さ。`bm_network_idle_sweep`側の能動的切断(ハンドシェイクタイムアウト)は
ログを出すのに対し、こちらの「相手から切られた」経路は完全に無言だった。今夜のような
高頻度churnはこのログが無かったため今まで全く見えていなかった。

`network.c`の`rc != 0`分岐に`bm_log("[network] closing %s connection (fd=%d): %s\n",
...)`を追加し、`rc==1`(EOF)/`rc==-1`(読み取りエラー)を区別して出力するようにした。
ctest 34件全通過(専用の新規テストは追加せず、ログ文言はアサート対象外という
既存の慣習に合わせた)。

### ログ改善: inv/dinv受信の正常系にログが無かった(2026-08-23)

ユーザーの指摘で発覚。`handle_inv`(`object_sync.c`)はmalformed/上限超過等の異常系にしか
ログを出しておらず、正常にinv/dinvを受信・処理した場合(何件受信し何件getdataを
送ったか)は完全に無言だった。直前に見つけた「読み取りエラー/EOFによる切断が無言
だった」件と同種の穴。

`bm_free_inventory_message`直後(getdata送信より前)に
`bm_log("[object_sync] received %s: %llu item(s), %zu missing\n", msg->command,
received_count, missing_count)`を追加した(`msg->command`で"inv"/"dinv"どちらかを
区別する)。ctest 34件全通過(ログ文言は既存の慣習通りアサート対象外)。

### 重大な機能欠落の発見・修正: handshake完了時に自分のobject一覧を送っていなかった(sendBigInv)(2026-08-23)

ユーザーからの疑問(「version/verackの後に相手からaddrが最初に来るのでは、プロトコル
順序を間違えてinvまで進めていないのでは」)がきっかけで発覚。PyBitmessage本家
(`network/tcp.py`)の`set_connection_fully_established`(docstring: "Initiate
inventory synchronisation")を確認したところ、handshake完了時に`sendAddr()`
(実装済み)に加えて`sendBigInv()`(自分が保有する全objectのhashを新規peerへ知らせる、
50,000件区切りでチャンク送信)を無条件で呼んでいたが、**うちには`sendBigInv`相当が
丸ごと存在しなかった**(DESIGN.mdにも記載無し、backlogにすら挙がっていなかった)。

**実害の見立て**: 新規に繋がった実peerから見ると、うちは「何も持っていない役に
立たないノード」に見えてしまい、相手からgetdataが一切来ない(=うちが保有する
objectが他ノードへ伝播しない)。今夜観測していた「verack受信→addr送信直後に
Connection resetされる」というパターン(SOCKS5を外しても再現し、かつログの
544行目=プロジェクト最初期から起きていたことを確認済み)についても、こちらが
まともに喋らないノードに見えることが遠因の可能性がある(確証は無いが、少なくとも
本家との明確な仕様差分であり優先して埋めるべき欠落だった)。

**実装**:
- `infra/object_store.h/.c`に`bm_object_store_list_hashes_by_stream(db, stream,
  now, out_hashes, out_count)`を新設。指定streamの未期限切れobject hashを全件
  取得する(COUNT→malloc→SELECTの2段クエリ)。
- `infra/object_sync.c`に`send_big_inv(ctx, conn)`を新設。取得した全hashについて
  `bm_decide_propagation`(DESIGN.md §9.2の差し込み点、`bm_peer_registry_
  broadcast_inv`と同じ経由方針)でFLUFF/STEM/SKIPを判定し、FLUFFは"inv"、STEMは
  "dinv"としてそれぞれ`BM_MAX_INVENTORY_ITEMS`(50000、本家のMAX_OBJECT_COUNTと
  同値)件ずつチャンク送信する。新規接続がstem successorに選ばれていることは
  通常無い(選定は既存のoutbound接続の中からのみ行われるため)ため、実質的には
  「stemタイムアウト前でSKIP判定されたhashだけがbigInvから除外される」形になり、
  本家の「stem中のhashは除外する」という方針と結果的に一致する。
- verack受信ハンドラで`send_addr_reply`の直後に`send_big_inv`を呼ぶ(addr→bigInvの
  順、本家と同じ)。

**テスト**: `tests/test_object_sync.c`にシナリオ13を追加。object_pool_dbをクリアし
既知の2件だけを種として使い、verack送信直後に届く"inv"メッセージが正しくその2件の
hashを含むことを確認した。ctest 34件全通過(既存シナリオ10もsend_big_invが割り込む
形になったが、書き込み順序がaddr→bigInvのため既存の「最初の1メッセージだけ読む」
アサーションには影響しないことを確認済み)。

### テストカバレッジの穴の解消: inbound接続でのaddr/big inv送信(2026-08-23)

sendBigInv実装直後、ユーザーから「outboundから接続を受けたとき(inbound)でも
verack後にaddr/invを送っていたか」と確認された。コードを読んだ結果、
`object_sync.c`のverackハンドラは`conn->type`による分岐が無く
「inbound/outbound問わず」addr/big inv送信を行う設計だったが、実際に
`BM_FD_SERVER_SOCKET`(inbound、相手から接続してきた側)がverackを受信するケースを
直接検証しているテストが無かったことが判明した(`tests/test_inbound.c`は
「inbound接続が相手のversionを受けてverack+versionを送り返す」ところまでしか
カバーしておらず、その後こちらが相手からのverackを受信する側は未検証だった)。

`tests/test_object_sync.c`にシナリオ14を追加。シナリオ13(outbound版)と同じ
検証を`BM_FD_SERVER_SOCKET`で行い、`conn->handshake_complete`が1になることと、
種として仕込んだ2件のhashを含む"inv"が正しく送られることを確認した。実装コード自体の
変更は無し(既存実装が正しいことをテストで裏付けただけ)。ctest 34件全通過。

### 重大な性能バグ修正: dandelion.cのhash探索がO(n^2)だった(2026-08-23)

sendBigInv実装直後、コードを見直していて発覚。`dandelion.c`の`find_or_create_entry`
(`bm_dandelion_note_source`・`bm_dandelion_decide`の両方が使う内部関数)が
`g_state.entries`配列を先頭から線形探索(`memcmp`)しており、`handle_inv`(受信した
未所持hashごとに呼ぶ)や今夜実装した`send_big_inv`(保有する全hashごとに呼ぶ)が
実質O(n^2)になっていた。今夜object_pool.dbが約1万件規模まで育った状態で
`send_big_inv`を1回呼ぶだけで概算5000万回超の`memcmp`が発生する計算になり、
`g_state.lock`を握ったまま単一の`network_epoll_thread`全体を一瞬(新規peer1件あたり
概算0.2〜0.5秒)止めていたことになる。しかもobject_pool.dbが増えるほど二次関数的に
悪化する(上限の50,000件まで育てば1回あたり数秒規模)。相手から見ると
「handshake後しばらく応答が無いnode」に見えてタイムアウト切断されうるため、今夜
ずっと観測していた接続churnの有力な一因と考えられる。

**修正**: オープンアドレッシング(線形探索、hashの先頭8byteをキーにした単純なもの。
Bitmessageのhashは既に暗号学的ハッシュ値のため先頭8byteだけで十分一様分布する)の
ハッシュテーブルを`g_state`へ追加した(`index_slots`/`index_capacity`)。
`find_or_create_entry`はまずこのテーブルで既存エントリを探し(O(1)平均)、無ければ
`g_state.entries`へ追記した上でテーブルにも登録する。負荷率が50%を超えたら
テーブルを倍に拡張して作り直す(`index_ensure_capacity`/`index_rebuild`)。
`g_state.entries`自体は`bm_dandelion_expire_and_refluff`の定期的な全走査
(fluffタイムアウト判定・古いエントリの間引き)用に配列のまま維持し、間引きで要素の
位置がずれた場合のみインデックスを作り直す(その関数自体が既にO(n)のため、
再構築を足しても計算量は変わらない)。

**テスト**: `tests/test_dandelion_index.c`を新規追加。50,000件(実運用の上限
`BM_MAX_INVENTORY_ITEMS`と同数)の相異なるhashを用意し、半数は事前に
`bm_dandelion_note_source`で印を付け(FLUFF確定になるはず)、残り半数はstem
successorへSTEMになるはずという状態を作った上で、`bm_dandelion_decide`が全件について
正しい判定を返すこと(索引が既存エントリを取り違えたり重複作成したりしていないことの
証明)と、処理全体が3秒以内(実測0.23秒、旧O(n^2)実装なら概算6秒規模)に完了することを
確認した。ctest 35件全通過(既存のdandelion_stage1〜3も回帰無し)。

### ログ改善: getdata受信の正常系にログが無かった(2026-08-23)

ユーザーからの「外部からgetdataを1回でも受信したことがあるか、ログから確認できるか」
という質問がきっかけで発覚。ログ全体(bitmessaged_bootstrap.log)を`getdata`で
grepすると28件全てが「こちらが送ろうとして失敗した("failed to send getdata")」側の
記録のみで、外部から受信した記録は0件だった。ただし`handle_getdata`(`object_sync.c`)は
inv受信と同じく正常系に一切ログが無く、malformed/上限超過の異常系ログしか出ていな
かったため、「本当に一度も受信していない」のか「受信していたが記録が残っていないだけ」
なのかログからは判別できなかった。

`handle_getdata`に、`handle_inv`と同じ方針でログを追加した:
`bm_log("[object_sync] received getdata: %llu item(s) requested, %zu sent, %zu not
found\n", ...)`。要求件数・実際に送れた件数・持っていなかった件数を可視化する。
ctest 35件全通過(ログ文言は既存の慣習通りアサート対象外)。

### ログ改善: perror()がbm_logを経由せず取りこぼされていた(2026-08-23)

ユーザーが`read: Connection reset by peer`という無時刻のログ行に気付いて発覚。
`common/logging.c`(`bm_log`)新設時の一括置換(2026-08-23早い時間帯)は
`fprintf(stderr, ...)`だけを対象にしており、`perror()`(別関数)は対象外のまま
取り残されていた。`network.c`5箇所・`peer_connector.c`1箇所・`main.c`2箇所の計8箇所が
該当し、いずれも無時刻・`bm_log`のスレッド安全な単一書き込み(2026-08-23の別項目
参照)の恩恵を受けられないまま残っていた。

全て`bm_log("...: %s\n", strerror(errno))`の形に置き換えた(`perror(msg)`の出力
`msg: strerror(errno)`と同じ体裁を維持)。`main.c`に`<errno.h>`を追加(既存の
`errno`直接参照箇所は無かったため今回初めて必要になった)。ctest 35件全通過
(ログ文言はアサート対象外)。

### listConnections送受信バイト数(後半分)+getNetworkStats(2026-08-23)

backlog項目5の残り(送受信バイト数)に着手。ユーザーと相談し、全体累積は
`listConnections`とは別の新規メソッド`getNetworkStats`に分離した(「listConnectionsと
いう名前でtotalsまで返すのは名前と実態が合わない」というユーザー指摘による)。
接続ごとの送信バイト数がbroadcast_inv経由(dup()したfdへの書き込み、connを持たない)の
分だけ取りこぼす制約はユーザー了承の上で受容した(全体累積には含まれる)。

**実装**:
- `infra/network.h`の`struct bm_fd_data`に`bytes_sent`/`bytes_received`を追加。
- `infra/network.c`にプロセス内シングルトンの全体累積(`bm_network_get_stats`、
  mutex保護、dandelion.cのg_stateと同じ方針)を追加。`bm_network_write_all`成功時に
  全体送信累積を、`bm_network_handle_readable`の読み取り成功時に接続ごと・全体受信累積の
  両方を更新する(受信側は読み取りが成功する箇所がこの1箇所しか無いため経路を問わず
  正確に集計できる)。
- 接続ごとの送信バイト数は、connを持つ呼び出し元(`bm_reply_verack`/`bm_reply_pong`
  [`send_header_only`をconn引数に変更]、`send_addr_reply`、`send_big_inv`、
  `handle_getdata`、`handle_inv`のgetdata送信、プロトコルバージョン/timestamp
  エラー送信、inbound版versionの送り返し、`peer_connector.c`のversion送信
  [`bm_version_message_size`で長さを再計算])で個別に積む。
- `core/api_server.c`: `listConnections`の各エントリへ`sentBytes`/`receivedBytes`を
  追加。新規メソッド`getNetworkStats`(`{sentBytes, receivedBytes}`、全体累積を返す、
  PyBitmessage自体には無いAPI)を追加。
- `cli/main.c`に`list-connections`(usageのみ更新)・`get-network-stats`サブコマンドを
  追加。

**テスト**: `tests/test_network_stats.c`を新規追加(受信側の接続ごと・全体累積、
送信側の`bm_reply_verack`/`bm_reply_pong`の接続ごと累積、conn無しの
`bm_network_write_all`直接呼び出しでも全体累積には計上されること、の3シナリオ)。
`tests/test_api_server.c`の既存`listConnections`シナリオへ`sentBytes`/`receivedBytes`の
検証を追加し、`getNetworkStats`のHTTP経由シナリオも新設した。ctest 36件全通過。

### 重大バグ修正: daemon AがSIGPIPEで無言のまま突然終了していた(2026-08-23夜〜2026-08-24朝、解決)

23:23:17起動のdaemon Aが、23:36:26のログ出力(通常運用中、`sent big inv`等が
活発に流れていた)を最後に、以後一切ログが無いままプロセスごと消えていた
(`pgrep`で存在確認、ユーザーが気付いて発覚)。以下を確認したが原因を特定できなかった:

- ログに`シグナル 15 を受信`(SIGTERMによる正常終了)の記録が無い → 通常のkill/
  再起動操作によるものではない
- `journalctl -k`(sudo無しで読める範囲)にOOM killer・segfault・coredumpいずれの
  痕跡も無し
- `journalctl -u systemd-coredump`も該当時間帯に記録無し
- `dmesg`本体は権限で読めず未確認(要sudo、今夜は確認できなかった)
- `ulimit -c`が0(コアダンプ無効)のため、仮にsegfaultだったとしても解析用のcore
  ファイルは残らない設定だった

死んだ直前は、複数の新規接続が短時間に連続して確立し(`sent big inv`が数秒間隔で
何度も発生)、`send_big_inv`が呼ばれるたびに一時的な配列(hash件数ぶん×32byte、
今夜の時点でobject_pool.dbが約1万件)を複数回mallocしていた。この負荷と無関係かは
未確認。次回同じ現象が起きたら、`ulimit -c unlimited`を設定してからdaemonを起動し
coreファイルを残す、または`journalctl -k`をリアルタイムで`tail -f`しながら再現を待つ、
のいずれかで原因究明を試みる。今回は同じバイナリでそのまま再起動して復旧した。

**続報(同日深夜、2回目の発生)**: 再起動から約32分後(00:29:47のログを最後に)、
全く同じパターン(`sent big inv`が連続していた最中)で再び原因不明のまま消えた。
1回目と合わせて短時間に2回連続で発生したため、「htopでの誤操作等、人為的な
SIGKILL」という当初の仮説は弱まり、コード側の実際のバグの可能性が高まった。
ユーザー提供の`sudo dmesg`ダンプ(uptime秒表記だったため起動時刻から逆算して
該当区間を特定)を確認したが、該当区間にもOOM killer・segfaultの痕跡は無かった。
さらに`/var/crash/`(本機は`core_pattern`が`apport`経由)にも`bitmessaged`関連の
クラッシュレポートが一切無いことを確認した。apportは本来SIGSEGV/SIGABRT等
コアダンプ対象のシグナルを必ず捕捉するはずだが、`ulimit -c`が0だとカーネルが
そもそも`core_pattern`ハンドラを呼ばない(=apportに情報が渡らない)可能性があるため、
「本当にsegfaultではなかった」とは言い切れない。

**恒久対応**: `watchdog_daemon_a.sh`(リポジトリ直下、`.gitignore`済み)を新設。
daemon Aが理由を問わず終了したら、終了コード(bashの規約でシグナル終了時は
`128+シグナル番号`になるため、次回は`137`ならSIGKILL、`139`ならSIGSEGV、と
判別できる)をログに記録した上で5秒後に自動再起動するループ。`ulimit -c unlimited`を
ループ内で明示し、次回実際にsegfault等が起きた場合は今度こそ`apport`にコアダンプを
残せるようにした。`nohup`+`disown`で起動し、放置していても復旧できる状態にした。

**解決(2026-08-24朝、watchdogが決定的な証拠を記録)**: watchdog導入後の一晩で
6回連続発生し、そのたびに`bitmessaged exited (exit_code=141)`が記録されていた。
bashの規約でシグナル終了時の終了コードは`128+シグナル番号`になるため、
`141 = 128 + 13 = SIGPIPE`と判明した。

**根本原因**: `main.c`がSIGPIPEを一切ハンドリングしていなかった。SIGPIPEは
「相手が既に閉じたソケットへ`write()`した」瞬間にOSのデフォルト動作として
**プロセス全体を即座に終了させる**シグナルで、かつ(a)コアダンプ対象ではない
(`apport`に何も残らない)、(b)カーネルが検知する異常でもない(`dmesg`/
`journalctl`に何も残らない)、(c)アプリ側にSIGTERM以外のシグナルハンドラが無い
(`シグナル15を受信`ログが出ない)ため、**あらゆる観測経路で完全に無言のまま
落ちる**。今夜これまでに確認した「dmesgにもjournalctlにもapportにも一切痕跡が無い」
という状況証拠と完全に一致する。実際の引き金は、今夜観測し続けていた高頻度の
接続churnと、`send_big_inv`/`handle_getdata`が1接続あたり何度も連続で
`write()`する処理の組み合わせ: 相手が切断した直後(こちらがまだ検知していない
タイミング)に書き込みが発生するたびにSIGPIPEが飛んでいたと考えられる。

**修正**: `main()`の文字通り最初の行で`signal(SIGPIPE, SIG_IGN);`する
(他のどのスレッドがwrite()を始めるよりも前に済ませる必要があるため)。
`bm_network_write_all`は既にwrite()失敗を`-1`として正しく扱っている
(EPIPE時は単なる接続エラーとして既存の切断処理に合流する)ため、SIGPIPEを
無視するだけで直る。ctest 36件全通過。

昨夜の一連の調査(OOM killer・segfault・SIGKILL・ヒープ破損等)はいずれも
外れだったが、その過程で見つけた`send_big_inv`/`dandelion.c`のmalloc未チェック
箇所の修正自体は妥当なハードニングとして残す。watchdog_daemon_a.sh(終了コード
からシグナルを判別できる設計)がこの根本原因特定の決め手になった。

**コードレビューで見つけた実際のバグ(直接の原因かは未確定、ハードニングとして修正済み)**:
`object_sync.c`の`send_big_inv`が`malloc`の戻り値を確認しておらず(`fluff`/`stem`配列、
現在hash件数約1万件規模で接続のたびに毎回呼ばれる)、失敗時にNULL参照でクラッシュ
しうる状態だった。`dandelion.c`の`find_or_create_entry`にも、索引テーブルの初回確保が
万一失敗した場合にゼロ除算(SIGFPE)しうる箇所があった。いずれもガードを追加した。
ctest 36件全通過。今夜の時点では次にまた発生するか経過観察が必要(watchdogにより
放置は可能)。

### ログ改善: getdata送信・通常inv/dinv配信の正常系にログが無かった(2026-08-24)

ユーザーの指摘で発覚。今夜これまでに`inv`/`dinv`/`getdata`受信側の正常系ログは
追加済みだったが、送信側の一部にまだ同じ穴が残っていた:

- `handle_inv`(`object_sync.c`)のgetdata送信: 失敗時("failed to send getdata")の
  ログしか無く、実際に何件送れたかが分からなかった
- `bm_peer_registry_broadcast_inv`(`peer_registry.c`、新規object受信時に既存の
  接続中peerへ配る、`send_big_inv`とは別の通常経路)のinv/dinv配信: こちらも
  失敗時のログしか無かった

前者は`bm_log("[object_sync] sent getdata: %zu item(s)\n", missing_count)`を
追加。後者は宛先ごとの個別ログにはせず(peer数が多いと大量に出るため)、
1回のbroadcast呼び出しにつき`"broadcast inv: %zu hash(es) inv to %zu peer(s),
dinv to %zu peer(s)"`という1行のサマリにした(誰にも送るものが無ければ出さない)。
ctest 36件全通過。

### 重大バグ修正: send_big_invがDandelion++の判定機構を誤って毎回発火させ、自分のobjectを無限ループで再配信していた(2026-08-24)

daemon Aの稼働状況確認中、ユーザーが「`broadcast inv`ログが異常に多い、DoSでは」と
指摘したことがきっかけで発覚。実測したところ、稼働7時間で`broadcast inv`が
525,727回発生していたが、その間object_pool.dbの実件数は10,384件(緩やかに増加)
にとどまっており、**保有件数の50倍以上**の再ブロードキャストが起きていた。

**根本原因**: `send_big_inv`(前日実装、handshake完了時に自分の保有object全件を
新規peerへ知らせる)が、hashごとに`bm_decide_propagation`(Dandelion++の
stem/fluff判定・状態管理の本体、DESIGN.md §9.2の差し込み点)を呼んでいた。この
関数は「今まさに新しく検出したobjectをstemすべきか」を判定するためのもので、
呼ぶたびに未知のhashへ新規のタイムアウト管理エントリを作ってしまう。何年も前から
公開済みのobjectを、新規peerが繋がるたび(=1万件のhash全部について)毎回この
判定に通してしまい、たまたまstem successorが選ばれているタイミングだと
「stem中」の未確定エントリが大量に作られる。これが10〜40秒後にタイムアウトして
`bm_dandelion_expire_and_refluff`経由で`broadcast_inv`を発火し、300秒後に
間引かれ、次回`send_big_inv`が同じhashを処理する時には再び「未知」扱いで
作り直される——という実質無限ループになっていた。

PyBitmessage本家の実際の`sendBigInv`はstem/fluff判定を一切行わず、
「今stem中のhashだけ`dandelion_ins.hasHash`で除外し、残りは普通のinvとして送る」
だけの単純な処理だった。

**修正**: `dandelion.c`に読み取り専用の`bm_dandelion_is_stemming(hash)`を新設
(エントリが存在しなければ新規作成せず単に「stem中ではない」を返す、副作用無し)。
`send_big_inv`はこれで単純に除外判定するだけにし、`bm_decide_propagation`の
呼び出しとdinv送信を完全に廃止した(bigInvは元々「stemを開始する」ための送信では
なく、既に確定した自分の保有物一覧を知らせるだけなので、dinvという形式を使う
理由が無い)。

**テスト**: `tests/test_object_sync.c`にシナリオ15を追加。専用のDandelion状態・
registryで隔離した上で、意図的に1件を「stem中」の状態にしてから`send_big_inv`を
実行し、stem中のhashが除外され、それ以外は含まれることを確認した。ctest 36件全通過。

### 調査+改善: rating<0のpeerへの無駄な再接続を緩和するクールダウンを追加(2026-08-24)

ユーザーから「`95.49.240.98:8444`のratingが-1.0のままpeers.dbに残り続けている、
削除条件がおかしいのでは」との指摘を受け調査。まず削除条件(`bm_peer_manager_cleanup`)
自体はPyBitmessage本家の`cleanupKnownNodes`と2条件(28日経過は無条件削除/3時間経過かつ
rating<=-0.5)とも完全一致しており、削除条件そのものにバグは無かった。

**削除しても直らない理由(裏付け)**: `last_seen`が更新され続ける原因を実ログで追跡した
ところ、2つの独立した経路が判明した。(1) 他peerからのaddrメッセージ経由の伝聞
(`bm_peer_manager_upsert_learned`はrating/sourceを変えずlast_seenだけ無条件更新する
設計で、これもPyBitmessage本家の`addKnownNode`と一致)。(2) **うちのdaemon自身が
このpeerへ13時台〜14時台の1.5時間で少なくとも9回、直接outbound再接続を試みていた**
(`connected to 95.49.240.98:8444, version sent`のログが繰り返し出現)。`peer_connector.c`の
候補選定式`prob = 0.05/(1-rating)`はrating=-1.0でも2.5%の確率で選ばれ続ける設計であり、
かつ`bm_peer_manager_record_result`のsuccess分岐(verack受信時)はrating更新とlast_seen
更新を同一UPDATE文で行うため、TCP応答はあるがhandshake完了直後にfatal切断してくる
ような「死んでいないが役に立たない」peerでは、ratingは上がらない(または前述の
fatal>=1ペナルティで相殺される)一方でlast_seenだけが再接続のたびに更新され続ける。
つまり**削除条件を厳しくしても、addr伝聞または自分自身の再接続のどちらかで
すぐ復活する「イタチごっこ」になる**ことが確認できた。

**PyBitmessage本家との比較(裏付け)**: `network/connectionchooser.py`の
`chooseConnection`を確認したところ、`prob = 0.05 / (1.0 - rating)`という式そのものが
本家由来で、rating<0を候補から完全排除する仕組みは本家にも無い。さらに`tcp.py`の
`set_connection_fully_established`(verack受信時)は`increaseRating`と`addKnownNode`
(lastseen更新)を同時に呼び、`handle_close`側も「fully established後に切断された
outbound接続」であれば**ratingを一切減らさずlastseenだけ再更新する**設計になっており、
むしろ本家の方がうちより「一度でも応答した低ratingノードに優しい」動きをする。
結論として、この挙動は「うちのバグ」ではなく「PyBitmessage本家の設計」であり、
ユーザーとの相談の結果、`rating`/`last_seen`の意味論自体は本家互換のまま維持し、
**候補選定側にのみ再接続クールダウンを追加する**方針で合意した。

**実装**: `core/peer_manager.c`の`hosts`テーブルへ`last_attempt`列を追加
(既存DBへは`is_self`追加時と同じ`ALTER TABLE`後付けパターンで対応)。新設した
`bm_peer_manager_record_attempt(db, ip, port, stream, now)`は成否を問わず
「接続を試みた事実」だけを記録する(rating/last_seenには一切触れない、record_resultとは
完全に独立)。`bm_peer_connector_choose_candidate_index`に`int64_t now`引数を追加し、
候補のrating<0かつ`now - last_attempt < BM_PEER_LOW_RATING_COOLDOWN_SECONDS`(30分)
の場合は既に接続済みのpeerと同様に不採用として次の候補を試すようにした。rating>=0の
候補には一切影響しない(本家互換の挙動をそのまま維持)。`peer_connector.c`の
`connect_initial`は候補を選ぶたびに`now`をローカルの`candidates[]`配列にも反映してから
DBへ永続化する(`list_top`は1呼び出しにつき1回しか候補をfetchしないため、ローカル反映を
怠ると同一サイクル内で即座に再選出されクールダウンが無意味になる)。

**テスト**: `tests/test_peer_reconnect_cooldown.c`を新設。クールダウン中/明けた後の
選出可否、rating>=0の候補が無影響であること、`record_attempt`→`list_top`のDB往復
(rating/last_seenを変更しないこと含む)を確認。ctest 37件全通過。

### onionpeer自己announceの定期再送(backlog項目6、2026-08-24)

PyBitmessage本家(`class_singleCleaner.py`)を再確認したところ、`sendOnionPeerObj`は
起動時1回に加え、メインループの`timeWeLastClearedInventoryAndPubkeysTables < tick -
7380`という条件(約2時間3分おき)でも呼ばれていた。うちは起動時1回・TTL2日固定で、
再起動しない限り2日でannounceが失効し誰からも発見されなくなる問題があった。

**実装**: 専用スレッドは新設せず、Dandelion++の`bm_dandelion_maybe_reshuffle`/
`bm_dandelion_expire_and_refluff`と同じ方針で、既存の`peer_connector_thread`の1秒間隔
ポーリングループに相乗りさせた。新設した`bm_object_sync_maybe_reannounce_onion_peer`
(`infra/object_sync.c`)は`ctx->last_onion_announce`(新設フィールド、単一スレッド
専有につき排他制御無し)を基準に`BM_ONIONPEER_REANNOUNCE_INTERVAL_SECONDS`
(=7380秒、PyBitmessage本家準拠)未満の呼び出しは即returnし、間隔が明けていれば
`bm_object_sync_announce_onion_peer`を実際に呼ぶ。1秒ごとに呼んでも大半は軽い
即returnで終わる。

onionアドレスは`main.c`が静的torrc設定(`manual_onion_address`)/Tor ControlPort
(`onion_address`、announce直後にfreeされる一時変数)のどちらの経路で判明しても、
`main()`のスタック上の`self_onion_address[BM_PEER_IP_STRLEN]`へ控えてから
`peer_connector_config`経由でスレッドへ渡す(`object_sync_ctx`等と同じ「main()の
スタック変数のアドレスを複数スレッドへ渡す」既存パターン)。起動時の直接announce
呼び出し直後に`ctx->last_onion_announce`をその場でセットしておくことで、
`peer_connector_thread`側のゲートが起動直後の1回目で二重announceしないようにした。
Tor未使用構成(`self_onion_address`が空文字列のまま)では`maybe_reannounce`が
常に即returnし何もしない。

TTL(`BM_ONIONPEER_ANNOUNCE_TTL_SECONDS`=2日)自体は変更していない。今回の再送間隔
(2時間強)に対して約23倍の安全マージンがあり、意図的に選んだ短めのTTL(pubkeyほど
長生きする必要が無い一時的な情報という判断、既存コメント参照)を維持したまま
定期再送だけを追加すれば元の問題は解決するため。

**テスト**: `tests/test_object_sync.c`にシナリオ16を追加。間隔未満/間隔経過後の
announce有無、`last_onion_announce`の更新、onion_addressがNULL/空文字列の場合に
常にスキップされることを確認した。ctest 37件全通過。

### ログレベル(DEBUG/INFO/WARN/ERROR)の導入(backlog項目8、2026-08-24)

**経緯**: 2026-08-23に`common/logging.c`(`bm_log`)を新設した際、時刻付与とあわせて
検討したがスコープ外としていた項目(backlog項目8参照)。既存の約140箇所の`bm_log`
呼び出しを1つずつ「どのレベルに当たるか」判断し直す必要があり、時刻付与のような
機械的な置換とは規模が違うため後回しにしていたが、今回着手した。

**設計**: `enum bm_log_level { BM_LOG_DEBUG, BM_LOG_INFO, BM_LOG_WARN, BM_LOG_ERROR }`を
新設し、`bm_log_leveled(level, fmt, ...)`を中核に、呼び出し側は`bm_log_debug/info/warn/error`
マクロ経由で使う。旧`bm_log()`(レベル無し)は廃止し、全呼び出し箇所を置き換えた。
出力フォーマットは`[TS] [LEVEL] msg`(時刻を付ける場合)/`[LEVEL] msg`(JOURNAL_STREAM
配下等、付けない場合)。既定の最低レベルは`BM_LOG_INFO`(`DEBUG`を抑制)で、`BM_LOG_LEVEL`
環境変数(`DEBUG`/`INFO`/`WARN`/`ERROR`、大文字小文字区別しない)で変更できる。認識できない
値が指定された場合は既定(`BM_LOG_INFO`)のまま(誤指定でログが完全に沈黙する事故を防ぐ、
安全側の挙動)。journald連携(優先度プレフィックス`<N>`によるSD_ERR等へのマッピング)は
今回のスコープ外とした(backlog項目8の要求事項は「フィルタリング方式」のみで、
journald固有の仕組みへの依存を増やすのは過剰と判断)。

**レベル判定基準**(約140箇所を分類する際に採用した目安):
- `ERROR`: 初期化・セットアップ処理が失敗し、その機能(DBオープン、スキーマ作成、
  listen、Tor hidden service作成の各ステップ等)が丸ごと使えなくなる場合。OOM
  (`malloc`/`calloc`失敗)や、自分で生成したはずのobjectが破損しているような内部
  不変条件違反もここに含めた。
- `WARN`: 実行時に起きる回復可能な異常(peerからの不正/期限切れ/PoW不足object、
  malformed message、accept/epoll_ctl等のsyscall失敗、SOCKS5/Torプロキシ経由の
  接続失敗、設定ファイルの記述ミス等)。単発では致命的でないが運用者が気に留めるべき事象。
  Tor ControlPort連携(`tor_control.c`)のみ例外的に大半を`ERROR`とした
  (PROTOCOLINFO/AUTHENTICATE/ADD_ONIONの一連の手順はどのステップで失敗しても
  hidden service全体が使えなくなるため、`WARN`より`ERROR`が実態に合うと判断)。
- `INFO`: 意味のあるライフサイクルイベント(daemon起動/終了、DB初期化完了、listen開始、
  outbound/inbound接続確立、hidden service準備完了、メッセージ受信・送信成功等)。
  頻度が低く運用上の節目になるもの。
- `DEBUG`: 高頻度で個々の重要性が低いトレース(inv/getdata/addrの受信件数サマリ、
  keepalive ping送信、verack受信、pubkey応答のキャッシュ再利用等)。2026-08-23〜24に
  「正常系ログが無く可視化できない」という指摘を受けて追加した一連のログの多くが該当する
  (§11「ログ改善」各節参照)。

**テスト**: `tests/test_logging.c`にレベルタグ付与・`BM_LOG_LEVEL`によるフィルタリング
(既定で`DEBUG`抑制、`BM_LOG_LEVEL=DEBUG`で表示、`BM_LOG_LEVEL=ERROR`で`ERROR`以外を
抑制、不正値は既定にフォールバック)のシナリオを追加。既存の時刻付与・マルチスレッド
安全性の検証もレベルタグを含む新フォーマットに合わせて更新した。

実装中に見つけたテスト設計上の注意点: `bm_log_init()`は`BM_LOG_LEVEL`未設定/不正値の
場合に「前回の値のまま変更しない」という実装にすると、同一プロセス内で`bm_log_init()`を
複数回呼ぶテスト(env varを変えながら繰り返し呼ぶ)で前のテストケースの設定を引きずり
非決定的になることが実際に発覚した(不正値のテストケースの直前に`BM_LOG_LEVEL=ERROR`を
設定するケースがあり、不正値指定時に`ERROR`のままフィルタが効いてしまっていた)。
実運用では`main()`起動時に1回しか呼ばないため実害は無いが、`bm_log_init()`呼び出しのたび
`g_min_level`を既定値へ一度リセットしてから環境変数で上書きする実装に変更し、
呼び出し履歴に依存しない決定的な挙動にした。

ctest 37件全通過(警告ゼロ)。

**副次的に発見・修正したバグ**: 上記の移行後にビルド・テストを流したところ、
`test_object_sync`のシナリオ16(onionpeer自己announceの定期再送、backlog項目6)が
数回に1回だけ失敗するflakinessが発覚した。原因は`bm_object_sync_announce_onion_peer`
(`infra/object_sync.c`)が`expires_time`の計算に関数内部で`time(NULL)`を直接呼んで
いたこと。シナリオ16は`bm_object_sync_maybe_reannounce_onion_peer`へ合成の`now`
(1000, 1000+7380)を渡して間隔判定の決定性を検証しているが、内部で呼ばれる
`bm_object_sync_announce_onion_peer`自体は合成`now`を無視して実時刻を使っていたため、
テストが実行される実時刻の1秒以内に2回のannounceが発生すると(このテストは瞬時に
実行されるため通常そうなる)、`expires_time`を含むonionpeer payloadが完全に同一に
なり、PoW(決定的なnonceのブルートフォース探索)の結果までnonce込みで一致し、
2回目が`bm_object_store_has`の重複排除に引っかかって announceされない(=定期再送が
効かない秒がある)という実バグだった。実運用では2回目の呼び出しはTTL(7380秒)後
なので通常問題化しないが、CLAUDE.mdの「時刻は明示引数で受け取り、関数内部で
time(NULL)を直接呼ばない」方針に反していたのも事実であり、`bm_object_sync_announce_onion_peer`
にも`int64_t now`引数を追加し、呼び出し元(`main.c`2箇所、
`bm_object_sync_maybe_reannounce_onion_peer`、`tests/test_object_sync.c`)を全て
更新した。修正後、`ctest -R object_sync`を5回連続実行してflakinessが再現しないことを
確認した。

### ASan/UBSanの導入(backlog項目9、2026-08-24)

**経緯**: 2026-08-24にユーザーが外部(Google検索)で得た助言を踏まえ提起したbacklog項目9。
「Sanitizeビルドで`ctest`一式を流し、指摘を1件ずつ精査・修正する」「daemon本体もtestnet+
隔離ディレクトリで短時間動かし、テストでは踏まない実ネットワーク経路も検証する」という
2点をユーザーと合意した上で着手した。

**CMake実装**: `CMakeLists.txt`へ`BM_ENABLE_ASAN`/`BM_ENABLE_UBSAN`/`BM_ENABLE_TSAN`の
3オプション(既定OFF)を追加。ON時は`-fsanitize=...,-fno-omit-frame-pointer,-g`を
コンパイル・リンク両方に付与する。`BM_ENABLE_TSAN`を`BM_ENABLE_ASAN`/`BM_ENABLE_UBSAN`と
同時にONにすると`FATAL_ERROR`で弾く(instrumentation競合のため)。既存の`build-Debug`とは
別に`build-Sanitize`ディレクトリ(`cmake -S . -B build-Sanitize -DCMAKE_BUILD_TYPE=Debug
-DBM_ENABLE_ASAN=ON -DBM_ENABLE_UBSAN=ON`)を使う運用にして、日常のbuild-Debugサイクル
(CLAUDE.md「Build」参照)を一切崩さないようにした。

**実装中に踏んだ罠**: 最初`list(APPEND BM_SANITIZE_FLAGS "-fsanitize=address")`のように
プレフィックス込みの文字列をリストへ積んでから`list(JOIN ... "," ...)`で結合し、それを
さらに`"-fsanitize=${...}"`で包んでいたため、`-fsanitize=-fsanitize=address,-fsanitize=undefined`
という二重プレフィックスの壊れた引数になりコンパイルエラーになった。プレフィックス無しの
値(`address`/`undefined`/`thread`)だけをリストに積み、結合後に1回だけ`-fsanitize=`を
付ける形に修正した。

**ctestで発見した実リーク2件(いずれもテストハーネス側の後片付け漏れ、本体コードのバグでは
ない)**:
- `tests/test_api_server.c`: `struct bm_peer_registry registry`を`bm_peer_registry_init`
  するだけで、`bm_peer_registry_destroy`を一度も呼ばずにmain()を終えていた。登録した
  個々の接続(`lc_conn_out`/`lc_conn_in`)自体は`bm_fd_data_free`済みだったが、registry
  内部の配列(`reg->conns`)がリークしていた(`bm_peer_registry_add`内の`realloc`、64byte)。
  `bm_peer_registry_destroy(&registry)`をmain()末尾に追加して解消。
- `tests/test_config_store.c`: `bm_peer_connector_connect_initial`がSOCKS5モックプロキシ
  経由で実際に1本接続を確立し、その`bm_fd_data`(と内部のrecvバッファ、計131488byte)を
  registryへ登録するが、registryは接続オブジェクトの所有権を持たない設計
  (`peer_registry.h`のdocコメント参照、close_connection/`bm_fd_data_free`の呼び出しは
  常に呼び出し元の責務)なので、テストが自分で個々の接続をfreeしないとリークする。
  `bm_peer_registry_for_each`で全登録接続を巡回してfd close+`bm_fd_data_free`する
  コールバックを追加し、`bm_peer_registry_destroy`の前に呼ぶよう修正した。

この2件はいずれも「registryは接続の所有者ではない」という既存設計に対するテスト側の
理解不足が原因で、本体コード(`peer_registry.c`/`peer_connector.c`)自体にはバグが
無かった。修正後、`build-Sanitize`でのctest 37件が全通過(ASan/UBSanとも指摘ゼロ)。

**daemon本体の手動smoke test**: `build-Sanitize/src/bitmessaged`をリポジトリ外の隔離
ディレクトリ(スクラッチ領域、実DBファイルとは完全に別)から`BM_TESTNET=1`・SOCKS5/Tor
未使用で2回(45秒・150秒)起動し、実testnet peer(5.78.198.100:8444等)への実際の
outbound接続・version交換・切断(相手からのconnection reset)・SIGTERMによる
graceful shutdownを複数サイクル踏ませた。`ASAN_OPTIONS=detect_leaks=1:log_path=...`
`UBSAN_OPTIONS=print_stacktrace=1:log_path=...`を指定したが、レポートファイルは
一つも生成されず(=指摘ゼロ)。DB初期化・config読み込み・実TCP接続の確立/切断の
繰り返し・graceful shutdownの経路では問題が見つからなかった。ただしこの smoke test は
inv/getdata交換までは安定して踏めておらず(テスト用testnet peerがversion直後に切断
してくることが多かった)、その経路の実ネットワーク検証は今後の課題として残る。

**CI統合**: `.github/workflows/ci.yml`へ`sanitize`ジョブを新設(`build-and-test`とは
別ジョブ、並列実行)。`-DBM_ENABLE_ASAN=ON -DBM_ENABLE_UBSAN=ON`でビルドし、
`ASAN_OPTIONS=detect_leaks=1`/`UBSAN_OPTIONS=print_stacktrace=1`付きで`ctest`を
走らせる。上記の通りリークを解消済みの状態でCIへ組み込んだため、導入直後からグリーンな
状態でスタートできる。ThreadSanitizerは別ジョブが必要なため、この時点ではCIに含めず
別途着手することにした(下記「TSanの導入」参照)。

ctest 37件全通過(通常のbuild-Debugビルドでも警告ゼロ・全通過を再確認済み)。

### TSanの導入(backlog項目9続き、2026-08-24)

**経緯**: 上記ASan/UBSan導入に続けて、ユーザーと合意の上でThreadSanitizerにも着手した。
「`BM_ENABLE_TSAN`ビルドで`ctest`一式を流し、実際に何件・どんな種類の指摘が出るか
確認してから、1件ずつ修正/意図的な設計として記録するかを判断する」という進め方で
合意した。事前に「`volatile sig_atomic_t`によるstop_flagのポーリングパターンが
大量に検出される可能性が高い」と予想を共有していた。

**実行環境の罠**: `build-TSan`(`-DBM_ENABLE_TSAN=ON`)でビルドした`test_json`等
(スレッドを一切使わないテストも含む)が軒並み`FATAL: ThreadSanitizer: unexpected memory
mapping`で即死する現象に遭遇。これはTSanと新しめのLinuxカーネルの高ASLRエントロピー
(`mmap_rnd_bits`)との既知の非互換で、`setarch $(uname -m) -R <command>`(その
プロセスに対してのみASLRを無効化するpersonality設定、カーネルのsysctl自体は一切変更
しない)でラップすることで回避できた。`ctest`自体を`setarch -R`配下で実行すれば、
fork/execで起動される各テストバイナリにも同じpersonalityが引き継がれ、個別にラップし直す
必要は無かった。

**実際に検出した指摘、2種類**:
1. **`stop_flag`系のデータレース**(`api_server`/`getpubkey_automation`/`broadcast`の
   3テストで検出、いずれも同一パターン): `bm_api_server_serve_forever`
   (`core/api_server.c:1252`)が`*stop_flag`を読み、テスト/main()側が別スレッドから
   `server_stop = 1`のように書き込む際、`volatile sig_atomic_t`では
   スレッド間の可視性・順序(happens-before関係)が一切保証されない
   (`volatile`は同一スレッド内でのシグナルハンドラとの安全な読み書きを保証するだけ)。
   もっとも、main()は実際には非同期シグナルハンドラの中ではなく`sigwait()`後の通常の
   スレッドコンテキストでstop_flagを立てており(main.c参照)、そもそも本来欲しかったのは
   「スレッド間で安全に読み書きできること」の方だった。`_Atomic sig_atomic_t`
   (C11 `<stdatomic.h>`)へ変更することで、シグナルハンドラからの利用も引き続き安全な
   ままスレッド間可視性も得られる。読み書き側のコード(`*stop_flag == 0`等)は
   _Atomic修飾された左辺値への通常の演算がそのままatomicなload/storeになるため
   変更不要だった。影響箇所: `core/api_server.h`/`.c`、`infra/peer_connector.h`
   (同じパターンの`stop_flag`を持つが今回のテスト実行では偶然踏まれなかった。放置すると
   将来同じ理由で再発するため合わせて修正)、`main.c`の2箇所の宣言、および
   `tests/test_api_server.c`/`test_broadcast.c`/`test_getpubkey_automation.c`/
   `test_peer_connector_shutdown.c`のローカル宣言。
2. **`dandelion.c`/`peer_registry.c`間のロック順序逆転(潜在的デッドロック、
   `dandelion_stage2`テストで検出)**: `bm_dandelion_maybe_reshuffle`
   (`infra/dandelion.c`、peer_connector_threadの1秒間隔ポーリングから呼ばれる)が
   dandelionモジュールの内部mutex(`g_state.lock`)を保持したまま
   `bm_peer_registry_pick_random_dandelion_peer`(`peer_registry.c`)を呼び、
   registryのmutex(`reg->lock`)を取得していた(dandelion_lock→registry_lockの順)。
   一方`bm_peer_registry_broadcast_inv`(object_sync_threadから呼ばれる)は
   `reg->lock`を保持したまま`bm_decide_propagation`→`bm_dandelion_decide`経由で
   `g_state.lock`を取得していた(registry_lock→dandelion_lockの逆順)。
   古典的なABBAデッドロックで、実daemonでは`peer_connector_thread`と
   `object_sync_thread`という別スレッドがそれぞれの経路を実際に踏むため、タイミング次第で
   本物のデッドロックになりうる潜在バグだった。`bm_dandelion_maybe_reshuffle`は
   peer_connector_threadからしか呼ばれない(CLAUDE.md方針、他スレッドからの同時呼び出しは
   無い)ため、`g_state.epoch_started`の更新だけ先に確定させてロックを一旦解放し、
   `pick_random_dandelion_peer`呼び出しをロック外へ出し、結果(stem_ip/stem_port/has_stem)の
   反映だけ再度ロックする2段階に分割してサイクルを断ち切った(§11の該当コメント
   `infra/dandelion.c`参照)。epoch_started更新とstem情報更新の間の一瞬だけ他スレッドが
   古いstem情報を読む可能性があるが、Dandelion++のepoch選択自体が元々確率的なものであり
   実害は無いと判断。

**修正後の確認**: `build-TSan`で`ctest`一式(`setarch -R`配下)が37件全通過・TSanの指摘
ゼロ(393秒、通常ビルドの約7倍)。`build-Debug`・`build-Sanitize`(ASan/UBSan)いずれも
再ビルド・再テストして100%通過を再確認した(型変更の影響が他ビルドへ波及していないこと
の確認)。

**CI統合**: `.github/workflows/ci.yml`へ`sanitize-thread`ジョブを新設
(`build-and-test`/`sanitize`とは別ジョブ、並列実行)。`-DBM_ENABLE_TSAN=ON`でビルドし、
`TSAN_OPTIONS=halt_on_error=0`・`setarch $(uname -m) -R`付きで`ctest`を走らせる。
GitHub Actionsのrunnerも同じ理由(モダンなUbuntuカーネルの高ASLRエントロピー)で
`unexpected memory mapping`を踏む可能性が高いと判断し、ローカルで検証済みの
`setarch -R`回避策をそのままCIステップにも適用した。

これでbacklog項目9(ASan/UBSan/TSan)は全て着手・CI統合まで完了した。

### Releaseビルド検証(backlog項目10の1/5、2026-08-24)

**経緯**: backlog項目10(Releaseビルドでのテスト・インストール・systemdサービス化)を
5つに分割し(Releaseビルド検証→DBファイル置き場の固定パス化→`cmake --install`定義→
systemdユニットファイル→非Ubuntu環境への軽い手当て、この順で依存関係がある)、まず
検証から着手した。

**`-DCMAKE_BUILD_TYPE=Release`で初めて顕在化した警告、3系統**:
1. **`-Wstringop-truncation`(5箇所)**: `strncpy(dst, src, sizeof(dst)-1)`(直後に手動で
   NUL終端する箇所を含む)で、GCCがsrcの最大長とdstサイズがちょうど一致すると判断できる
   場合に警告する。`-O2`でのデータフロー解析強化により初めて検出可能になった
   (`peer_manager.c`/`trial_decrypt.c`/`network.c`/`tests/test_dandelion_stage2.c`)。
   このうち**`main.c`の1箇所は実際のバグだった**: `self_onion_address`
   (`char[BM_PEER_IP_STRLEN]`)は宣言直後に`self_onion_address[0]='\0'`しかしておらず
   (配列全体のゼロ初期化ではない)、`manual_onion_address`(bitmessage.confの
   `[tor] onion_address`やBM_ONION_ADDRESS経由、長さ検証なし)が63文字以上だと
   NUL終端されないまま未初期化のスタック領域を文字列として読むバッファオーバーリードに
   なりうる状態だった(正規のv3 onionアドレスは62文字なので通常は踏まないが、設定
   ミスがあれば容易に踏みうる)。全箇所を`snprintf(dst, sizeof(dst), "%s", src)`
   (常にNUL終端される)へ置き換えて解消。`tests/test_dandelion_stage2.c`の1箇所は
   書き込むだけで読まれない完全な死コード(`(void)picked_ip`していた)だったため、
   変数ごと削除した。
2. **`-Wunused-result`(6箇所)**: `write()`(`core/api_server.c`2箇所、テスト3ファイル
   4箇所)・`getrandom()`(`infra/protocol.c`、version messageのnonce生成)の戻り値を
   無視していた(`-O2`で有効化される`_FORTIFY_SOURCE`経由で警告化される)。
   `api_server.c`は既存の`bm_network_write_all`(部分書き込み対応、`peer_registry.c`等と
   同じヘルパー)へ置き換え。`protocol.c`のgetrandomは戻り値をチェックし、失敗時は
   nonce=0にフォールバックするコメント付きの分岐にした(nonceは自己接続検出用で
   暗号的な秘密ではないため、失敗しても致命的ではないと判断)。テスト側4箇所は
   `CHECK`マクロで検証することで警告を解消しつつ、万一の部分書き込みもテスト失敗として
   可視化されるようにした。
3. **`-Wdeprecated-declarations`(9箇所、`core/crypto.c`のEC_KEY/ECDSA系)**: これは
   `-O2`固有ではなく、実は`build-Debug`でも以前から出ていた警告だった。発覚の経緯:
   このセッション中`crypto.c`が一度も再ビルドされておらず(インクリメンタルビルドの
   対象外)、`cmake --build build-Debug`を何度実行しても再コンパイルされないため警告が
   再表示されず、「警告ゼロ」を誤って確認できていた。`crypto.c`には既に
   「EC_KEY/ECDSA系はOpenSSL 3.0で非推奨だが、生成される署名はビット単位で同一かつ
   API自体は当面removeされない見込みのため、書き換えコストに見合わないとあえてこのまま
   使う」という設計判断のコメントが記されていたが、実際に警告を抑制する`#pragma`が
   付いておらず「警告ゼロ」を満たせていなかった。既存の判断はそのまま尊重し、
   `build_ec_key`〜`bm_crypto_verify`の範囲だけ`#pragma GCC diagnostic ignored
   "-Wdeprecated-declarations"`で局所的に抑制した(ファイル全体ではなく該当範囲のみに
   絞ることで、将来他の箇所で新たに非推奨APIが使われたら引き続き警告されるようにした)。
   EVP_PKEYベースAPIへの本格移行(署名・ECDH双方に影響する大掛かりな書き換え)は
   別途backlog項目として記録する(下記参照)。

**この発覚を受けた運用上の教訓**: `cmake --build`はインクリメンタルビルドのため、
変更していないファイルは再コンパイルされず、そのファイルの警告も再表示されない。
「警告ゼロ」を確実に確認するには、疑わしい時は`rm -rf build-*`してクリーンビルドする
必要がある(このセッションでも実際にRelease検証以外の3ビルド全て、この方法で
再確認した)。

**検証結果**: `build-Debug`・`build-Release`・`build-Sanitize`(ASan/UBSan)・
`build-TSan`の4種全てクリーンビルドで警告ゼロ・ctest 37件全通過を確認した
(Releaseビルドでの`-O2`最適化によるUB顕在化・タイミング変化は、この時点では
確認されなかった)。

### DBファイル置き場の固定パス化(backlog項目10の2/5、2026-08-24)

**設計判断**: 既定値(CWD相対パス)自体を`/var/lib/bitmessage/`等へ変更する(破壊的)か、
既定はCWDのまま据え置いて環境変数で明示的に上書き可能にする(非破壊的)かをユーザーに
確認し、後者で合意した。理由: 前者だと稼働中のdaemon A(リポジトリ直下に実の秘密鍵入り
DBを持つ)が見つからなくなり、手動移行が必須になる。後者なら既存挙動を一切変えず、
次のステップ(systemdユニットファイル)側で明示的に環境変数を設定するだけで済む。
既に同じ設計の前例(`BM_CONFIG_FILE`、`bitmessage.conf`の場所を上書きする既存の仕組み)が
あったため、これに合わせた。

**実装**: `main.c`に`BM_DATA_DIR`環境変数を追加。未設定時は従来通り`"."`(CWD)。
`open_and_init`ヘルパーが`data_dir`引数を受け取り`snprintf`でパスを結合するように変更
(5つのDBファイル: `peers.db`/`object_pool.db`/`identity.db`/`messages.db`/`config.db`)。
`DB初期化完了`ログに`data_dir=%s`を追記し、運用者が実際に使われたパスを確認できるように
した。`seeds/observed_nodes.txt`(読み取り専用のbootstrapシード、ユーザー状態データでは
ない)は対象外(次のステップ`cmake --install`定義の方で扱う)。

**テスト**: `tests/test_data_dir.sh`を新規追加(`test_cli_integration.sh`と同じ、実際に
`bitmessaged`を起動するシェルスクリプト統合テスト)。(1) `BM_DATA_DIR`を明示指定した
場合に指定先にのみ5つのDBファイルが作られCWD直下には何も作られないこと、(2)
`BM_DATA_DIR`未設定時は従来通りCWD直下に作られること、の両方を確認する。
`tests/CMakeLists.txt`へ`data_dir`として登録(計38件)。手動でも
`BM_DATA_DIR=<隔離ディレクトリ> BM_TESTNET=1`で実際に起動し、ログの`data_dir=`表示と
生成されたファイルの場所を目視確認した。

`build-Debug`/`build-Release`/`build-Sanitize`/`build-TSan`の4種全てクリーンビルドで
警告ゼロ・ctest 38件全通過を確認(TSan含む)。CLAUDE.mdの試験件数表記(37件→38件)も
更新した。

### `cmake --install`定義(backlog項目10の3/5、2026-08-24)

**実装**: `CMakeLists.txt`へ`include(GNUInstallDirs)`を追加し、
`install(TARGETS bitmessaged bitmessage-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})`
(既定`bin`)と`install(FILES seeds/observed_nodes.txt DESTINATION
${CMAKE_INSTALL_DATADIR}/bitmessage)`(既定`share/bitmessage`)を追加した。パスを
ハードコードせずGNUInstallDirsのディストリ標準変数を使う一般的な作法に従った。

**`seeds/observed_nodes.txt`のパス解決**: インストール後は`bm_peer_manager_seed_bootstrap`
内でCWD相対の`"seeds/observed_nodes.txt"`を直接参照できなくなるため、`BM_SEEDS_FILE`
環境変数(既定は従来通り`"seeds/observed_nodes.txt"`)で上書き可能にした
(`BM_DATA_DIR`/`BM_CONFIG_FILE`と同じ設計)。実装は`bm_peer_manager_seed_bootstrap`
(`core/peer_manager.h`/`.c`)に`observed_nodes_path`引数を追加、
`struct bm_peer_connector_config`(`infra/peer_connector.h`)に`observed_nodes_path`
フィールドを追加してmain.cから受け渡す形にした(env varの読み取り自体はmain.cのみが
行う既存方針、core/infra層は直接getenvを呼ばない、main.c参照)。呼び出し元の変更に伴い
`tests/test_network_testnet.c`・`tests/test_peer_connector_shutdown.c`も
シグネチャ変更に追従させた(後者はtestnet=0で呼ぶため、`bm_peer_manager_seed_bootstrap`
内の早期return(peers.dbが空でない)に実際には守られているとはいえ、NULLだと
`fopen(NULL)`相当の未定義動作になりうるため念のため有効な値を設定した)。

**動作確認**: `DESTDIR`付きで`cmake --install build-Debug`を実行し、
`bitmessaged`/`bitmessage-cli`/`observed_nodes.txt`が期待通りの相対パスへ
インストールされることを確認。さらにインストール先のバイナリを、ソースツリーとは
無関係な隔離ディレクトリから`BM_DATA_DIR`・`BM_SEEDS_FILE`を明示指定して起動し、
実際にDBファイルが指定先へ作られ、CWD直下には何も作られず、SIGTERMで正常終了する
ことを確認した。

`build-Debug`/`build-Release`/`build-Sanitize`/`build-TSan`の4種全てクリーンビルドで
警告ゼロ・ctest 38件全通過を確認(TSan含む)。

### systemdユニットファイル(backlog項目10の4/5、2026-08-24)

**設計判断(ユーザーと相談)**: `ExecStart`等のインストール先パスを`/usr/local`
(`CMAKE_INSTALL_PREFIX`の既定値、`cmake --install`をそのまま実行した場合の実際の
インストール先)前提にするか、配布パッケージを想定した`/usr`前提にするか確認し、
前者で合意した。Ubuntu/Debianパッケージリポジトリへの登録は現実的な目標ではない
(ユーザー本人の運用が主目的)という位置づけの確認も込み。`/usr`前提にしたい場合は
ユニットファイル内の`/usr/local`を置換するだけで対応できるようコメントを残した。

**`systemd/bitmessaged.service`の内容**:
- `Type=simple`・`Restart=on-failure`(ユーザー指定通り)。`on-failure`は`exit(0)`や
  正常なシグナル終了では発火しないため、「予期しないクラッシュ(SIGSEGV/OOM-kill等)
  からは自動復旧するが、`systemctl stop`による意図的な終了では再起動しない」という
  意図に合う。これまで`watchdog_daemon_a.sh`(DESIGN.md参照)が担っていた役割を
  systemd自身に移管する形になる。
- `DynamicUser=yes`+`StateDirectory=bitmessage`+`ConfigurationDirectory=bitmessage`:
  systemdに`/var/lib/bitmessage`(所有権含む)・`/etc/bitmessage`の作成を任せ、専用の
  システムユーザー作成やディレクトリの手動`chown`が一切不要になる現代的な作法。
- `Environment=BM_DATA_DIR=/var/lib/bitmessage`・`BM_CONFIG_FILE=/etc/bitmessage/
  bitmessage.conf`・`BM_SEEDS_FILE=/usr/local/share/bitmessage/observed_nodes.txt`:
  backlog項目10の2/5・3/5で追加した環境変数を実際に使い、systemd管理下での標準的な
  配置に固定する。
- セキュリティ強化は`NoNewPrivileges`/`PrivateTmp`/`ProtectHome`等の軽めのものに留め、
  `ProtectSystem=strict`のような強い制限は意図的に入れなかった。Tor ControlPort連携
  (`/run/tor/control`等、実行時の設定次第でパスが変わりうる)が強い制限下で気づかない
  うちに塞がれるリスクを避けるため。
- `After=network-online.target`/`Wants=network-online.target`(outbound P2P接続の
  ためネットワーク到達性を待つ)。

**CMake統合**: `install(FILES systemd/bitmessaged.service DESTINATION
${CMAKE_INSTALL_LIBDIR}/systemd/system)`を追加。systemdの`pkg-config`経由での
`systemdsystemunitdir`問い合わせ方式は、ビルド環境にsystemdの開発用pkg-configファイルが
無いと失敗しうるため、多くのCMakeプロジェクトで使われている
`${CMAKE_INSTALL_LIBDIR}/systemd/system`への直接インストールに倣った。

**検証**: `systemd-analyze verify`でユニットファイルの構文が正しいことを確認
(`ExecStart`先を実際のビルド成果物のパスに一時的に差し替えて検証、実運用のパスは
未インストールのため検証できないのは想定通り)。`DESTDIR`付き`cmake --install`で
`.service`ファイルが期待通りの相対パスへインストールされることも確認した。

この変更は`CMakeLists.txt`(`install()`追加)と新規ファイル`systemd/bitmessaged.service`
のみで、Cソースコードは一切変更していないため、`build-Debug`/`build-Release`は
クリーンビルド+ctest 38件全通過を確認したが、`build-Sanitize`/`build-TSan`は
再ビルドが警告ゼロで通ることのみ確認し(コード変更が無い以上ctestの結果が変わる
理由が無いため)、フルの`ctest`再実行は省略した。

### 非Ubuntu環境への軽い手当て(backlog項目10の5/5、2026-08-24)

これでbacklog項目10(Releaseビルドでのテスト・インストール・systemdサービス化)の
5分割全てに着手完了した。当初DESIGN.mdで結論していた通り「CIにもう1ディストリ追加」
「Tor control socketの既定値をドキュメントで明記」の2点の軽い手当てで十分と判断し、
以下を実施した。

**CI**: `.github/workflows/ci.yml`へ`build-and-test-fedora`ジョブを追加(`container:
fedora:latest`、`dnf install cmake gcc make openssl-devel sqlite-devel git`で
依存関係を導入)。Sanitizer系は既にUbuntu上で十分カバーしているため、Fedora側は
素のDebugビルド+ctestのみに絞った(全ジョブをディストリ×Sanitizerの掛け算にすると
CI時間が過大になるため)。ローカルにdocker/podmanが無くこの場では実行確認できず、
実際の動作確認は次回pushでのGitHub Actions実行時になる。

**ドキュメント**: `core/config_file.h`(`tor_control_socket`フィールド)・
`core/config_file.c`(既定値設定箇所)へ、既定値`/run/tor/control`がDebian/Ubuntu系
Torパッケージの慣習的パスであり他ディストリでは異なりうる旨のコメントを追加。
`README.md`の環境変数一覧にも同様の注記を追加した。あわせて、backlog項目10の2/5・3/5で
追加した`BM_DATA_DIR`/`BM_SEEDS_FILE`環境変数が`README.md`の一覧に載っていなかった
(追加時に見落としていた)ことに気づき、この機会に追記した。

Cソースコードの変更はコメント追加のみ(挙動に影響しない)のため、`build-Debug`で
クリーンビルド+ctest 38件全通過のみ確認し、他3ビルドの再確認は省略した。


### ドキュメント再構成: DESIGN.md/DESIGN-LOG.md/CHANGELOG.mdの分離、v1.2.0リリース(2026-08-24)

**経緯**: backlog項目10完了後、ユーザーから「DESIGN.mdがごちゃごちゃしている」
「README.mdのv1スコープ外節が古い」「v1.2タグ・リリースノート整理をどうするか」の
相談を受けた。調査した結果、DESIGN.md(当時3616行)のうち§11が約2484行(約69%)を
占め、今も有効なアーキテクチャ資料(§0〜§10)と日付入りセッション記録が同じファイルに
混在していたことが「ごちゃごちゃ」の正体だと判明。以下を順に実施した。

1. README.mdの「v1スコープ外」節を修正: inbound接続・Dandelion++のstem機能は
   v1.1で実装済みのため除外し、実際に凍結中の項目(GPU PoW・LAN discovery・
   EVP_PKEY移行)を明記した。
2. CHANGELOG.mdを新設: v1.0.0タグ・v1.1.0タグ間のコミット履歴と、v1.1.0以降の
   DESIGN.md記載内容から、利用者向けの追加/修正/変更を抜き出してKeep a Changelog
   形式で整理した。
3. v1.2.0タグを作成しGitHub Releaseを公開。あわせてv1.0.0/v1.1.0も遡ってGitHub
   Release化した(いずれもCHANGELOG.mdの該当セクションを本文に使用)。作成順の影響で
   一時的にv1.0.0が「Latest」表示になる問題が起きたため、`gh release edit v1.2.0
   --latest`で明示的に修正した。
4. DESIGN.mdの§11(旧: 日付入りセッション記録+現在のbacklogリストが混在)を分離。
   §0〜§10・§11の見出しと現在のbacklogリスト(旧`### v1.1以降のbacklog`以降)だけを
   DESIGN.mdに残し、それより前の日付入りセッション記録を丸ごとDESIGN-LOG.md
   (このファイル)へ移動した。diffで内容が完全一致することを確認済み(内容の削除は
   無い、単純な移動)。backlogリスト内の「上記まとめ参照」等、移動先を失った
   後方参照は「DESIGN-LOG.mdの該当セッション参照」へ書き換えた。見出しテキスト自体は
   変更していないため、README.mdの`DESIGN.md#11-...`アンカーリンクや、ソースコード中の
   `DESIGN.md §11`参照(30箇所以上)は引き続き有効。結果、DESIGN.mdは3616行→1261行
   (約65%削減)。

### `bitmessage-cli`のHTTPリクエスト確保サイズ修正(セキュリティレビューの端緒、2026-08-24)

**経緯**: 上記のドキュメント整理が一段落した際、ユーザーから「脆弱性チェックも
終わったと判定していいのか」と問われた。それまでのASan/UBSan/TSan導入(backlog項目9)は
あくまで「メモリ安全性」の検査であり、脆弱性チェック全般(SQLインジェクション・
認証まわり・untrusted入力のパース処理の堅牢性等)を系統的にレビューしたことは
無かった、と正直に回答。その場で軽くコードを見たところ、`src/cli/http_client.c`の
`bm_http_post_json`で以下を発見した:

```c
char *request = malloc(strlen(body) + strlen(auth_header) + 256);
int req_len = sprintf(request, "...Host: %s\r\n...", host, ...);
```

確保サイズの計算に`host`(`BM_API_HOST`環境変数由来、長さ無制限)が含まれておらず、
一見するとヒープバッファオーバーフローに見えた。しかし、この`sprintf`より前に
`connect_to()`内の`inet_pton(AF_INET, host, ...)`が呼ばれており、これは`host`が
正しいIPv4のdotted-decimal形式(最大15〜16文字程度)でなければ即座に失敗して
returnする。つまり`sprintf`へ到達する時点で`host`は既に短いことが保証されており、
**この経路は実際には到達不能**だった(ユーザーへの報告時に「見つけた」と言った後、
念のため検証して訂正した)。

とはいえ、確保サイズの計算にhostを含めていないこと自体はコードとして脆いパターン
(将来`connect_to`の実装がホスト名解決に変わる等でこの前提が崩れた場合、即座に
悪用可能なバグへ変わりうる)だったため、`strlen(host)`をサイズ計算へ追加し、
`sprintf`も`snprintf`へ置き換えて防御的に修正した。あわせて、`bm_http_post_json`
自体にこれまで専用のユニットテストが一つも無かった(`tests/test_cli_integration.sh`
経由での間接的なカバレッジのみ)ことに気づき、`tests/test_http_client.c`を新規追加
(ローカルにダミーTCPサーバーを立てて実際のリクエスト組み立て・レスポンス解析を検証、
認証あり/無し・接続失敗の3シナリオ)。`tests/CMakeLists.txt`へ`http_client`として
登録(計39件)。

**教訓として記録**: 「Sanitizer導入 = 脆弱性チェック完了」ではない。ASan/UBSan/TSanは
メモリ破壊・UB・データ競合という重要だが限定的なカテゴリしかカバーせず、
SQLインジェクション・認証ロジック・untrusted network入力のパース処理の堅牢性
(このプロジェクトの本来の脅威モデルの中心であるP2Pメッセージパーサ群)といった
観点は別途レビューが必要。今回の一件も「たまたまコードを流し見て気づいた」もので、
系統的なレビューではなかった。backlogへ正式な項目として追加する(下記参照)。

`build-Debug`/`build-Release`/`build-Sanitize`/`build-TSan`の4種全てクリーンビルドで
警告ゼロ・ctest 39件全通過を確認。

