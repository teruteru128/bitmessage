# Bitmessage C言語フルスクラッチ 設計文書

方針: `~/Documents/Projects/teruteru128/study/libstudy` の `bm_*` 資産を移植・拡張ベースとして採用。
4層(フロント/コア暗号/インフラ/計算)は当面 **1プロセス内のスレッド分離** とし、
層間はスレッドセーフキュー(`queue.c` 流用)または関数呼び出しで接続する。
将来のプロセス分離に備え、層をまたぐデータは常に「シリアライズ済みバイト列 or 値渡し可能な構造体」でやり取りし、
生ポインタや同一プロセス前提のロックを層境界で共有しない。

## 0. 既存資産の棚卸し(2026-08-20時点、libstudy/bm_*)

| ファイル | 状態 | 再利用方針 |
|---|---|---|
| `bm_protocol.c/h` | version/verack/addr/inv/ping/pong の parse/encode 実装済み(766行) | ほぼそのまま移植。`process_command` はキュー投入に書き換え |
| `bm_sonota.c/h` | 鍵導出・secp256k1鍵生成・RIPEMD160・Base58アドレス(v3/v4)・WIF・varint 実装済み(389行) | そのまま移植。ECIES暗号化はここに無いので新規追加 |
| `bm_network.c/h` | `fd_data`構造体、`new_fd_data`/`free_fd_data`、verack/pong送信、`postVersion` | 移植。`epoll_wait_thread`/`upload_thread`/`download_thread`はスタブ→新規実装 |
| `bm_queue.c/h` | pthread mutex+condのスレッドセーフキュー(78行) | そのまま全層間キューの基盤として採用 |
| `bm_crypto.c` | **空(0行)** | ECIES暗号化・ECDSA署名を新規実装 |
| `bm_node_db.h`, `bm_peer_manager.h`, `bm_storage.h`, `bm_address.h` | **空** | 本設計で新規に中身を設計 |
| `bm_api.h` | xmlrpc-c ベースのAPI宣言のみ(PyBitmessage API互換のメソッド名) | JSON-RPC化するか要検討(§5) |
| `study/src/bm.c` | 固定IP1台に接続するPoCクライアント(epollシングルスレッド) | ロジックを`network_epoll_thread`に分解移植。`parse_message`がNULLを返した際の分岐に未整理コードあり→書き直し |

既知の修正点: `bm.c` L164-207 で `parse_message` が NULL を返すケース(不完全 or checksum不一致)の処理が
「不完全メッセージ待ち」と「不正メッセージ破棄」を混同しており、`msg`がNULLなのに読み進めようとする箇所がある。
移植時に `parse_message` を「ヘッダ未着(NULL, errno的な区別なし)」と「checksum不一致(別関数 or 判別可能な返り値)」に分離する。

## 1. スレッドモデル

**`network_epoll_thread`と`peer_connector_thread`はv1実装済み(2026-08-21)。詳細は§1.1の各項目に
追記。実際にtestnetの実ノード(`5.78.198.100:8444`, `/PyBitmessage:0.6.3.2/`)とTCP接続→version送信→
verack受信→相手のversion受信、というプロトコルレベルのハンドシェイクが成立することを手動で確認済み
(magic bytes・24byteヘッダ・checksum・varintエンコード・versionメッセージ構築が実ネットワークと
バイト単位で相互運用可能であることの実証)。
**`peer_connector_thread`の常駐化・再接続維持ループも実装済み(2026-08-23)。**
`bm_peer_connector_thread`(`src/infra/peer_connector.c`)として、起動直後に
`bm_peer_connector_connect_initial`相当を1回実行し、以後30秒間隔で接続数
(`peer_registry`参照)を`max_outbound`まで補充し続ける。同じ相手への二重接続は
`bm_peer_registry_has_peer`で回避する。接続試行の成否は`peer_manager.c`の新関数
`bm_peer_manager_record_result`でrating(成功+0.1/失敗-0.1、上下限±1.0、PyBitmessageの
rating更新方式を簡略化したもの)へ反映され、`list_top`(rating降順)の結果に効いてくる。
シャットダウンは`volatile sig_atomic_t`のstop flagを1秒間隔でポーリングする方式にし、
`main.c`からpthread_joinできるようにした(この時点でネットワーク関連スレッドの中で
唯一グレースフルシャットダウンに対応している)。実testnetノードで65秒稼働させ、
2回の再接続サイクル(生存中の相手は据え置き、接続できない相手のratingが-0.1ずつ
減っていく)とSIGINT後0.5秒程度でのプロセス終了を実機で確認済み。

**`object_sync_thread`実装済み(`src/infra/object_sync.c/h`、2026-08-22)。** `command_worker_thread`の
役割も兼ねる形で1関数(`bm_object_sync_dispatch`)にまとめ、`network_epoll_thread`のハンドラとして
差し替える(`main.c`)。実装内容:
- `inv`受信 → 未所持hashのみ`getdata`で要求(`bm_object_store_has`で既知判定)
- `getdata`受信 → `object_pool.db`にあれば同じ接続へ`object`を返す(無ければ黙って無視)
- `object`受信 → 重複排除して`object_pool.db`へ保存。type=msgなら`trial_decrypt`(§5.3)を試み
  成功時inboxへ、type=pubkey(v2/v3)なら`pubkey_cache`(§2.3)へ登録。**ack突合せ
  (`bm_messages_store_try_mark_ack_received`、§5.5)は既知/未知・type問わず毎回最初に試みる**
  ようにしている点に注意(自分がack先回り登録した直後に同じackが"届く"ケースでも取りこぼさない
  ため、既知object早期returnより前に置く設計)
- 期限切れobjectのGC(`bm_object_sync_gc`、`object_store.c`の`delete_expired`を呼ぶだけ)を
  300秒間隔で間引きながら実行
- 新規に取り込んだobject(受信msgそのもの、埋め込みfullAckPayload取り込み分の両方)は
  `src/infra/peer_registry.c/h`(接続レジストリ、2026-08-22実装)経由で受信元コネクション以外の
  接続中peerへ`inv`をbroadcastする(§9.1「常にfluff」に対応)。`peer_registry`はmutexで保護した
  `bm_fd_data*`の配列で、接続確立時(`peer_connector.c`)に登録・切断検知時(`network.c`の
  epoll loop)に削除する。`main.c`で1つ生成し`object_sync_ctx`/`peer_connector_config`双方へ
  共有ポインタとして渡す

DoS対策としてinv/getdataの要素数上限(50000)とobject payloadサイズ上限(256KiB、§5.0)を
このディスパッチ内で強制する。

**受信object全般のPoW検証、実装済み(2026-08-23)。** それまで`validate_and_store_ack`(§5.5)の
みが行っていたPoW検証を`handle_object`(`object`受信の共通経路)にも適用した。共有の静的関数
`object_pow_is_valid`が、期限切れ(`expires_time<=now`)と、ネットワーク既定の最低難易度
(`BM_NETWORK_MIN_NONCE_TRIALS_PER_BYTE`/`_PAYLOAD_LENGTH_EXTRA_BYTES`、いずれも1000)を
満たさないobjectを即座に(重複排除やtype別処理の前に)拒否する。宛先固有の難易度は
受信時点では分からない(pubkey_cache未登録の相手からも受信しうる)ため、常にネットワーク
既定値で判定する。自分自身が生成したobject(`validate_and_store_ack`・
`handle_incoming_getpubkey`の自応答・`bm_object_sync_broadcast_thread`・再送)はこの経路を
通らないため影響を受けない(自分のPoWは信頼する)。`tests/test_object_sync.c`で意図的に
低難易度(50,50)でPoWしたobjectが拒否される(`object_pool.db`に入らない)ことを検証済み。

**`api_server.c`からの能動的なinv broadcastも実装済み(2026-08-22)。** core層(`api_server.c`)は
infra層の`peer_registry`を直接呼べない(§1参照)ため、common層の`struct bm_broadcast_item`
(`src/common/broadcast_item.h`)を介して`broadcast_queue`(§1.2、これまで骨格のみで未配線
だったキュー)経由で受け渡す。`h_sendMessage`は`bm_send_pipeline_send_message`が生成した
objectを(即座にfreeするのではなく)`broadcast_queue`へpushし、`object_sync.c`の新スレッド
`bm_object_sync_broadcast_thread`(`main.c`で起動、`queues_shutdown`で自然停止するので
join可能)がpopして`object_pool.db`への挿入と`peer_registry`経由のinv broadcast(除外無し、
全接続peerへ)を行う。実testnetノードに接続した状態で`sendMessage`を呼び、
`object_pool.db`に該当行が入ること・ログに`[object_sync] broadcasted locally-originated
object to peers`が出ることを実機で確認済み。

v1スコープ外(既知の制限、TODO): addrのpeer_manager永続化。getpubkey受信時の自応答・
broadcast(type=3)の購読・復号・pubkey v4の自動キャッシュはいずれもこの後実装済み
(§5.1, §5.4参照)。
`tests/test_object_sync.c`でinv→getdata、object重複排除、getdata応答、GC、
2本目のpeer接続を接続レジストリへ登録した上で「受信元以外にだけinv broadcastが届く」ことの
検証、そしてsend_pipeline.cで実際に組み立てたmsgをdispatchに流し込み「trial_decrypt→
inbox保存→埋め込みfullAckPayloadのobject_pool.db取り込み→そのack自体を受信した体で
dispatchに流す→sent.statusがackreceivedへ遷移」までのack往復をend-to-endで検証済み
(2026-08-22)。実testnetノードとの通信でも`bitmessaged`が正常動作することを確認済み。

### 1.1 スレッド一覧

```
[main]
  起動処理(DB初期化、鍵ロード、設定読込)、シグナルハンドリング、全スレッドのjoin

── インフラ層 ──────────────────────────────
[network_epoll_thread]        epoll_wait ループ。read()でconnectedBufferに追記、
                               parse_messageでmessage単位に切り出し → command_queue へpush
[command_worker_thread] × N   command_queueから message を取り出し process_command 実行
                               (version/verack/addr/inv/ping/pong応答、objectはobject_inbox_queueへ)
[peer_connector_thread]       known_nodesを参照し定期的にアウトバウンド接続を試行、
                               接続数(outbound上限/inbound上限)を維持。connect()した fd を
                               epoll_ctl(ADD)して network_epoll_thread に合流させる
[object_sync_thread]          inv受信→未所持hashをgetdata要求、object受信→object_pool.dbへ保存
                               →新着hashをdecrypt_request_queueへpush

── コア・暗号層 ────────────────────────────
[api_server_thread]           Unixドメインソケット(将来: TCP)でJSON-RPC受付。フロントからの
                               送信要求/アドレス作成要求等をディスパッチ
[decrypt_worker_thread] × N   decrypt_request_queueから新着objectを取り出し、保有する
                               全秘密鍵でトライアル復号。成功したらinbox DBへ保存
[send_pipeline_thread]        送信要求(api_server_threadから)を受け取り、暗号化(bm_crypto)
                               →pow_request_queueへpush。PoW完了通知を待って完成Blobを
                               broadcast_queue(インフラ層行き)へpush

── 計算層 ──────────────────────────────────
[pow_worker_thread] × NumCPU  pow_request_queueからjobを取り出しnonce探索、
                               見つかったらpow_result_queueへpush
```

**実装上の注記(2026-08-22)**: 上記は初版設計時点の理想形。実装では`bm_queue.h`のキュー群
(`main.c`の`struct bm_queues`)は骨格として確保したまま中身が未配線で、`command_worker_thread`/
`decrypt_worker_thread`/`pow_worker_thread`はそれぞれ独立スレッドではなく、`object_sync_thread`
(`network_epoll_thread`のハンドラとして動作)から`trial_decrypt`/`pow_engine`を直接関数呼び出しする
形に単純化されている(1プロセス内スレッド分離という前提上、キュー越しの非同期化より直接呼び出しの
方がシンプルで、v1では並列度より実装の見通しを優先した)。`pow_worker_thread`の並列化(NumCPU本)は
§11のTODO。

### 1.2 層間キュー

`bm_queue.h` の `Queue` (mutex+cond、voidポインタの単方向リンクリスト)をそのまま使い、
キューごとに要素の構造体を定義する。将来プロセス分離する場合はこの構造体をそのままシリアライズ形式にできるよう、
可変長データは全て「長さ+バイト列」で持たせる(生ポインタの相互参照を避ける)。

| キュー | Producer → Consumer | 要素 |
|---|---|---|
| `command_queue` | network_epoll_thread → command_worker_thread | `{fd_data*, struct message*}` |
| `object_inbox_queue` | command_worker_thread → object_sync_thread | `{unsigned char hash[32], unsigned char *payload, size_t len}` |
| `decrypt_request_queue` | object_sync_thread → decrypt_worker_thread | `{unsigned char hash[32]}` (payloadはobject_pool.dbから引く) |
| `send_request_queue` | api_server_thread → send_pipeline_thread | `{from_address, to_address, subject, body, encoding, ttl}` |
| `pow_request_queue` | send_pipeline_thread → pow_worker_thread | `{unsigned char *payload_with_header, size_t len, uint64_t target}` |
| `pow_result_queue` | pow_worker_thread → send_pipeline_thread | `{uint64_t nonce, unsigned char hash[32]}` |
| `broadcast_queue` | send_pipeline_thread → network_epoll_thread(送信担当) | `{unsigned char *object_bytes, size_t len}` |

**`broadcast_queue`のみ実際に配線済み(2026-08-22)**。他のキューは上記「実装上の注記」の通り
未使用のまま。実際のproducerは`api_server.c`の`h_sendMessage`(send_pipeline_threadという
独立スレッドは無いため)、consumerは`object_sync.c`の`bm_object_sync_broadcast_thread`
(専用スレッド、`main.c`で起動)。要素の型は`struct bm_broadcast_item`(`src/common/
broadcast_item.h`、core/infra両層から素朴に参照できるようcommon層に置く)。詳細は§1直下の
`object_sync_thread`実装ノート参照。

### 1.3 DB接続方針

SQLiteはスレッドごとに個別コネクションを開く(`SQLITE_OPEN_FULLMUTEX` + WALモード)。
1コネクションを複数スレッドで共有しない。書き込みが集中する`object_pool.db`はWALモードで
readerをブロックしないようにする。

## 2. DBスキーマ全体設計

(既存2DB: `peers.db`, `object_pool.db` に加え、以下を追加)

### 2.1 `peers.db` (インフラ層) — 元案を拡張

```sql
CREATE TABLE IF NOT EXISTS hosts (
  ip_address TEXT NOT NULL,
  port INTEGER NOT NULL,
  stream INTEGER NOT NULL DEFAULT 1,
  services INTEGER NOT NULL DEFAULT 1,
  last_seen INTEGER NOT NULL,
  rating REAL NOT NULL DEFAULT 0.0,     -- PyBitmessage同様 -1.0〜+1.0程度で減衰させる
  source TEXT NOT NULL DEFAULT 'unknown', -- 'seed' | 'addr_msg' | 'manual'
  PRIMARY KEY (ip_address, port, stream)
);
CREATE INDEX IF NOT EXISTS idx_hosts_stream_rating ON hosts(stream, rating DESC);
```

### 2.2 `object_pool.db` (インフラ層) — 元案を拡張

```sql
CREATE TABLE IF NOT EXISTS objects (
  hash BLOB PRIMARY KEY,
  object_type INTEGER NOT NULL,   -- getpubkey=0, pubkey=1, msg=2, broadcast=3 (PyBitmessage protocol.py準拠)
  stream INTEGER NOT NULL,
  payload BLOB NOT NULL,          -- object本体(nonce込み、受信バイト列そのまま)
  expires_time INTEGER NOT NULL,
  received_time INTEGER NOT NULL,
  processed INTEGER NOT NULL DEFAULT 0  -- トライアル復号済みフラグ(msg/broadcastのみ意味を持つ)
);
CREATE INDEX IF NOT EXISTS idx_expires ON objects(expires_time);
CREATE INDEX IF NOT EXISTS idx_stream_type ON objects(stream, object_type);
CREATE INDEX IF NOT EXISTS idx_unprocessed ON objects(processed) WHERE processed = 0;
```

### 2.3 `identity.db` (コア・暗号層、新規) — keys.dat相当

権限を厳格に(0600)。**PyBitmessageと異なり平文保存はしない**(§8-1)。秘密鍵は常にパスフレーズ由来鍵で
ラップして保存し、起動直後は全アドレスがロック状態。`unlockAddress`されるまでプロセスメモリに
生の秘密鍵は存在しない。詳細な鍵ライフサイクルは§7参照。

```sql
CREATE TABLE IF NOT EXISTS identities (
  address TEXT PRIMARY KEY,          -- 'BM-...'
  label TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,  -- PyBitmessage同様「トライアル復号対象に含めるか」の表示上フラグ
                                        -- (unlockedかどうかとは独立。enabled=0かつunlockedでも復号対象外)
  is_chan INTEGER NOT NULL DEFAULT 0,
  address_version INTEGER NOT NULL,  -- 3 or 4
  stream INTEGER NOT NULL,
  signing_pubkey BLOB NOT NULL,      -- 64byte (0x04プレフィックス無し、PyBitmessage準拠)
  encryption_pubkey BLOB NOT NULL,   -- 64byte
  -- 秘密鍵は鍵ラッピングキー(KEK)で暗号化して保存。KEKはpassphraseからKDFで導出し、メモリに残さない
  kdf_algo TEXT NOT NULL DEFAULT 'scrypt',   -- 将来argon2idへの移行を許すため文字列化
  kdf_salt BLOB NOT NULL,              -- 16byte random
  kdf_params TEXT NOT NULL,            -- JSON, 例: {"N":131072,"r":8,"p":1}
  wrapped_priv_signing_key BLOB NOT NULL,    -- AES-256-GCM(KEK, nonce=12byte) : nonce(12)+ciphertext(32)+tag(16)=60byte
  wrapped_priv_encryption_key BLOB NOT NULL, -- 同上
  nonce_trials_per_byte INTEGER NOT NULL DEFAULT 1000,
  payload_length_extra_bytes INTEGER NOT NULL DEFAULT 1000,
  created_time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pubkey_cache (
  ripe BLOB PRIMARY KEY,             -- 宛先のripeハッシュ(20byte)、v4はtag(32byte)を別カラムで持つ
  tag BLOB,                          -- v4アドレス宛のみ(32byte)。ripeが不明な段階でも引けるようにNULL許容+別インデックス
  address_version INTEGER NOT NULL,
  stream INTEGER NOT NULL,
  behavior_bitfield INTEGER NOT NULL,
  signing_pubkey BLOB NOT NULL,      -- 64byte
  encryption_pubkey BLOB NOT NULL,   -- 64byte
  nonce_trials_per_byte INTEGER,     -- version>=3のみ意味を持つ
  payload_length_extra_bytes INTEGER,-- version>=3のみ意味を持つ
  used_personally INTEGER NOT NULL DEFAULT 0, -- 自分が送信に使った pubkey は掃除対象から除外(PyBitmessage同様)
  received_time INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pubkey_cache_tag ON pubkey_cache(tag);
```

**実装済み(`src/core/pubkey_cache.c/h`)。** DB CRUD(`bm_pubkey_cache_upsert`/`_lookup_by_ripe`/`_lookup_by_tag`/
`_mark_used_personally`、upsertは`ON CONFLICT(ripe) DO UPDATE`で`used_personally`を保持)に加え、
pubkeyオブジェクト(v2/v3/v4)のパーサ・検証を実装(`bm_parse_pubkey_v2/v3/v4`、`message_builder.c`の
構築処理の逆)。v3は埋め込みECDSA署名を検証、v4は`bm_address_derive_secret_and_tag`(§3.4相当、
`address.c`に共通化)でtagを算出して候補と突き合わせてから復号・署名検証・ripe一致まで確認する。
`message_builder.c`で構築したオブジェクトとのラウンドトリップ、改ざん検知、候補違い時の拒否、DB
upsert/lookupを`tests/test_pubkey_cache.c`で検証済み(2026-08-21)。現状は手動登録(`cachePubkey` API/
`cache-pubkey` CLI)またはテスト経由のみで、実ネットワークから受信した`pubkey`オブジェクトをこの
パーサへ流し込む配線は未実装(§9 TODO参照)。

### 2.4 `messages.db` (コア・暗号層、新規) — 受信/送信ボックス

```sql
CREATE TABLE IF NOT EXISTS inbox (
  msg_id BLOB PRIMARY KEY,          -- object hash
  to_address TEXT NOT NULL,
  from_address TEXT NOT NULL,
  subject BLOB NOT NULL,
  body BLOB NOT NULL,
  received_time INTEGER NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  folder TEXT NOT NULL DEFAULT 'inbox'  -- 'inbox' | 'trash'
);

CREATE TABLE IF NOT EXISTS sent (
  ack_data BLOB PRIMARY KEY,
  to_address TEXT NOT NULL,
  from_address TEXT NOT NULL,
  subject BLOB NOT NULL,
  body BLOB NOT NULL,
  status TEXT NOT NULL,             -- 'encoding'|'doingpow'|'broadcasted'|'ackreceived'
  sent_time INTEGER NOT NULL,
  ttl INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS address_book (
  address TEXT PRIMARY KEY,
  label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions ( -- §5.4 broadcast購読先、実装済み(2026-08-23)
  address TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1
);
```

## 3. 暗号層(bm_crypto)設計

出典: PyBitmessage `src/highlevelcrypto.py`, `src/pyelliptic/ecc.py`, `src/class_addressGenerator.py`

### 3.1 ECIES暗号化(メッセージ本体・pubkey v4・broadcastの暗号化に共通)

**実装済み(`src/core/crypto.c`)。PyBitmessage本家の`pyelliptic`と実際にPython⇔Cで暗号文・平文を
相互に暗号化/復号できることをクロス検証済み(2026-08-20、`highlevelcrypto.encrypt/decrypt`との
往復で平文一致を確認)。**

PyBitmessageは`pyelliptic.ECC.raw_encrypt`をそのまま使っている。**この関数の一時公開鍵エンコードは
標準の0x04+X+Yではなく、pyelliptic独自のTLV形式である点が実装上の最重要注意点**(ここを素朴に
`EC_POINT_point2oct`の65byte形式で実装すると本物のBitmessageネットワークと相互運用できなくなる)。

手順(暗号化側):
1. 一時ECDH鍵ペア`(d_e, Q_e)`をsecp256k1上に生成
2. 共有秘密 `S = ECDH(d_e, Q_recipient)` — OpenSSL `ECDH_compute_key`で得られる32byte(X座標のみ、Yは使わない)
3. `K = SHA512(S)` (64byte)。`key_e = K[0:32]`(AES鍵)、`key_m = K[32:64]`(HMAC鍵)
4. `IV` = ランダム16byte (AES-256-CBCのブロック長)
5. 一時公開鍵`Q_e`を以下のTLVでエンコード(**70byte固定**、secp256k1前提):
   `curve_id(2byte BE, =714) || len_x(2byte BE,=32) || X(32byte) || len_y(2byte BE,=32) || Y(32byte)`
   (`714`はOpenSSLのNID_secp256k1。値は固定なのでCではリテラルで埋め込んで良い)
6. `ciphertext = AES-256-CBC-Encrypt(key_e, IV, PKCS7Pad(plaintext))`
7. `mac = HMAC-SHA256(key_m, IV || Q_e_TLV || ciphertext)`
8. 出力 = `IV || Q_e_TLV || ciphertext || mac` (16 + 70 + len(ciphertext, 16の倍数) + 32 byte)

復号側: `IV`(先頭16byte)→`Q_e_TLV`(次70byte、パース時にcurve_idが714でなければ拒否)→
`ciphertext`(末尾32byteを除いた残り)→`mac`(末尾32byte)。まず`HMAC-SHA256(key_m, IV||Q_e_TLV||ciphertext)`を
定数時間比較で検証してから復号する(MAC検証failより先にAES複合するとpadding oracleになるため順序厳守)。

`ECDH(d, Q)`の実体はOpenSSLの`EC_KEY`+`ECDH_compute_key`、またはOpenSSL3の`EVP_PKEY`+`EVP_PKEY_derive`
系APIで代替できる。出力は共有点のX座標をbig-endianで32byteに左詰めゼロ埋めしたもの(pyellipticは
`ECDH_compute_key(buf, 32, ...)`で明示的に32byte出力を指定している)。

### 3.2 ECDSA署名

**実装済み(`src/core/crypto.c`)。`highlevelcrypto.sign/verify`(digestAlg="sha256")とのクロス検証済み
(2026-08-20、Python生成署名をCで検証、C生成署名をPythonで検証、双方向で成功)。
OpenSSL 3.0で`EC_KEY`/`ECDSA_sign`/`ECDSA_verify`系が非推奨になっているが、生成される署名は
ビット単位で同一でありAPI自体は当面removeされない見込みのため、EVP_PKEY+OSSL_PARAM経由への
書き換えはコストに見合わないと判断しあえてそのまま使っている(§3.5の規律は維持: ヘッダには
`EC_KEY`型を露出させていない)。**

- curve: secp256k1、ハッシュ: **SHA256のみ実装する**(確定、§8-2)。SHA1はPyBitmessageがSHA256移行(サポート追加
  2015-03-27、デフォルト化2019-11-18)前の旧クライアントと会話するための検証専用フォールバックだったが、
  該当ノードは実質的に存在しないと判断し送受信とも実装しない
- 署名フォーマット: OpenSSL `ECDSA_sign`が返すDER形式のASN.1シーケンス(可変長、最大約72byte)。
  オブジェクトペイロード中では`encodeVarint(len(signature)) + signature`として埋め込む
- **署名対象データはオブジェクト種別ごとに異なる**(§5で各オブジェクトごとに明記)。共通するのは
  「オブジェクトヘッダ(time+type+version+stream、暗号化前)」と「オブジェクトのメインペイロード
  (暗号化される場合は暗号化前の平文)」を連結したものに署名し、**署名自体はメインペイロードの末尾に
  追記してから(必要なら)暗号化する**という順序

### 3.3 鍵導出

```
deterministic_keys(passphrase, nonce):
    priv = SHA512(passphrase || encodeVarint(nonce))[0:32]
    pub  = secp256k1_point_mul(priv, G)   # 65byte (0x04||X||Y)、ワイヤ上は先頭0x04を落として64byte
    return priv, pub
```

既存`bm_sonota.c`の`deriviedPrivateKey`はこの計算式と一致しており(passphrase→varint(nonce)の順でEVP_DigestUpdate)、
そのまま流用可能。`getPublicKey`(EC_POINT_mul)も流用可能。

**未実装で新規に追加が必要な部分**: 決定性アドレス生成のnonce探索ループ。
`class_addressGenerator.py`によると、署名鍵nonceと暗号化鍵nonceを(例えば0と1から開始し)ペアで
インクリメントしながら鍵ペアを生成し続け、`ripe = RIPEMD160(SHA512(signPub || encPub))`の
**先頭Nバイトが0x00になるまで**繰り返す。**signPub/encPubは0x04プレフィックス込みの65byteのまま**
(class_addressGenerator.py:183-184で`highlevelcrypto.random_keys()`が返す65byteをそのまま`to_ripe`に渡している。
`[1:]`で先頭バイトを落とすのは§5でワイヤに乗せる直前の別処理であり、ripe計算そのものには適用しない。
既存`bm_sonota.c`の`calcRipe`はこれを正しく実装済み)。Nはデフォルト1バイト
(`numberOfNullBytesDemandedOnFrontOfRipeHash`)、「もっと短いアドレス」オプション選択時は2バイト。
ランダムアドレス生成も同じループで、nonce更新の代わりに毎回新規ランダム鍵ペアを引く。

**アドレス文字列エンコード時の先頭ゼロ除去ルール**(`addresses.py:142-171`、既存`bm_sonota.c`の
`encodeAddress0`は`max`引数を使う独自ロジックで分かりにくいため、以下の単純な規則で書き直す):
```
if 2 <= version < 4:
    if ripe[0:2] == "\x00\x00": ripe = ripe[2:]
    elif ripe[0:1] == "\x00":   ripe = ripe[1:]
    # (それ以外はripeを削らない。最大2byteまでしか削らない)
elif version == 4:
    ripe = ripe.lstrip("\x00")   # 先頭の0x00を全て(理論上最大20byteまで)削る
storedBinaryData = encodeVarint(version) || encodeVarint(stream) || ripe
checksum = double_sha512(storedBinaryData)[0:4]
address = "BM-" + base58encode(storedBinaryData || checksum)
```

### 3.4 ハッシュ関数まとめ

| 用途 | アルゴリズム |
|---|---|
| ripeハッシュ(アドレス) | RIPEMD160(SHA512(signPub \|\| encPub)) |
| チェックサム(BMアドレス) | **double_sha512**(encodeVarint(version)\|\|encodeVarint(stream)\|\|ripe)[0:4] (`addresses.py:165`。SHA256ではない点に注意、実装時に誤りやすい) |
| チェックサム(WIF) | SHA256(SHA256(data))[0:4](Bitcoin方式、アドレスとはアルゴリズムが異なる) |
| メッセージヘッダchecksum | SHA512(payload)[0:4] |
| inventory hash(objectの識別子) | SHA512(SHA512(payload))[0:32] (`calculateInventoryHash` = double_sha512の先頭32byte) |
| PoW trial value | SHA512(SHA512(nonce(8byte BE) \|\| SHA512(payload)))[0:8] (§4) |
| ECIES鍵導出 | SHA512(ECDH共有X座標) |
| ECIESマック | HMAC-SHA256 |
| v4アドレスの`tag`/暗号化鍵 | SHA512(encodeVarint(version)\|\|encodeVarint(stream)\|\|ripe) → 前半32byteが鍵、後半32byteがtag |

### 3.5 暗号バックエンドの抽象化方針

暗号ライブラリはOpenSSL固定とする。ripeハッシュ計算(RIPEMD160)を含めsecp256k1のECDSA/ECDHまで一通り揃う
ライブラリが実質OpenSSLかlibgcryptしかなく(libsodiumはRIPEMD160非対応、mbedTLS 3.x系はRIPEMD160を
非推奨化)、選択肢が狭い上、現時点で差し替えたい具体的な動機(ライセンス・組み込みターゲット・静的リンク
サイズ等)もないため、実行時プラガブルな抽象化レイヤーは作らない。

ただし将来の差し替えコストを下げるため、**暗号関連モジュール(`common/hash.*`、および今後実装する
`core/crypto.*`, `core/address.*`)は公開ヘッダにOpenSSLの型(`EVP_MD*`, `EC_KEY*`, `BIGNUM*`等)を
一切露出させず、生バイト列(`const unsigned char *`+長さ)の関数シグネチャのみで公開する**という実装規律を
徹底する。この規律を守っておけば、将来本当にバックエンドを替えたくなっても該当`.c`ファイルの中身を
書き換えるだけで済み、呼び出し側コードには影響しない。

## 4. PoW計算エンジン設計

出典: PyBitmessage `src/proofofwork.py`

### 4.1 target計算式

```
target = 2^64 / ( nonceTrialsPerByte * ( L + ((TTL * L) / 2^16) ) )
  where L = payloadLength + 8 + payloadLengthExtraBytes
```

- `payloadLength`: nonce(8byte)を除いたオブジェクトペイロードの長さ(objectヘッダ含む、署名・暗号化後の最終バイト列)
- `TTL`: 秒単位、`embeddedTime - now`に相当する値(実際には送信側が別途計算したTTLをそのまま渡す)
- `nonceTrialsPerByte`, `payloadLengthExtraBytes`: デフォルトはPyBitmessage `defaults.py`の
  `networkDefaultProofOfWorkNonceTrialsPerByte = 1000`, `networkDefaultPayloadLengthExtraBytes = 1000`
  (identity.db側にも同名カラムがあり、宛先のpubkeyが要求するより厳しい値を採用する)
- 整数演算に注意: Pythonは任意精度なのでオーバーフローしないが、C実装では`nonceTrialsPerByte * (...)`が
  `uint64_t`を超えうる。`__uint128_t`(GCC/Clang拡張)で計算してから`target`はuint64_tに収める
  (targetは常に2^64未満になる想定だが、極端に小さいnonceTrialsPerByte×小さいLだとtargetが2^64近くまで
  行き得るので128bit中間演算は必須)

### 4.2 trial value計算

```
initialHash = SHA512(payload)                 # payload = nonce抜きの本体
trial_value(nonce) = SHA512(SHA512( pack_uint64_BE(nonce) || initialHash ))[0:8] as uint64_t (BE)
成功条件: trial_value(nonce) <= target
```

nonceは0から順に(並列時はワーカー数刻みで)探索。見つかった`nonce`をペイロード先頭に
`pack('>Q', nonce)`で付与したものが完成オブジェクト。

### 4.3 計算層のインターフェース(既存スレッドモデル§1.2との接続)

`pow_request_queue`の要素は `{payload_without_nonce, payload_len, target, ttl, request_id}`。
計算層は`payload`から`initialHash = SHA512(payload)`を一度だけ計算し、`pow_worker_thread`(NumCPU本)に
`nonce_start = worker_index`, `nonce_step = NumCPU`で割り当てて並列探索する(PyBitmessageの
`_pool_worker`と同じ「ワーカー数だけnonceをずらして開始し、ワーカー数刻みで進める」方式。
排他制御は不要で、見つけたワーカーが`pow_result_queue`に`{request_id, nonce}`を積み、他ワーカーは
共有の`atomic_bool found`を見て次のラウンドで抜ける)。

GPU/OpenCLは初版スコープ外(§8)。マルチスレッドCPU実装のみを対象とする。

**マルチスレッド探索、実装済み(`src/pow/pow_engine.c`、2026-08-23)。** 上記の設計どおり
`sysconf(_SC_NPROCESSORS_ONLN)`本のワーカースレッドに`nonce_start=worker_index`,
`nonce_step=num_threads`で探索空間を割り当てる。ただし`pow_request_queue`/`pow_result_queue`
経由ではなく、他の計算(`trial_decrypt`等)と同様に`bm_pow_run`を直接呼び出す設計に単純化して
いる(§1「実装上の注記」と同じ方針)。`atomic_bool found`を各ワーカーが64反復に1回チェックし
(メモリバリアの頻度を抑えつつ取りこぼしても正しさには影響しない)、見つけたワーカーが
`atomic_compare_exchange_strong`で1回だけ`result_nonce`を書き込む。CPUコア数取得に失敗した
場合(`num_cpus<1`)は従来のシングルスレッド探索にフォールバックする。
`tests/test_pow_engine.c`で複数の乱数payload・難易度に対し返り値のnonceが実際にtargetを
満たすことを検証(並行探索特有の競合バグを拾うため)、実daemonで実ネットワーク難易度
(nonce_trials_per_byte=1000)のmsg送信PoWが16コア環境で約0.35秒(従来のシングルスレッドでは
数秒〜十数秒)まで短縮されることを実機確認済み。

## 5. Object種別のワイヤーフォーマット

**実装済み(`src/core/message_builder.c`)。getpubkey/pubkey v2・v3・v4/msg/broadcast/ack(stealth level 0/1/2)
全て実装。`tests/test_message_builder.c`でmsg(構築→ECIES復号→全フィールド照合→署名検証)、getpubkey v3/v4
(tag計算含む)、pubkey v3(署名検証)を検証済み(2026-08-20)。エンコーディングはSIMPLE("Subject:...\nBody:...")
固定(§8、TRIVIAL/EXTENDEDは未対応)。

パース側(受信msgオブジェクトのトライアル復号)も`src/core/trial_decrypt.c`に実装済み。keyring内の
unlocked鍵全てでECIES復号を試行し、toRipe一致検証(なりすまし転送対策)・署名検証・SIMPLEデコード
(`\nBody:`分割、PyBitmessage `decodeSimple`と同一規則)まで行い、成功したら`messages_store.c`経由で
inboxへ保存する(msg_id=inventory hashで重複排除)。`tests/test_trial_decrypt.c`で
アドレス生成→keyring作成/unlock→message_builder→PoW(pow_engine.c)→trial_decrypt→inbox保存という
パイプライン全体をend-to-endで検証し、改竄object・重複投入への耐性も確認済み(2026-08-20)。
getpubkey/pubkey/broadcastのパース、ネットワーク層とのキュー結線(decrypt_worker_thread本体)は
引き続きTODO。

送信側も`src/core/send_pipeline.c`(`bm_send_pipeline_send_message`)で実装済み。keyringから
fromアドレスの鍵を引き、ack object(§5.5)とmsgオブジェクトを組み立て、PoWを計算して完成object
(nonce込み)を返し、`messages_store.c`のsentテーブルへ記録する。副産物として`common/base58.c`に
`bm_base58_decode`(整数ベース、PyBitmessage `decodeBase58`と同一方式)、`core/address.c`に
`bm_address_decode`(`addresses.py` `decodeAddress`準拠、v2/v3のゼロパディング復元・v4の
非マレアビリティ検証を含む)を実装した。`tests/test_send_pipeline.c`で送信→sentテーブル記録→
受信者keyringでのtrial_decrypt→ackPayloadとsent.ack_dataの一致までend-to-endで検証済み
(2026-08-20)。宛先pubkeyは呼び出し側が直接指定するか、`to_pub_encryption=NULL`で呼べば
`pubkey_cache`(§2.3)を`to_ripe`で検索して解決する(未登録なら送信失敗)。PoW難易度も
pubkey_cacheに宛先のnonce_trials_per_byte/payload_length_extra_bytesがあれば送信元既定値との
大きい方を採用する。`tests/test_send_pipeline.c`でNULL指定時のフォールバック(未登録で失敗
→upsert後は成功)まで検証済み(2026-08-21)。getpubkey要求による自動取得(未登録時に能動的に
取りに行く経路)は引き続きTODO。**

出典: PyBitmessage `src/protocol.py`, `src/class_singleWorker.py`, `src/helper_ackPayload.py`

### 5.0 共通ヘッダとobjectType定数

全objectペイロード(PoW nonce付与後、`inv`/`getdata`でやり取りされる単位)は:

```
nonce(8byte BE) || expiresTime(8byte BE) || objectType(4byte BE) || objectVersion(varint) || stream(varint) || <種別依存payload>
```

`objectType`定数(既存`libstudy`のコメント`getpubkey=1,...`は誤りなので注意、正しくは0始まり):

| 定数 | 値 |
|---|---|
| OBJECT_GETPUBKEY | 0 |
| OBJECT_PUBKEY | 1 |
| OBJECT_MSG | 2 |
| OBJECT_BROADCAST | 3 |
| OBJECT_ONIONPEER | 0x746f72 (初版スコープ外) |
| OBJECT_I2P | 0x493250 (初版スコープ外) |

inventory hash(`inv`/`getdata`で使うobject識別子) = `SHA512(SHA512(nonce込みの全payload))[0:32]`。

DoS対策の上限値(PyBitmessage `protocol.py`より): `inv`/`dinv`/`addr`等の複数要素メッセージは1メッセージあたり
**50000要素(`MAX_OBJECT_COUNT`)**まで、object本体は**2^18byte=256KiB(`MAX_OBJECT_PAYLOAD_SIZE`)**まで。
超過した場合は即座に接続を切断する実装がPyBitmessage側の挙動(`BMProtoExcessiveDataError`相当)。

### 5.1 getpubkey (type=0)

```
<共通ヘッダ> || (version<=3 ? ripe(20byte) : tag(32byte))
```

`tag`(version>=4) = `SHA512( encodeVarint(version) || encodeVarint(stream) || ripe )[32:64]`(後半32byte)。
署名なし、暗号化なし。

**getpubkey要求の自動化、実装済み(2026-08-23)。** 送信側(`core/api_server.c`の`h_sendMessage`)は
`toPubEncryptionHex`省略時に`pubkey_cache`未登録なら、上記フォーマットの`getpubkey`を
`bm_build_getpubkey`(既存)+PoW(ネットワーク既定値1000/1000)で組み立て`broadcast_queue`へ
投入する(実際のobject_pool.dbへの挿入・peer_registry経由のbroadcastは他のsendMessage生成object
と同じく`bm_object_sync_broadcast_thread`が行う)。同時に`identity.db`の新規テーブル
`pubkey_requests`(ripe/address_version/stream/requested_time)へpending登録し、10分以内の
再要求はbroadcastしない(`bm_pubkey_cache_has_recent_request`)。この呼び出し自体は
(その場でpubkeyを持っていないため)引き続き失敗を返す設計。

受信側(`infra/object_sync.c`の`handle_incoming_getpubkey`)は、要求されているripe(version<=3)/
tag(version>=4)がkeyringでunlock済みの自分のアドレスと一致するか`bm_keyring_find_by_ripe`/
新設の`bm_keyring_find_by_tag`で判定し、該当すれば自分のpubkeyオブジェクトを
`bm_build_pubkey_v2/v3/v4`で組み立ててPoW(自分のidentityのnonce_trials_per_byte/
payload_length_extra_bytes、TTLは28日固定)し、object_pool.dbへ登録して全peer(除外無し)へ
broadcastする。ロックされたままのアドレス宛の要求には応答できない(秘密鍵での署名が必要な
ため、v1はkeyringにロードされているアドレスのみ対応)。

pubkey v4の受信時キャッシュも同時に実装: 「誰宛の候補か」の判定に`pubkey_requests`の
pending行を候補として順に試す(`bm_parse_pubkey_v4`は候補ripeを1件ずつ受け取る設計のため)。
一致してキャッシュできたら該当のpending行を削除する(`bm_pubkey_cache_clear_request`)。

`tests/test_getpubkey_automation.c`で(1)実HTTPリクエスト経由のsendMessageがgetpubkeyを
broadcast_queueへ投入すること・pubkey_requestsへ登録すること・cooldown中は再投入しないこと、
(2)自分のアドレス宛getpubkeyへの自応答がobject_pool.dbに正しいpubkeyとして登録されること、
(3)pending登録した候補への実際のv4 pubkey受信でキャッシュ登録+pending解除、をend-to-endで
検証済み。実daemonでもtestnet接続中に未キャッシュ宛先へsendMessageを呼び、getpubkeyの
自動broadcastとpubkey_requestsへの登録を実機確認済み(2026-08-23)。

既知の制限: (a) 28日TTL×実ネットワーク難易度(1000/1000)でのpubkey自応答PoWは実測20秒超
かかる(16コア環境)。実際のBitmessageクライアントでもアドレス作成時のpubkey告知に同程度の
時間がかかることが知られており設計としては妥当だが、その間`network_epoll_thread`(単一スレッド)
がブロックされる点は既存のsend_pipeline PoW(APIスレッドをブロック)と同じ性質のトレードオフ。
(b) 同一宛先への短時間repeated getpubkeyに対する応答側スロットリングは無い。受信object全般の
PoW検証(§1、2026-08-23実装)により無償のPoW無しobjectでの負荷はかけられなくなったが、
相手が正規のPoWを払ってgetpubkeyを連投した場合の応答側スロットリングは依然として無い
(既知のギャップ)。(c) getpubkey要求自体の定期再送(初回broadcastが届かなかった場合の再試行)は無い。

### 5.2 pubkey (type=1)、addressVersion(=objectVersion)ごとに構造が異なる

**version 2**(平文、署名なし):
```
<共通ヘッダ> || bitfield(4byte) || signingPubkey(64byte) || encryptionPubkey(64byte)
```

**version 3**(平文、署名あり):
```
<共通ヘッダ> || bitfield(4byte) || signingPubkey(64byte) || encryptionPubkey(64byte)
  || encodeVarint(nonceTrialsPerByte) || encodeVarint(payloadLengthExtraBytes)
  || encodeVarint(sigLen) || signature
署名対象 = 上記全体(signature自身を除く)
```

**version 4**(タグ付き、本文はアドレス由来鍵でECIES暗号化=秘匿目的ではなく「アドレスを知らないと読めない」フィルタ用途):
```
平文部: <共通ヘッダ> || tag(32byte)
暗号化対象(dataToEncrypt) = bitfield(4byte) || signingPubkey(64byte) || encryptionPubkey(64byte)
  || encodeVarint(nonceTrialsPerByte) || encodeVarint(payloadLengthExtraBytes)
  || encodeVarint(sigLen) || signature
署名対象 = 平文部(tag込み) || dataToEncrypt(signature除く)
最終payload = 平文部 || ECIES_encrypt(dataToEncrypt, pubEncFromAddress)
暗号化鍵: privEnc = SHA512(encodeVarint(version)||encodeVarint(stream)||ripe)[0:32]、pubEnc = pointMul(privEnc)
```

`bitfield`は`protocol.getBitfield`相当: 4byte、bit30(先頭からの数え方に注意、`isBitSetWithinBitfield`参照)が
`BITFIELD_DOESACK`(値1、実装上はbit位置と値の対応を`protocol.py`の実装に厳密に合わせる必要あり)。
初版では「ack要求bitのON/OFF」のみ実装し、モバイル向けbitなど他のbitfield機能は未対応でよい(§8)。

### 5.3 msg (type=2、objectVersion=1固定)

```
平文部: <共通ヘッダ(objectVersion=1)> || ECIES_encrypt(payload, recipientPubEncryptionKey)

payload(暗号化される中身) =
    encodeVarint(fromAddressVersion) || encodeVarint(fromStream)
    || bitfield(4byte)
    || fromSigningPubkey(64byte) || fromEncryptionPubkey(64byte)
    || (fromAddressVersion>=3 ? encodeVarint(nonceTrialsPerByte)||encodeVarint(payloadLengthExtraBytes) : "")
    || toRipe(20byte)                       -- なりすまし転送対策。受信側は自分のripeと一致するか検証必須
    || encodeVarint(encoding)               -- 1=trivial(暗号化前と同一) 2=simple(件名+本文) 3=extended(未対応でよい)
    || encodeVarint(messageLen) || message  -- encoding依存のシリアライズ済みバイト列
    || encodeVarint(ackPayloadLen) || ackPayload  -- §5.5参照、0byteのこともある
    || encodeVarint(sigLen) || signature

署名対象 = <共通ヘッダ(平文, objectVersion固定で1)> || payload(signature除く全体)
```

受信側の処理: 自分が持つ全秘密鍵(ロック中のものは除く、§7)で`ECIES_decrypt`を試み、成功したら
`toRipe`が自アドレスのripeと一致するか検証 → 署名検証 → inboxへ格納、の順。

### 5.4 broadcast (type=3、addressVersion<=3ならobjectVersion=4、>=4ならobjectVersion=5)

```
平文部: <共通ヘッダ> || (objectVersion==5 ? tag(32byte) : "")
       || ECIES_encrypt(dataToEncrypt, pubEncFromAddress)

dataToEncrypt =
    encodeVarint(fromAddressVersion) || encodeVarint(fromStream)
    || bitfield(4byte)
    || fromSigningPubkey(64byte) || fromEncryptionPubkey(64byte)
    || (fromAddressVersion>=3 ? encodeVarint(nonceTrialsPerByte)||encodeVarint(payloadLengthExtraBytes) : "")
    || encodeVarint(encoding)
    || encodeVarint(messageLen) || message
    || encodeVarint(sigLen) || signature

署名対象 = 平文部(tagまで) || dataToEncrypt(signature除く)

暗号化鍵(pubkey v4と同じ「アドレスを知っていれば誰でも読める」パターン):
  objectVersion==4(fromAddressVersion<=3):
    privEnc = SHA512(encodeVarint(fromAddressVersion)||encodeVarint(fromStream)||fromRipe)[0:32]
  objectVersion==5(fromAddressVersion>=4):
    privEnc = SHA512(encodeVarint(fromAddressVersion)||encodeVarint(fromStream)||fromRipe)[0:32] (同一計算式)
    tag = 同ハッシュの[32:64]、平文部にtag併記(受信側が候補を絞るため)
```

購読者は既知の送信元アドレス全てについて`privEnc`を計算済みにしておき、`tag`(v5)またはtotal-scan(v4)で
候補を絞ってから復号を試みる。

**購読・復号、実装済み(2026-08-23)。** 新規`core/broadcast_decrypt.c/h`が`bm_build_broadcast`の
逆方向を実装(`trial_decrypt.c`のmsg復号ロジックとほぼ同じ構造)。`bm_trial_decrypt_broadcast`は
candidate(1件のアドレス、version/stream/ripe)を受け取り、objectVersion==5ならtagを先に比較して
不一致なら復号を試みずに即座に失敗を返す(§5.4の「安価な絞り込み」)。objectVersion==4は
tagが無いため常にECIES復号を試みる(total-scan)。署名検証、および復号できたpubkeyから
計算したripeがcandidateと一致するかの整合性チェックまで行う(pubkey v4の検証と同じ設計)。

購読先の管理は`messages.db`に新設した`subscriptions`テーブル(address/label/enabled)で行う。
CRUD(`bm_messages_store_add_subscription`/`_remove_subscription`/`_list_subscriptions`)を
`messages_store.c`に追加し、API(`addSubscription`/`removeSubscription`/`listSubscriptions`)と
CLI(`add-subscription`/`remove-subscription`/`list-subscriptions`)から操作できる。

受信側は`infra/object_sync.c`の`handle_incoming_broadcast`(`handle_object`のtype=broadcast分岐)で、
`subscriptions`を全件列挙し候補として順に`bm_trial_decrypt_broadcast_and_store`を試す(購読数は
通常少数なので線形探索で十分)。成功したらinboxへ保存する(`to_address=from_address`、broadcastには
単一の宛先が無いためPyBitmessageに倣った慣習、通常のmsgと区別できる)。

**broadcast送信(`sendBroadcast` API)も実装済み(2026-08-23)。** `send_pipeline.c`に
`bm_send_pipeline_send_broadcast`を追加(`bm_build_broadcast`を呼びPoWして完成objectを返す。
broadcastには単一の宛先もack機構も無いため、`sendMessage`と異なり`sent`テーブルへの記録・
再送の対象にはしない設計、送りっぱなし)。`api_server.c`の`sendBroadcast`
(`[fromAddress, subject, body, ttlSeconds?]`)が`sendMessage`と同じ`broadcast_queue`経由で
`object_pool.db`への挿入・ネットワークへのbroadcastを行う。CLIの`send-broadcast`コマンドも
追加。

`tests/test_broadcast.c`でobjectVersion=4/5両方の実broadcastオブジェクトを購読先から受信して
inboxへ保存されること、購読していない相手や購読解除後は復号されないこと、
`addSubscription`/`listSubscriptions`/`sendBroadcast`が実HTTPリクエスト経由で動作することを
end-to-endで検証済み。実daemonでも`add-subscription`/`list-subscriptions`/`remove-subscription`/
`send-broadcast`のCLI連携を確認済み。

### 5.5 ack payload(msg内に埋め込まれる自己完結オブジェクト)

送信側は`sent`レコード作成時に`ackobject`を事前生成し、`ackdata`として保持する
(=送信側が受信側からの「確認」を検知するための照合キー)。**stealthLevelにより3種類の形がある**
(`helper_ackPayload.genAckPayload`, §8-6で3段階とも実装・デフォルトはlevel 1に決定):

| level | ackobject | 特徴 |
|---|---|---|
| 0 | `type=2(msg,4byte)\|\|encodeVarint(1)\|\|encodeVarint(stream)\|\|random(32byte)` | 最小コスト。ただし本物のmsg(最低234byte程度)よりずっと小さく、**サイズだけでack用ダミーだとネットワーク観測者に判別されてしまう**(復号不要の弱いトラフィック解析手がかり) |
| 1(既定) | `type=0(getpubkey,4byte)\|\|encodeVarint(4)\|\|encodeVarint(stream)\|\|random(32byte)` | getpubkeyオブジェクト(§5.1のversion>=4形式、tagの代わりにランダム32byte)に偽装。本物のgetpubkeyと構造上区別できず、PoWコストもgetpubkey相当で軽い |
| 2 | `dummyMsg = random(234〜800byteの範囲でランダム長)`を`ECIES_encrypt(dummyMsg, ランダムに生成した使い捨て公開鍵)`で暗号化したものが中身。`type=2(msg)\|\|encodeVarint(1)\|\|encodeVarint(stream)\|\|暗号文` | 本物のmsgと完全に同形。最も秘匿性が高いがpayload長がランダムに大きくなる分PoWコストも上がる |

`ackobject`はこの後§5.0共通ヘッダ(nonce/expiresTime抜き)に続けて`type/version/stream`を含む形でそのまま
`payload`として使われる(ackobject自体に既にtype/version/streamが埋め込まれているため、共通ヘッダの
objectType/version/stream相当部分と重複させず、そのまま連結する実装になっている点に注意)。

msg送信時、受信側の`bitfield`が`BITFIELD_DOESACK`を要求していれば、
`fullAckPayload = CreatePacket("object", <共通ヘッダ(time+ackobjectそのまま)> || nonce付与後payload)`
を計算し、これを**msgのpayload内に(§5.3の`ackPayload`として)平文のまま**埋め込む。
`CreatePacket`は既存`bm_protocol.c`の`message`ヘッダ(magic+command+length+checksum)と同一フォーマット。

受信側はmsgを復号できたら、埋め込まれていた`fullAckPayload`を**そのままP2Pソケットに書き込むだけ**で
確認応答が完了する(中身を再構築する必要がない = 受信側は追加のPoWを一切行わずに済む設計)。
送信側は自分が生成した`ackdata`と同じ`inventoryHash`を持つ`object`メッセージがネットワークに現れるのを
監視し、見つかったら送達確認とする。

**実装済み(2026-08-22)。** `send_pipeline.c`の`generate_full_ack`が上記`fullAckPayload`生成
(PoW+`CreatePacket`包み)を担い、`bm_build_ack_object`(ackobject本体のみ)と対になる。
`sent.ack_data`にはPoW済みnonce込みobject本体(P2Pヘッダ無し、`inventoryHash`計算用)を、
msgへの埋め込みには`CreatePacket`で包んだ完成P2Pパケット(受信側がそのまま書き込める形)を
それぞれ格納する(両者は別物である点に注意、`bm_build_msg`のドキュメントコメント参照)。
受信側の「そのまま書き込む」に対応する実装は`trial_decrypt.c`の`out_ack_payload`出力→
`object_sync.c`の`validate_and_store_ack`(§1参照、object header・PoW・期限を検証してから
自分のobject_pool.dbへ挿入し、`peer_registry`経由で全peerへinv broadcastする)。送達確認
(`ackreceived`遷移)は`messages_store.c`の`bm_messages_store_try_mark_ack_received`
(§1のobject_sync_thread参照)。

**再送(resend)ロジック、実装済み(2026-08-23)。** `sent`テーブルの主キーを`ack_data`から
`msg_id`(32byteランダムID、送信試行を安定して指す。再送しても不変)へ変更し、`ack_data`/
`status`/`resend_count`/`next_resend_time`は再送のたびに上書きされるようにした
(`bm_messages_store_insert_sent`は`msg_id`でUPSERTし、UPDATE時は`resend_count`をDB側で
`+1`する)。`bm_send_pipeline_send_message`は`reuse_msg_id`(NULL=新規送信、非NULL=既存行を
再利用)と`next_resend_time`を新たに受け取る。`object_sync.c`の`bm_object_sync_check_resends`
(GCと同様300秒間引きで`bm_object_sync_dispatch`から呼ばれる、`bm_object_sync_gc`と同じ手動
呼び出しも可)が、ack未着かつ`next_resend_time`経過・`resend_count`が
`BM_RESEND_MAX_ATTEMPTS`(既定5回)未満の行を`bm_messages_store_list_resend_candidates`で
列挙し、同じ`msg_id`で`bm_send_pipeline_send_message`を呼び直す(`to_pub_encryption=NULL`固定、
=pubkey_cache参照。**直接pubkeyを渡して送った場合はcacheに乗らないため自動再送できない**、
既知の制限)。初回間隔`BM_RESEND_INITIAL_INTERVAL_SECONDS`(既定4時間)から2^resend_count倍で
間隔が伸びていく。再送で生成された新しいobjectはobject_pool.dbへ挿入しpeer_registryで
全peer(除外無し)へbroadcastする。`tests/test_resend.c`で、再送によりmsg_idが不変のまま
ack_data/resend_count/next_resend_timeが更新されること、上限到達・ackreceived済みの行が
対象から外れること、broadcastされること(inv)をend-to-endで検証済み。実daemonでも
sendMessage→sentテーブルへの正しい記録までは実機確認したが、5分間引きの実発火タイミングは
testnetの実イベント到達間隔と噛み合わず今回は個別確認できていない(GCと同じ間引き方式で
機構自体は共通のため、信頼性は同等と判断)。

## 6. API層(フロント⇄コア暗号層)方針決定

**実装済み(`src/core/api_server.c`)。自前JSON-RPC 2.0(`src/common/json.c`、外部JSONライブラリ非依存の
最小実装)+HTTP/1.1(自前、ブロッキングI/O、1接続1リクエスト)。HTTP Basic認証、`§6.2`の
`unlockAddress`/`lockAddress`/`lockAllAddresses`/`deleteAddress`/`listAddresses`/
`createDeterministicAddress`を実装。`apiusername`/`apipassword`は設定ファイル未実装のため
起動毎にランダム生成し標準エラー出力へ表示する(`main.c`)。`tests/test_api_server.c`で
実ソケット越しのHTTPリクエストにより認証拒否・全メソッドの疎通・エラーハンドリングを検証済み
(2026-08-20)。`sendMessage`(send_pipeline.c連携)・`getInboxMessages`(messages_store.c連携)も
実装済み(2026-08-21)。`sendMessage`は`[fromAddress, toAddress, toPubEncryptionHex, subject, body,
ttlSeconds?, ackStealthLevel?]`を取り、`toPubEncryptionHex`は130桁hexまたは`null`/空文字が可能で、
`null`の場合は`pubkey_cache`(§2.3)から解決する。応答は`{objectLength, inventoryHash}`(完成object
本体はAPI経由では返さない設計)。`cachePubkey`(`[address, signingPubkeyHex, encryptionPubkeyHex]`)を
新設し、`pubkey_cache`への手動登録に使う。`getInboxMessages`は`[folder?]`でinbox一覧を返す。
`tests/test_api_server.c`で`cachePubkey`+`sendMessage(toPubEncryptionHex=null)`の一連の流れを含め、
実HTTPリクエストで検証済み(2026-08-21)。CLI(`bitmessage-cli`)からも`cache-pubkey`コマンドと
`send-message ... -`(cache利用の合図)で同じ経路を呼べる。`tests/test_cli_integration.sh`で
引数検証・cache未登録時のエラー伝播まで確認済み(2026-08-21)。

**graceful shutdown実装済み(2026-08-23)。** `bm_api_server_serve_forever`は`accept()`を直接
ブロッキングで呼ばず、`poll()`に1秒のタイムアウトを与えて`*stop_flag`を定期的に再チェックする
方式に変更した(`peer_connector_thread`と同じポーリング設計、§1・§11参照)。`stop_flag`が
非0になれば次のタイムアウト(最大1秒)で抜ける。`main.c`ではこのスレッドを
`struct bm_api_server_thread_args`(config+stop_flagのポインタ、mallocしてスレッド側でfree)
経由で起動し、以前は`pthread_detach`していたが今は`pthread_join`できる。
`tests/test_api_server.c`でstop_flagを立ててから3秒以内に`pthread_join`が返ることを検証
(実測1.005秒、poll()のタイムアウト分そのまま)。実daemonでもBM_NO_CONNECT=1構成で
SIGINT送信から約1.04秒でプロセス全体が終了することを確認済み。

出典: PyBitmessage `src/api.py`(モジュールdocstring, `singleAPI.run`, `CommandHandler`, `command`デコレータ)

### 6.0 PyBitmessageの実際の設計(判明した事実)

PyBitmessageは「メソッドディスパッチテーブル」と「トランスポート」を分離している。`BMRPCDispatcher`配下に
`@command('methodName')`で登録された**単一のハンドラ辞書**があり、それを`apivariant`設定値(`xml`|`json`|`legacy`)に
応じて`SimpleXMLRPCServer`(stdlib)または`jsonrpclib.SimpleJSONRPCServer`のどちらかに載せ替えているだけ
(`jsonrpclib`が無ければXML-RPCにフォールバック)。docstringには**「`apivariant=xml`が後方互換のための現行
デフォルトだが、`json`が推奨」**と明記されている(api.py:28-29)。`legacy`は結果をJSON文字列にダンプする
古いエンコーディング互換モードで、トランスポートとは別軸。

その他の設定: `apienabled`(true/false)、`apiinterface`(既定`127.0.0.1`)、`apiport`(既定8442、
使用中なら32767〜65535のランダムポートに自動フォールバックし、実際に使ったポートを設定へ書き戻す)、
`apiusername`/`apipassword`(HTTP Basic認証、`http://user:pass@host:port/`の形でURIに埋め込む)、
`apinotifypath`(`startingUp`/`newMessage`等の内部イベント発生時に外部コマンドを実行する簡易webhook)。

### 6.1 本実装での決定

PyBitmessage自身が推奨する方向性(JSON-RPC)にそのまま合わせ、**トランスポートは自前実装のJSON-RPC 2.0の
みをv1スコープとする**(xmlrpc-c依存は持たない。既存`bm_api.h`のxmlrpc-cベースコードは不採用)。ただし
PyBitmessage同様「ハンドラ辞書とトランスポートを分離した設計」を踏襲し、`struct api_method { const char *name;
api_handler_fn handler; }`の配列をコア層が持ち、HTTPレイヤーとJSONパース/シリアライズだけをトランスポート側に
閉じ込める。将来XML-RPCを追加したくなった場合も、この配列を差し替えずに同じハンドラ群を別トランスポートに
載せられる構造にしておく(が、v1では作らない)。

- bind: `apiinterface:apiport`相当の設定項目をそのまま踏襲(既定`127.0.0.1:8442`)、ポート衝突時のランダム
  フォールバック+設定書き戻しロジックもそのまま採用
- 認証: HTTP Basic認証を踏襲(`apiusername`/`apipassword`、比較は定数時間で行う)
- `apinotifypath`: 踏襲する場合は`execve`系(argv配列)で起動し、シェル文字列経由(`system()`/`popen()`)には
  絶対にしない(PyBitmessage本体はPython `subprocess.call`でargvリストのまま渡しておりコマンドインジェクション
  経路はないが、C実装でうっかり`system()`を使うと同じ安全性を失うので明記しておく)
- `legacy`エンコーディング互換は対応しない(スコープ外)
- §7で設計した鍵ライフサイクル系メソッド(`unlockAddress`等)はPyBitmessage標準APIに存在しない本実装独自の
  追加なので、同じハンドラ辞書に新規登録する

### 6.2 §7の鍵ライフサイクル系メソッド

| メソッド | 引数 | 効果 |
|---|---|---|
| `unlockAddress` | address, passphrase | KEK導出→秘密鍵復号→keyringに追加。成功後、そのripe宛の未処理objectを再デコードキューへ |
| `lockAddress` | address | keyringから当該鍵をゼロ埋めして除去(ディスク上のラップ済み鍵は保持) |
| `lockAllAddresses` | (なし) | 全unlocked鍵を一括ゼロ埋め(アプリ終了時・スクリーンロック連動などを想定) |
| `deleteAddress` | address | lock相当の消去 → identity.dbから当該行を完全削除(復元不可、確認はフロント側の責務) |
| `listAddresses` | (なし) | identity.db一覧 + 各アドレスの`unlocked`状態(bool)を返す |
| `createDeterministicAddress` | passphrase, addressVersion, stream, ripeNullBytes | §3.3のnonce探索でアドレス生成、KEK(新規passphrase)でラップして保存 |
| `importAddress` | signingWIF, encryptionWIF, storePassphrase | 既存鍵のインポート、保存時に必ずラップ(平文保存は許容しない) |

## 7. 鍵ライフサイクル管理設計(§8-1、ユーザー要望による独自拡張)

**実装済み(`src/core/keyring.c`, `src/core/identity_store.c`)。scrypt(N=2^15,r=8,p=1)でKEK導出、
AES-256-GCM(AAD=address)でラップ。`tests/test_keyring.c`でcreate→誤passphrase拒否→unlock→
秘密鍵一致確認→lock→再unlock→delete→完全削除の一連を検証済み(2026-08-20)。**

PyBitmessageは`keys.dat`に秘密鍵を平文保存し、`enabled`は「トライアル復号に使うか」のUIフラグに過ぎず、
有効なアドレスの鍵は起動直後から常時プロセスメモリ上にある。本実装では**起動時は全アドレスがロック状態**で、
明示的に`unlockAddress`されるまで秘密鍵の平文はプロセスメモリに存在しない設計にする。

### 7.1 保存時の鍵ラッピング(identity.db)

```
KEK = scrypt(passphrase, salt=identities.kdf_salt(16byte), N,r,p from kdf_params)   -- 32byte
wrapped = AES-256-GCM-Encrypt(KEK, nonce=random12byte, AAD=address文字列, plaintext=priv_key(32byte))
        = nonce(12byte) || ciphertext(32byte) || tag(16byte)   -- 計60byte
```

- KDFはscrypt(またはargon2id、`kdf_algo`列で切替可能にしておく)。反復コストは端末性能に応じて可変にしたいので
  `kdf_params`をJSON文字列で保存し、生成時のパラメータをそのまま記録する(検証時に再現するため)
- AAD(Associated Data)に`address`文字列を入れることで、ある行の`wrapped_priv_signing_key`を
  別の行に貼り替えるような改竄を認証タグ検証で検出できる
- signingKeyとencryptionKeyは別々にラップする(別nonce)。KEK自体はディスクに保存しない

### 7.2 In-memoryキーリング

```c
struct unlocked_identity {
    char address[40];
    unsigned char ripe[20];
    unsigned char priv_signing[32];
    unsigned char priv_encryption[32];
    unsigned char pub_signing[64];
    unsigned char pub_encryption[64];
    time_t unlocked_at;
};
```

プロセス内に1つの`keyring`(ripeをキーにしたハッシュマップ、`pthread_rwlock_t`で保護)を持ち、
`decrypt_worker_thread`(トライアル復号)・`send_pipeline_thread`(送信時の署名/暗号化)・
`api_server_thread`(unlock/lock/delete操作)の3者が参照・更新する。

- `unlockAddress`: identity.db行取得 → KEK導出 → 両鍵をAES-GCM復号(タグ検証失敗=passphrase誤り、
  エラーを返すだけで既存keyringには触らない) → `mlock(2)`でスワップアウト禁止にしてからkeyringへ追加 →
  **`object_pool.db`から該当ripe宛の`processed=0`な`msg`オブジェクトを`decrypt_request_queue`へ再投入**
  (ロック中に受信していたメッセージは`object_pool.db`にそのまま残っているため、unlock後に取りこぼしなく拾える。
  これはインフラ層とコア層でDBを分離した設計の副産物として自然に成立する)
- `lockAddress`/`lockAllAddresses`: `OPENSSL_cleanse`(またはPOSIX `explicit_bzero`)で該当エントリを
  明示的にゼロ化 → `munlock` → keyringから除去。identity.db側のラップ済みデータは変更しない
- `deleteAddress`: lock相当の消去を行った上で、identity.dbから該当行を`DELETE`(ラップ済み鍵ごと消滅し復元不可)。
  「本当に消してよいか」の確認はフロント層の責務とし、コア層はconfirmationパラメータを持たない
- `enabled`フラグとの関係: 実際にトライアル復号対象になるのは**`enabled=1` かつ `keyringにunlock済み`**の
  両方を満たすripeのみ

### 7.3 送信パイプラインとの関係

`send_pipeline_thread`は送信元アドレスがkeyringにunlockedでなければ、`send_request_queue`から取り出した
リクエストをエラー(`E_ADDRESS_LOCKED`のようなコード)としてAPI呼び出し元に返す。送信要求自体は`messages.db`の
`sent`テーブルに`status='addresslocked'`のような状態で保存しておき、後でunlockされたら自動的に再試行できるように
しておくと、PyBitmessageの「keyが見つからないまま延々retryする」挙動より扱いやすい(要検討、初版では
単純にエラー即返却でも良い)。

## 8. PyBitmessageとの差分・独自追加要件(随時追記)

グランドデザイン本体との混同を避けるため、PyBitmessage標準仕様から意図的に外れる/追加する決定はここに集約する。

| # | 項目 | PyBitmessageでの扱い | 本実装での決定 | 決定日 / 状態 |
|---|---|---|---|---|
| 8-1 | 秘密鍵の保存形式 | `keys.dat`に平文保存、`enabled`はUI表示フラグのみ | パスフレーズ由来KEKでAES-256-GCMラップ保存。明示的な`unlock`/`lock`/`delete`API(§7) | 2026-08-20 確定 |
| 8-2 | 署名検証アルゴリズム | SHA1署名(旧クライアント互換、`verify()`はSHA1→SHA256の順で試行)とSHA256署名の両方を検証。SHA256はサポート追加2015-03-27(`6ebf8666`)、デフォルト化2019-11-18(`8684d647`) | **SHA256のみ**を送受信双方で実装。SHA1署名はデフォルト化から7年・サポート追加から11年経過しており該当ノードは実質的に存在しないと判断し、互換は切り捨てる | 2026-08-20 確定 |
| 8-3 | PoW計算方式 | CPU(マルチプロセス)/C共有ライブラリ/OpenCL(GPU)の3方式 | CPUマルチスレッドのみ実装。GPU/OpenCLは初版スコープ外 | 仮決定 |
| 8-4 | onionpeer/I2P object | Tor onion peer共有、I2P対応(objectType 0x746f72等) | 初版スコープ外。TCP直結のみ対応 | 仮決定 |
| 8-5 | API層のトランスポート | `apivariant`設定でXML-RPC/JSON-RPC/legacyを切替可能(xmlは後方互換の既定値、json推奨) | 自前JSON-RPC 2.0のみをv1実装。ハンドラ辞書とトランスポートを分離した設計は踏襲し、XML-RPCは将来追加可能な形にしておく(§6) | 2026-08-20 決定 |
| 8-6 | ackdataのstealthLevel | 0/1/2の3段階(§5.5)。実際はGUI設定項目が存在せず`ackstealthlevel`未設定時は`safeGetInt`のデフォルト0となるため、実ネットワーク上のackはほぼ全てlevel 0 | level0はサイズ(32byte)が本物のmsg(最低234byte程度)と乖離しダミーだと判別されてしまう漏洩がある一方、level1/2は新規ワイヤーフォーマット不要で実装コストが低いため**3段階ともv1で実装**。デフォルトはlevel 1(getpubkey偽装、判別困難かつPoWコストも軽い)、config項目で変更可能 | 2026-08-20 確定 |
| 8-7 | Dandelion++(stem/fluff伝播) | 実装済み(Wikiのプロトコル仕様書には**未文書化**、`src/network/dandelion.py`ほか) | v1は常時fluff相当(stem機能なし、`NODE_DANDELION`ビットも立てない)。§9でインターフェースの位置だけ確保し、実装は初版完成後に着手 | 2026-08-20 決定 |
| 8-8 | メッセージエンコーディング | TRIVIAL(1)/SIMPLE(2)/EXTENDED(3、msgpack+zlib圧縮)の3種 | v1はSIMPLE("Subject:...\nBody:...")のみ実装。TRIVIALは低コストで追加可能、EXTENDEDはmsgpack依存が増えるため見送り | 2026-08-20 決定 |
| 8-9 | testnet対応 | `bootstrapN.testnet.bitmessage.org`、magic bytes `0xFB110907`(mainnetは`0xE9BEB4D9`)、専用シードノード2件 | 実装済み。`bm_protocol_set_testnet()`でmagic bytes切替、`BM_TESTNET=1`環境変数で起動時選択(設定ファイル未実装のため)。実testnetノードとのハンドシェイクを確認済み | 2026-08-21 決定 |
| 8-10 | inbound接続(サーバーソケット待受) | 通常のP2Pノードとして必須機能 | 開発者宅環境のISP事情(CGNAT等)により当面listen不可能。Tor hidden service実装まで見送り、v1はoutbound接続専用 | 2026-08-21 決定(ユーザー環境起因) |

## 9. Dandelion++ — インターフェース位置の確保(実装は初版完成後)

出典: PyBitmessage `src/network/dandelion.py`, `src/network/invthread.py`, `src/network/bmproto.py`, `src/protocol.py`

### 9.1 概要

新規/受信objectをまず**stemフェーズ**(単一の"子"ピア1本だけへ`dinv`コマンドで中継、これをピアが連鎖的に繰り返す
ランダムウォーク)に置き、一定時間(ポアソン分布、平均30秒+固定10秒)経過または経路断で**fluffフェーズ**
(通常の全接続ピアへの`inv`フラッド)に強制遷移させることで、objectの発信元をトラフィック解析から
分かりにくくする仕組み。Bitcoin向けに提案されたDandelion++をBitmessageに移植したもの。

- `NODE_DANDELION = 8`(servicesビット、`bm_protocol.h`に定数として追加予定)で対応ピアを識別
- `dinv`コマンドは`inv`とワイヤーフォーマット完全に同一(`encodeVarint(count) || hash(32byte)*count`)。
  意味論だけが異なる(「これはまだstem中なので周りに撒くな」という合図)
- outbound接続がないノードでは機能しない(inbound onlyなら自動的に無効)ため、
  peer_connector_threadがoutbound接続を維持している前提が必要(既存§1設計で満たされている)

### 9.2 v1で確保するインターフェース(実装しない、置き場所だけ決める)

- **プロトコル定数**: `dinv`コマンド名と`NODE_DANDELION = 8`を`bm_protocol.h`に定義しておく
- **受信側のv1挙動**: `dinv`を受信したら、stem状態を一切保持せず**`inv`受信と全く同じ処理経路**に流す
  (中身が同一フォーマットなので安全にできる)。これによりDandelion対応ピアと接続してもプロトコル違反にはならない
- **送信側のv1挙動**: version messageの`services`に`NODE_DANDELION`を立てない(=stem対応ピアとして名乗らない)。
  objectは常にfluff(`object_sync_thread`が全接続ピアへ`inv`)のみで伝播する
- **将来の差し込み点として今のうちに切り出しておく関数シグネチャ**:
  ```c
  enum propagation_mode { PROPAGATE_FLUFF, PROPAGATE_STEM, PROPAGATE_SKIP };
  enum propagation_mode decide_propagation(const unsigned char object_hash[32],
                                            struct fd_data *target_connection);
  ```
  `object_sync_thread`のinv送信判断は必ずこの関数を経由させる。v1の実装は常に`PROPAGATE_FLUFF`を返すだけの
  ダミーにしておき、将来Dandelion本実装時にこの関数の中身だけ差し替えれば済むようにする
- **将来必要になる状態(v1では作らない)**: infra層にプロセス内シングルトンとして
  `stem`(子ピア候補リスト, 最大2)・`nodeMap`(親→子の静的マッピング, 10分毎に再シャッフル)・
  `hashMap`(object hash → {子ピア, ポアソンタイムアウト})を持つ`struct dandelion_state`。
  DB永続化は不要(PyBitmessage同様プロセス内メモリのみで再起動時にリセットされる仕様)
- **将来必要になる周期処理**: 10分毎の`nodeMap`再シャッフルと、ポアソンタイムアウトによるstem→fluff強制遷移の
  チェック(PyBitmessageは`InvThread`が1秒ループの中で毎回`dandelion_ins.expire()`を呼んでいる)。
  既存§1の`peer_connector_thread`(定期実行スレッド)に相乗りさせるか、専用の`dandelion_thread`を
  新設するかは実装着手時に判断する

## 10. ディレクトリ構成・ビルド方針

§1のスレッド一覧(フロント/コア暗号/インフラ/計算の4層)にモジュールを対応させ、`src/`配下を層ごとの
サブディレクトリに分ける。`.h`と`.c`は同一ディレクトリに同居させる(libstudyの`include/`+`src/`分離は
今回は採用しない。インクルードパスの二重管理を避けるため)。

```
bitmessage/
  CMakeLists.txt              -- OpenSSL/SQLite3/Threadsをfind_package、サブディレクトリを束ねる
  DESIGN.md
  src/
    common/                   -- どの層からも参照される純粋ユーティリティ
      queue.c/.h                 -- 層間キュー(§1.2)。libstudy bm_queue.cを移植
      varint.c/.h                 -- varint/varstrのエンコード/デコード(§5.0)。bm_sonota.cから分離
      base58.c/.h                  -- Base58エンコード。libstudy changebase.cのbase58encodeを移植
      hash.c/.h                     -- SHA512/RIPEMD160/HMAC-SHA256のラッパー(§3.4)
      db_common.c/.h                 -- SQLite初期化共通処理(Google概要案のinit_database相当)
    infra/                    -- インフラ層(§1のnetwork_epoll_thread等)
      network.c/.h                -- epoll実装、fd_data。bm_network.cを移植・スタブを実装で埋める
      protocol.c/.h                 -- message/version/addr/invのparse/encode。bm_protocol.cを移植
      object.c/.h                    -- object種別の検証・伝播判断(§5, §9のdecide_propagation)
      peer_manager.c/.h               -- peers.db操作(bm_peer_manager.hの中身を新規実装)
      object_store.c/.h                -- object_pool.db操作(bm_storage.hの中身を新規実装)
    core/                     -- コア・暗号層
      crypto.c/.h                 -- ECIES/ECDSA(§3)。bm_crypto.c(空)を新規実装
      keyring.c/.h                  -- 鍵ライフサイクル管理(§7)
      address.c/.h                    -- アドレスエンコード/デコード・鍵導出。bm_sonota.cから移植
      identity_store.c/.h              -- identity.db操作
      messages_store.c/.h               -- messages.db操作(inbox/sent/addressbook)
      trial_decrypt.c/.h                 -- decrypt_worker_thread
      message_builder.c/.h                -- msg/broadcast/pubkey/getpubkeyの組み立て(§5.1〜5.5)
      send_pipeline.c/.h                   -- send_pipeline_thread
      api_server.c/.h                       -- JSON-RPCサーバー(§6)
    pow/                      -- 計算層
      pow_engine.c/.h              -- target計算・trial value・ワーカースレッドプール(§4)
    cli/                      -- フロント層(CLIクライアント、テスト・スクリプト用途)
      main.c                       -- サブコマンド(list-addresses/create-address/unlock/lock/
                                        lock-all/delete)、環境変数BM_API_*でdaemonへ接続
      http_client.c/.h              -- api_server.c宛ての最小HTTP/1.1クライアント
    main.c                    -- DB初期化、鍵ロード、全スレッド起動、シグナルハンドリング
  tests/
  .gitignore
```

CLIクライアント(`bitmessage-cli`)は「デーモン/UIクライアント分離」というグランドデザイン方針に沿い、
まずは自動テスト・スクリプトから叩きやすい一発コマンド型として用意した(TUIはncurses等の依存や
自動テストとの相性で後回し、2026-08-20の会話で決定)。`api_server.c`と同じJSON-RPC 2.0 APIを
そのまま経由するので、将来的なGUI/TUIクライアントもここで確立したプロトコルをそのまま使える。

- ビルドシステムはlibstudy同様CMake。ビルドディレクトリ名も揃えて`build-<Debug|Release|...>/`とする
- 依存: OpenSSL(EVP/EC/RIPEMD)、SQLite3、pthread(Threads)。libstudyが依存しているCURL/GnuTLS/Gettext/xmlrpc-c/
  libuuidはこのプロジェクトでは不要(API層は自前JSON-RPC、多言語対応は初版スコープ外)
- v1では**実装しない層(pow/message_builder/send_pipeline/api_server等の中身、object.cのDandelion分岐等)は
  コンパイルは通るがno-op/TODOのスタブとして先に骨組みだけ作る**方針とする。まずスレッド起動〜終了までの
  骨格を通してから、§1のキュー定義に沿って各モジュールを実装で埋めていく

## 11. 次にやること(引き継ぎメモ、随時更新)

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

Stage 2(Tor ControlPort経由のhidden service自動作成)は未着手。PyBitmessageの
`proxyconfig_stem.py`(stemライブラリ経由でControlPortに接続し`ADD_ONION`する)と
同様のアプローチを想定しており、初回は`NEW:BEST`で鍵生成、以後は生成したed25519鍵を
config.db等へ永続化して`ADD_ONION`に渡すことで同じonionアドレスを再利用する設計とする
予定(ユーザーとの合意事項)。

**注記:** 開発者はこの実装の動作確認のため、自身の環境で実際のTor hidden service
(静的torrc設定)を用意して`127.0.0.1:8444`へフォワーディングしているが、その
onionアドレス自体はユーザーの明示的な指示によりこのファイル・コミットメッセージ・
コード中を含め、一切の公開ドキュメントに記載しない。

### v1.1以降のbacklog

2026-08-21に洗い出した項目(優先順位付けした6項目・peers.dbクリーンアップ・
手動peer追加/observed_nodesリスト)は全て完了した。残るのは以下の通り。

- inbound接続はStage 1(汎用TCP listen/accept、上記参照)まで完了。Stage 2
  (Tor ControlPort自動化・onion鍵永続化)は引き続き未着手。
- Dandelion++のstem機能、GPU/OpenCL PoWは§8/§9で明示的にv1スコープ外と決めた項目のため、
  今回のv1完成の対象外(引き続き見送り)。

出典・詳細はこのファイル内の各章の実装状況ノートを参照(pubkey_cacheは§2.3、send_pipeline/ackは
§5末尾、object_sync_threadは§1、api_serverは§6.1末尾)。
