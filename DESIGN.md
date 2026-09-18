# Bitmessage C言語フルスクラッチ 設計文書

方針: 個人studyリポジトリ(libstudy)の `bm_*` 資産を移植・拡張ベースとして採用。
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
方がシンプルで、v1では並列度より実装の見通しを優先した)。`pow_worker_thread`の非同期化は
§11項目38のTODO。

**上記の`pow_worker_thread × NumCPU`という記述は誤りなので、実装時に踏襲しないこと
(2026-09-18追記)**。`bm_pow_run`が既に内部で`sysconf(_SC_NPROCESSORS_ONLN)`本へ探索空間を
stride分割しているため、ワーカースレッドをNumCPU本立てると`NumCPU × NumCPU`スレッドに
なり過剰購読する。**ワーカーは1本**にしてジョブを直列に処理するのが正しい(1ジョブの内部で
全コアを使い切るので、ジョブを並列化しても総スループットは上がらない)。詳細は§11項目38。

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
upsert/lookupを`tests/test_pubkey_cache.c`で検証済み(2026-08-21)。手動登録(`cachePubkey` API/
`cache-pubkey` CLI)に加え、実ネットワークから受信した`pubkey`オブジェクトをこのパーサへ流し込み
自動でDB登録する配線(`infra/object_sync.c`)も実装済み(§5.0「getpubkey要求の自動化」参照)。

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

**2026-08-29追記: version2/3アドレスのdecode時ゼロパディングを2byte固定から可変長に一般化**。
5143件規模の実keys.dat(ユーザーの実データ)を`importAddress`経由でインポートする実地検証中に、
`bm_address_decode`(旧実装、`ripe_data_len`が18/19/20の3ケースのみ許容)で3件が
"invalid address"/"WIF keys do not match"エラーになった。原因を調査した結果、そのうち2件
(チェックサムは正常、実在の本物のアドレス)は**version=3・ripe_data_len=16(4byte分のゼロを
圧縮)という非正規のアドレス**だった。上記encodeAddressの規則が示す通り、本家PyBitmessage・
このプロジェクトのbm_address_encodeは共にversion2/3で先頭ゼロを最大2byteまでしか圧縮しない
仕様であり、本家`decodeAddress`(`addresses.py`)も`len(embeddedRipeData) < 18`を明示的に
`'ripetooshort'`エラーにしている。つまりこれは本家の標準的な生成経路(GUIの「もっと短い
アドレス」オプションはnull_bytes=2までしか選べない)では作られないはずのアドレスだが、
ユーザーが実験的に(`class_addressGenerator.py`を直接操作する等で)4byte分のゼロを持つripeを
探索して意図的に生成していたことが判明した(確率1/2^32、探索に相当な計算時間を要したはず)。

実害のある実在アドレスのため、生成側(`bm_address_encode`)は本家仕様のまま変更せず、
decode側だけ寛容にして救済する方針にした(ユーザーと合意)。`bm_address_decode`の
version2/3分岐を、18/19/20の3ケース限定から「`ripe_data_len`が0〜20byteの任意の長さでも
先頭に`(20-ripe_data_len)`byte分のゼロを補って復元する」という一般化された処理に変更した
(v4の「先頭ゼロを全て除去/復元」ロジックと同じ考え方)。`tests/test_address_vectors.c`に、
varint+ripe(16byte)+checksumを手動で組み立てて非正規アドレスを合成し、正しくdecodeできる
ことを確認するテストを追加した。

なお、この検証で同時に見つかった別の1件("BM-GtE4KjZbHfpvD3pRVpzKFJwbeGPdJWNZ"、version3・
ripe_data_len=18=正規範囲内)は、上記の4byte圧縮版と全く同じripeにdecodeされるにも関わらず、
対応するWIF鍵から計算した公開鍵のripeとは一致しなかった。ユーザーへの確認の結果、これは
同じripeに対してversion4・正規圧縮version3・非正規圧縮version3の3種類の表現を実験的に
作っていた際の、既に使われていない重複エントリと判明した(「今回に限って」無視することで
合意、2026-08-29)。実害(到達不能になるアドレス)は無い(version4・非正規圧縮version3の
2つは正常にインポートできている)。

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
取りに行く経路)も実装済み(§5.0「getpubkey要求の自動化」参照、2026-08-23)。**

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

**2026-09-15: HTTPトランスポートとJSONを自前実装からlibmicrohttpd + cJSONへ移行した(§6.3)。
以下の「自前HTTP/1.1」「自前JSON」に関する記述は移行前の状態を示す歴史的な記録として残してある。**

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

**2026-09-15: 以下の「トランスポートは自前実装」の決定はlibmicrohttpd + cJSONへの移行により
撤回した(経緯と根拠は§6.3)。「ハンドラ辞書とトランスポートを分離した設計」の方は移行後も
維持しており、`METHODS[]`は手付かずのままトランスポート側だけを差し替えられた。**

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
| `unlockAllAddresses` | passphrase | §7.4参照。数千件規模の一括unlock(vault方式) |
| `importAddress` | address, signingWIF, encryptionWIF, label, storePassphrase, nonceTrialsPerByte?, payloadLengthExtraBytes? | 2026-08-29実装。当初案は`address`を含まなかったが、WIFは秘密鍵のみでaddressVersion/streamを含まないため確定時に追加した(§11参照)。addressから復元したripeとWIFの公開鍵ripeが一致するか検証してから保存する |
| `exportAddress` | address, passphrase | 2026-08-29実装。importAddressと対称。その場でpassphrase復号しsigningWIF/encryptionWIFを返す一回性操作(keyringには触れない) |


### 6.3 libmicrohttpd + cJSONへの移行(2026-09-15)

§6.1で「トランスポートは自前実装のJSON-RPC 2.0のみをv1スコープとする」と決めていたが、
これを撤回し、**HTTPトランスポートを[libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/)、
JSONのパース/シリアライズを[cJSON](https://github.com/DaveGamble/cJSON)へ移行した。**
自前実装(`bm_json_*`、`src/common/json.c`)はCLI(`src/cli/main.c`)側で引き続き使っており、
削除はしていない(§11の残件参照)。

#### 移行の動機(抽象論ではなく、実際に確認できた2件の欠陥)

1. **認証前DoS。** 旧`read_until_double_crlf()`はaccept済みのfdに読み取りタイムアウトを
   一切設定せず`read()`でブロックし、accept loop(`bm_api_server_serve_forever`)も
   シングルスレッドだった。このためTCP接続だけして1バイトも送らないクライアントが1つ
   居るだけでRPCサーバー全体が無期限に停止した。しかもこの停止はHTTP Basic認証の検証より
   手前で起きるため、`apiusername`/`apipassword`を知らない相手でも発動できた
   (`nc 127.0.0.1 8442`を実行して放置するだけ)。bindが`127.0.0.1`固定なのでリモートからは
   到達できないが、同一ホスト上の任意のプロセスから仕掛けられる。
2. **認証後のプロセスクラッシュ。** 自前JSONパーサ(`bm_json_parse`)は再帰下降で、
   ネストの深さに上限を設けていなかった。移行前に実測したところ、`[`を10万個並べただけの
   入力でスタックオーバーフローによりSIGSEGVした(深さ5万では成功、10万で落ちる)。
   リクエストボディの上限が1MiB(`MAX_REQUEST_SIZE`)なので、深さ約100万まで送り込める。
   JSONのパースはBasic認証より後段なので資格情報は必要だが、`bitmessaged`プロセス全体が
   落ちるため影響は大きい。cJSONは`CJSON_NESTING_LIMIT`(既定1000)を超えると`NULL`を返す
   だけなので、これは構造的に起こらない。

副次的に、**Transfer-Encoding: chunked非対応**(旧実装は`Content-Length`が無いと400を返した)、
**keep-alive非対応**、**同時1リクエスト**という制約も解消された。自前のHTTPパース約280行と
base64デコード/Authorizationヘッダ探索約80行を削除できている。

#### 「本家準拠か、意図的な逸脱か」の切り分け

CLAUDE.mdの規律に従い本家`src/api.py`を確認した。PyBitmessageのAPIサーバーはPython標準
ライブラリの`SimpleXMLRPCServer`(または`jsonrpclib.SimpleJSONRPCServer`)であり、
`SimpleXMLRPCRequestHandler.protocol_version`は`BaseHTTPRequestHandler`の既定値
`HTTP/1.0`のまま(実測確認)、`socketserver.TCPServer`なので同時に1リクエストしか処理しない。
つまり**旧自前実装の挙動は結果的に本家と一致しており、今回の移行は本家からの逸脱にあたる。**

それでも逸脱を選んだのは、**本家準拠が必要なのは「他ノードから観測できる挙動」に限る**
という切り分けによる。P2Pのワイヤーフォーマット・PoWのtarget計算式・rating更新・peerから
見えるタイムアウト値は、ズレれば相互運用が壊れるかbanされるので本家準拠が絶対である。
一方このAPI層は自ノードのローカルクライアント(`bitmessage-cli`や将来のフロントエンド)しか
見ないため、本家に権威が無い。加えて本家の`HTTP/1.0`は設計判断として選ばれたものではなく、
`BaseHTTPRequestHandler`のクラス変数の既定値を誰も見直していないだけであり、
本家`api.py`のdocstring自身が「`apivariant=xml`は後方互換のための現行デフォルトだが
`json`を推奨」と書いてAPI層をレガシー扱いしている。真似るべき判断が存在しない。

#### 実装上の決定

- **スレッドモデルは`MHD_USE_INTERNAL_POLLING_THREAD`単独**とし、
  `MHD_USE_THREAD_PER_CONNECTION`もスレッドプール(`MHD_OPTION_THREAD_POOL_SIZE`)も使わない。
  MHDが内部スレッド1本でpoll/epollループを回して複数接続を多重化しつつ、コールバックは
  常にその1本から直列に呼ぶモデルなので、「同時に処理するリクエストは常に1件」という
  旧実装の前提をそのまま維持できる。`METHODS[]`の各ハンドラはkeyring・registry・各DB
  ハンドルといった共有状態を触っており、並列化するならそれら全ての排他制御を見直す必要が
  あるため、今回の移行では意図的に直列のままにした。並列化したくなったら、フラグを変える
  前に全ハンドラのスレッド安全性を検証すること。
- **Basic認証の照合は引き続き自前の定数時間比較で行う。** `MHD_basic_auth_get_username_password3()`が
  肩代わりするのはAuthorizationヘッダの探索とbase64デコードとユーザー名/パスワードの
  切り分けまでで、照合自体はアプリの責任であるため。§6.1の「比較は定数時間で行う」は維持。
  なお旧実装は`"user:pass"`を`char expected[256]`へ`snprintf`で連結してから比較していたため、
  256バイトを超える長い`apipassword`を設定すると黙って切り詰められ、切り詰め後の値でも
  認証が通る状態だった(移行のついでに解消)。
- **keep-aliveが有効になった。** HTTP/1.1の既定動作なので許容するが、「応答を読んだ後EOFまで
  読む」実装のクライアントはサーバー側の接続タイムアウト(`BM_API_CONNECTION_TIMEOUT_SECONDS`
  =30秒)まで待たされる。本リポジトリの`bitmessage-cli`(`src/cli/http_client.c`)とテストの
  HTTPヘルパーがまさにその実装だったため、リクエストに`Connection: close`を付けるよう修正した。
  外部のクライアントを書く場合も同様の注意が要る。
- **MHDの内部エラーログは`MHD_OPTION_EXTERNAL_LOGGER`で`bm_log`へ流す(DEBUGレベル)。**
  `MHD_USE_ERROR_LOG`だけを指定するとMHDが素のstderrへ直接書き、タイムスタンプもレベルタグも
  付かない行がjournalに混ざる。しかもその大半は「Connection was closed by remote side with
  incomplete request.」のような、ローカルの任意プロセスが接続と切断を繰り返すだけで出させられる
  内容なので、運用時のログを汚さないようDEBUGへ落としてある(起動失敗のような本当に重要な
  事象は`MHD_start_daemon()`のNULL戻り値として別途`bm_log_error`している)。この配線のために
  `bm_log_vleveled()`(`bm_log_leveled`の`va_list`版)を`common/logging.*`へ追加した。
  なお`MHD_OPTION_EXTERNAL_LOGGER`は**オプション列の先頭に置かないと**MHD自身が
  「not the first option specified」と警告し、それ以前のメッセージは標準ロガーへ流れてしまう。
- **公開ヘッダ(`api_server.h`)には`struct MHD_Daemon *`も`cJSON *`も露出させない**
  (§3.5の暗号バックエンドと同じ規律)。移行に伴い`bm_api_server_listen()`/
  `bm_api_server_handle_connection()`/`bm_api_server_serve_forever()`は削除した
  (いずれも公開されていたが`bm_api_server_thread`以外からは呼ばれていなかった)。
- **ライセンス。** libmicrohttpdはLGPL-2.1+だが動的リンクのため本体(MIT)を汚染しない。
  cJSONはMIT。どちらもDebian/Ubuntu・Fedora・Arch等の標準リポジトリにある小さなCライブラリで、
  ビルド要件としてはOpenSSL/SQLite3に1段積む形になる(CMakeでは`pkg_check_modules`で検出)。

### 6.4 JSON-RPC 2.0仕様への準拠度の向上(2026-09-15)

§6.3の移行でディスパッチ層を書き直すのに合わせ、それまで未対応だった仕様項目を実装した。

- **バッチリクエスト(Specification §6)。** 旧実装はボディがJSONオブジェクトであることを
  要求しており、仕様で定められたバッチ(リクエストオブジェクトの配列)を送ると
  「Parse error: invalid JSON」で拒否していた。応答は仕様通り、通知を除いた各リクエストの
  応答オブジェクトを要素とする配列で返す(順序は仕様上は問わないが、クライアント側の
  突き合わせが楽なのでリクエスト順に揃えてある)。空配列はInvalid Requestとして
  単一の応答オブジェクトで返す。
  なお**1バッチあたり256件の上限(`BM_JSONRPC_MAX_BATCH_SIZE`)を設けた。** 仕様に上限の定めは
  無いが、1MiBのボディいっぱいまで最小サイズのリクエストを詰めると3万件強が入り、それが全て
  `unlockAddress`(1件あたりscryptで約161ms)だと1リクエストでRPCサーバーを1時間以上占有できて
  しまう(ハンドラは直列実行のため、その間他のAPI呼び出しは待たされる)。認証済みクライアント
  しか到達できない経路とはいえ、スクリプトのループミスでも起きうるので上限を設ける。
  数千件規模の一括処理には`importAddressesBulk`のような「1メソッド呼び出しで多件数を扱う」
  専用メソッドを使うこと。
- **通知(notification、Specification §4.1)。** `id`メンバを持たないリクエストには応答を
  返してはならない。旧実装は`id`が無くても`"id":null`を付けた応答を返していた。現在は
  単一の通知・全て通知のバッチともHTTP 204 No Contentで本文なしを返す。副作用(ハンドラの
  実行)は通常通り起こした上で応答だけを捨てる。`"id":null`は「idを明示的にnullにした
  リクエスト」であって通知ではないため、従来通り応答する。
- **エラーコードの整理(Specification §5.1)。** 旧実装は全て`-32000`(実装定義のServer error)を
  返しており、クライアント側が「JSONが壊れている」「メソッド名を間違えた」「そもそも
  リクエストの形になっていない」を区別できなかった。現在はParse error=`-32700`、
  Invalid Request=`-32600`、Method not found=`-32601`を使い分ける。ハンドラが返す
  アプリケーション由来のエラーだけは引き続き`-32000`(仕様上`-32000`〜`-32099`が実装定義用に
  予約されている)。

検証は`tests/test_api_transport.c`(新設)で行っている。バッチ・通知・エラーコードに加え、
移行の動機になった欠陥が実際に直っていること(放置された接続がサーバーを占有しないこと、
深さ10万のネストでプロセスが落ちないこと、chunkedで送れること)も実HTTPリクエストで確認する。

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

### 7.4 vault方式(2段階KDF)による一括unlock — §11-19の解決(2026-08-29)

**実装済み(`src/core/keyring.c`, `src/core/identity_store.c`)。** §11-19で「keys.datバックアップから
5000件規模のアドレスを一括インポートする予定があり、現行の1アドレス1passphrase・個別scrypt方式では
運用が非現実的」という課題が持ち上がった際の解決策。実測でscrypt(N=2^15,r=8,p=1)は1回あたり約161ms
かかり(2026-08-29計測、Ryzen系CPU)、5000件を直列に個別scryptすると約13.4分かかる計算になり、
起動のたびに許容できる待ち時間ではないと判断した。

**方式**: passphraseからscryptで導出する重いKDFを「vault全体で1回だけ」に抑える2段階構成にする。

```
master_kek = scrypt(passphrase, vault_salt, N, r, p)              -- 重い、1回だけ
per_row_kek = HKDF-Expand(SHA256, ikm=master_kek, salt=row.kdf_salt, info=address)  -- 軽い、行ごと
wrapped = AES-256-GCM-Encrypt(per_row_kek, nonce, AAD=address, plaintext=priv_key)   -- §7.1と同じ
```

- `identities.kdf_algo`列の値で行ごとの方式を判別する。既存の`'scrypt'`(個別KDF、§7.1のまま)と
  新設の`'vault-hkdf'`(この方式)が同一DB内に混在してよい設計にした
- `vault_salt`は新設した`kdf_vault`テーブル(単一行、`id=0`固定)にidentity.db全体で共有する形で保存する
- HKDFの`info`にaddress文字列を混ぜるのは、AES-256-GCMラップのAAD=addressと同じ意図(ある行のkekを
  別の行に転用するような取り違えの防止)

**lazy migration方針(ユーザー相談、2026-08-29)**: 既にidentity.dbには旧方式(個別scrypt)で登録済みの
アドレスが一部あり、かつそれらは「全部同一passphraseで運用していた」("たくさんあるアドレスに
それぞれpassphraseを割り振るのが非効率的だった"とのこと)ため、新規にvault方式へ統一しても運用上の
制約にはならないと確認した。移行は別途migrationツールを作るのではなく、`unlockAllAddresses`の
ループ内で「旧方式の行をpassphraseで復号できたら、その場でvault方式へre-wrapする」lazy migration方式を
採用した(ユーザー提案)。理由: ①master KEKの導出はどのみち呼び出し1回につき1回だけキャッシュする設計に
なるためre-wrap対象が何件あっても追加のscryptコストが発生しない、②2回目以降の呼び出しでは前回
re-wrapされた行が高速パスに乗るため「使うたびに勝手に速くなる」自然な挙動になる、③別APIや別CLIコマンドを
新設する必要がない。

**vault canaryによるpassphrase誤り保護(重要、2026-08-29発覚)**: 実装レビュー中に気付いた設計上の
落とし穴として、「vaultは既に存在するが、渡されたpassphraseがvaultの正しいものと異なる」場合の
挙動がある。scryptは誤ったpassphraseでも必ず何らかの32byte値を返すため、これだけでは
`derive_master_kek`の成否から正誤を判定できない。もし何も対策しなければ、たまたま「旧方式(個別scrypt)の
行の一つ」が渡された誤ったpassphraseと一致してunlockに成功した場合、その誤ったmaster KEKで
re-wrapが実行されてしまい、vault全体が汚染される(以後、正しいpassphraseでもvault方式の行が
一切復号できなくなる)という重大なバグになりうる。対策として、vault作成時に既知の固定平文
(`VAULT_CANARY_PLAINTEXT`、秘匿性は無い)をmaster KEKでAES-256-GCMラップした`canary`を
`kdf_vault`テーブルに保存しておき、以後`unlockAllAddresses`はmaster KEK導出の直後に必ずこの
canaryを復号できることを確認してから使う(`verify_vault_canary`)。canary検証に失敗した場合は
「master KEKを導出できなかった」ものとして扱い、以後のループでも新規vault作成を試みない
(`vault_exists`と`have_master_kek`を分けて管理し、「vaultは存在するが渡されたpassphraseが違う」
場合に誤って上書きしないようにしている)。この場合、旧方式の行のうち渡されたpassphraseと
一致するものは個別unlockはできるが、re-wrap(vaultへの統合)はスキップされる、という安全側の
挙動になる。`tests/test_keyring.c`にこの保護が実際に効くことを検証するテストケースを追加した
(2つ目のpassphraseで一括unlockした際、対象の行のkdf_algoが'scrypt'のまま変化しないことを確認)。

**今後の課題(未着手、バックログ化)**: 実装後にユーザーから「マスターパスフレーズの変更ができない」
「変更できるなら対称的にvault方式自体を無効化(個別管理方式へ戻す)する手段も無いと筋が通らない」との
指摘があった。もっともな指摘であり、現行実装には以下が一切無い:
- `changeMasterPassphrase(oldPassphrase, newPassphrase)`: 全vault-hkdf行を旧passphraseで
  unlockし直し、新しい`vault_salt`/`canary`を作成し、全行を新master KEKでre-wrapする
- vault方式の無効化(全vault-hkdf行を個別scrypt方式へ戻す、または`kdf_vault`行自体の削除)

いずれも「vault管理系ライフサイクルAPI群」としてまとめて別セッションで着手する方針(2026-08-29、
ユーザーと合意)。今回の`unlockAllAddresses`自体の機能には影響しない。

### 7.5 importAddressesBulk — importAddressの一括呼び出しでvault化の効果が出ない問題の解決(2026-08-29)

**実装済み(`src/core/keyring.c`の`bm_keyring_resolve_or_create_vault_master_kek`/
`bm_keyring_import_identity_with_master_kek`、`src/core/api_server.c`の
`importAddressesBulk`、CLIの`import-keys-dat`)。**

ユーザーの実keys.dat(5143件、1.5MB)を使った実地検証で発覚した問題。§7.4でimportAddressを
vault方式に切り替えたにも関わらず、CLIの`import-keys-dat`が`importAddress`を1件ずつ個別の
HTTPリクエストで呼ぶ実装のままだったため、**リクエストのたびにvaultのmaster KEK導出
(scrypt、実測161ms)が再実行されてしまい**、vault化の効果が全く出ていなかった(実測: 10件で
1.77秒、5143件では単純ループ版とほぼ同じ約15分の見積もりになった)。これは§11-19で
`unlockAllAddresses`について既に解決したのと全く同じ問題(「ループの各要素ごとに独立して
重いKDFを再実行してしまう」)が、importAddressの文脈で再発したもの。

対策として`unlockAllAddresses`と同じパターンを踏襲し、複数エントリをまとめて1回のAPI呼び出しで
処理する`importAddressesBulk(entries, storePassphrase)`を新設した。1回の呼び出し内でmaster KEKを
`bm_keyring_resolve_or_create_vault_master_kek`で1回だけ計算し、各entryは
`bm_keyring_import_identity_with_master_kek`(scryptを伴わない軽量パス)で処理する。CLIの
`import-keys-dat`は、daemonのHTTPリクエストボディ1MiB上限(§11参照)に収まるよう、
`KEYS_DAT_BATCH_SIZE`(300件、1エントリの概算JSONサイズ600byteから安全マージンを見て決定)
件ずつバッチに分けて呼び出す方式に変更した。既存の単発`importAddress`はそのまま残し
(1件だけインポートする場合はこちらでよい、内部は`bm_keyring_resolve_or_create_vault_master_kek`
→`bm_keyring_import_identity_with_master_kek`の組み合わせとして再実装)、複数件をこれで
個別に何度も呼んではいけない旨をヘッダコメントに明記した。

**実測結果(2026-08-29、ユーザー提供の実keys.dat 5143件で検証)**:
- `import-keys-dat`(バッチ化後): 約15秒(5140〜5142件成功、失敗はアドレスデータ自体の
  問題2〜3件、§3.3のdecode寛容化とは別途参照)
- `unlock-all`(vault方式、5142件全件が最初からvault-hkdfで保存済みの状態): **0.6秒**
  (2回目の呼び出しは既にunlock済みのためさらに高速、0.3秒)

これで§11-19発端の「5000件規模のkeys.datインポート・一括unlock」という目標が実測でも
達成されたことを確認した。

**2026-08-29追記: unlockAllAddressesからbackfill trial_decryptを削除**。本番daemon Aへの
デプロイ後、ユーザーから「unlock-all、オブジェクトの復号試行も普通に入ってくるのでめちゃくちゃ
重くなりますね」と指摘され発覚。`h_unlockAddress`(単体API)はunlock成功後に
`bm_object_sync_backfill_trial_decrypt`(§11 2026-08-25、joinChan後にchan宛の過去メッセージが
読めない問題への対応として追加)を呼んでおり、`h_unlockAllAddresses`もこれを踏襲して
(unlockが1件でも成功したら)1回だけ呼ぶ実装にしていた。しかし`bm_object_sync_backfill_
trial_decrypt`は内部でobject_pool.db内の**全MSGオブジェクト**それぞれに対し
`bm_trial_decrypt_msg`(`src/core/trial_decrypt.c`)を呼び、この関数はkeyring内の
**unlocked鍵全件**を線形探索してECIES復号(ECDH計算を伴う)を試みる実装になっている。
つまり計算量は「MSGオブジェクト数×unlockedアドレス数」に比例し、5000件規模の一括unlockで
「1回だけ呼ぶ」よう配慮しても、その1回の中身がobject_pool.dbにMSGオブジェクトが数百件
溜まっているだけで数十万回以上のECDH計算になり、APIリクエストが致命的に長時間ブロックされる
(daemonのAPIサーバースレッドが専有され、他のAPI呼び出しも待たされる)。

この一括backfill機能自体が本家PyBitmessage(全アドレスを起動時から常時プロセスメモリに
ロードしているため「ロック中に受信したメッセージを後から再走査する」という概念自体が存在
しない、§8-1参照)には無い、本実装独自の追加であることも踏まえ、`unlockAllAddresses`からは
この呼び出しを削除する対応にした(ユーザーと合意)。単体の`unlockAddress`は1identity分の
コストで済むため、これまで通りbackfillを継続する。5000件規模の一括インポート直後は、
そのアドレス群がこれまでネットワークに存在も知られていなかった(=まだメッセージを
受け取りようがない)のが通常のユースケースであるため、実用上の支障は小さいと判断した。
ctest 41件全通過。

**2026-08-29追記: 自前JSON実装(`src/common/json.c`)の非ASCII文字パース処理のバグ修正**。
本番daemon Aへのkeys.datインポート成功後、ユーザーから「インポートしたアドレスのラベルが
`Ã£ÂÂ§Ã£ÂÂÂ`のように文字化けする」と報告され発覚。元の`keys.ini`には`label = でじこ`と
UTF-8で正しく保存されていることを確認済みだったため、CLI→daemon間のJSON往復のどこかで
壊れていると判断し、`parse_string_raw`(`src/common/json.c`)を調査した。

原因: `parse_string_raw`はJSON文字列をバイト単位でループしており、エスケープされていない
通常の文字は`append_utf8(&out, &out_len, &out_cap, ch)`で処理していた。`ch`は`unsigned char`
(1バイト)であり、`append_utf8`はこれを**Unicodeコードポイントとして**UTF-8にエンコードする
関数だった。つまり、JSON文字列中に既にUTF-8エンコード済みのマルチバイト文字(例:
「で」=`E3 81 A7`の3バイト)が来ても、各バイトを個別に独立したコードポイントとして誤認識し、
`0xE3`(=Unicodeコードポイント227、Latin-1の`ã`に相当)を`append_utf8`で改めて2バイト
(`C3 A3`)に再エンコードしてしまっていた。これは「UTF-8のバイト列をLatin-1(1バイト1文字)
として誤読し、それを再度UTF-8としてエンコードし直す」典型的な二重エンコーディングで、
`Ã£ÂÂ`のような文字化けパターンと一致した。シリアライズ側(`sb_append_escaped_string`)は
逆に0x80以上のバイトを生バイトのままコピーする正しい実装だったため、非対称なバグだった
(自分がシリアライズしたJSONを自分でパースする往復では問題が起きず、他プロセス
(daemon)からのレスポンスをパースする片道でのみ顕在化していた可能性があるが、実際には
CLIが送信したリクエストをdaemon側がパースする際に本バグが発現していた)。

このバグは今回のkeys.datインポート機能に限らず、**日本語や絵文字等の非ASCII文字を含む
JSON文字列全般(ラベル・アドレス帳のlabel・メッセージのsubject/body等)に影響する既存の
一般的なバグ**であり、たまたま今まで非ASCII文字を含むデータでの往復テストが無かったため
見過ごされていた。

修正: 新設した`append_raw_byte`(コードポイント変換をせず生バイトをそのままバッファへ追加する
だけの関数)を使い、`ch < 0x80`(ASCII範囲)なら従来通り`append_utf8`、`ch >= 0x80`
(既にUTF-8エンコード済みの生バイト)なら`append_raw_byte`で分岐するようにした。
`tests/test_json.c`に`test_utf8_roundtrip`を追加し、日本語文字列
(`serialize→parse`往復、および生UTF-8バイト列を直接埋め込んだJSON文字列リテラルの
直接パース)がバイト単位で完全に復元されることを確認した。ctest 41件全通過。

**2026-08-29追記: setAddressLabel API・set-label/fix-labels-from-keys-dat CLIコマンドの新設**。
上記JSON文字化けバグの影響で、既にインポート済みの5142件のうち非ASCII文字(日本語等)を含む
ラベルが文字化けした状態でidentity.dbに保存されてしまっていたため、修復手段としてユーザーから
依頼された。PyBitmessage本家にはJSON-RPC API経由でidentityのラベルを変更する手段が無いが、
GUI(`bitmessageqt`)は`config.set(address, 'label', newLabel)`で直接keys.datを書き換えられる
ことをソースで確認した(`bitmessageqt/foldertree.py`等)。つまり本家もGUI上ではラベルだけの
変更が可能だが、API経由では公開されていない、という状況だった。

これを踏まえ、`setAddressLabel(address, label)`(`src/core/api_server.c`、秘密鍵には一切触れず
`identities.label`列のみ更新)を本実装独自のAPI拡張として新設した。あわせてCLIに`set-label
<address> <label>`(単発)と`fix-labels-from-keys-dat <path>`(keys.datを再パースしてlabelキー
だけを読み、既存アドレスのラベルを一括で正しい値へ修正する)を追加した。ラベル更新は秘密鍵の
KEKラッピング(scrypt)を伴わない軽量な処理のため、`importAddressesBulk`のようなバッチAPIは
不要と判断し、1件ずつの`setAddressLabel`呼び出しで十分と判断した。

`tests/test_api_server.c`に日本語ラベルでのend-to-end検証(上記JSON文字化けバグの回帰確認を
兼ねる)、`tests/test_cli_integration.sh`に`set-label`/`fix-labels-from-keys-dat`のCLI配線
テストを追加した。ctest 41件全通過。

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

### 9.3 Stage 1実装状況(配線、2026-08-22)

peer rating周りのバグ修正セッションと同じ日に着手。§9.2で確保していた`bm_decide_propagation`
(`infra/object.h`)は定義こそあったが、実際のinv送信経路(`infra/peer_registry.c`の
`bm_peer_registry_broadcast_inv`)からは一度も呼ばれておらず、「差し込み点」が配線されて
いなかったことが判明した。Stage 1でこれを解消した(挙動は変えない、v1は常にFLUFFを
返すダミーのまま)。

**着手前に確認した前提:** 実装が無駄足にならないか、この3日間観測した実peerの`version`
メッセージを集計したところ、85件全て`services=11`(1+2+8、8が`NODE_DANDELION`)で、
100%がDandelion対応を表明していた(全て`/PyBitmessage:0.6.3.2/`)。mainnetの主要
クライアントでは標準的に有効になっていると判断し、実装する価値があると確認した上で着手した。

**実装内容:**
- `infra/protocol.h`に`BM_SERVICE_NODE_DANDELION`(=8)を追加
- `infra/object_sync.c`の`bm_object_sync_dispatch`に、`dinv`コマンドを`inv`と全く同じ
  処理経路(`handle_inv`)へ流す分岐を追加(ワイヤーフォーマットが完全に同一なので安全)
- `infra/peer_registry.c`の`bm_peer_registry_broadcast_inv`を書き換え、登録済み接続
  ごと・hashごとに`bm_decide_propagation`を呼んでFLUFF判定されたhashだけをその接続への
  inv送信対象に含めるようにした(v1は常にFLUFFなので、結果的に送信内容・宛先は
  従来と完全に同じ。STEMがv1で発生することは無いが、将来STEMを実際に返すように
  なった際は、このbroadcast関数(全接続への通常inv配信)とは別に、単一の子ピアだけへ
  `dinv`を送る専用の送信経路をStage 2で追加する想定)

**テスト:** `tests/test_dandelion_stage1.c`を新規追加。`BM_SERVICE_NODE_DANDELION`の値、
`bm_decide_propagation`が常にFLUFFを返すこと、`dinv`受信が`inv`受信と全く同じ
(未所持hashへ`getdata`を送り返す)処理経路に流れることを確認した。加えて
`bm_peer_registry_broadcast_inv`の書き換え自体は既存の`tests/test_object_sync.c`の
broadcast検証(新規object受信時、他の接続peerへ`inv`が届くこと)が引き続き通っていることで
実質的な回帰確認になっている。ctest 25件全通過。

Stage 2(実際のstem/fluff状態機械)は§9.4参照。

### 9.4 Stage 2実装状況: 単一ホップ分のstem(2026-08-22)

Stage 1と同じ日、ユーザーから続けて依頼を受けて着手。§9.2の完全な設計(多段リレー、
nodeMapが親ごとに子を持つ形、hashMapのDB永続化無し等)をそのまま実装すると影響範囲が
非常に大きくなる(特に「dinvで受信したobjectを自分も継続してstem中継する」多段リレー部分は
受信経路(inv/dinv受信→getdata→object到着)全体に「どちらで最初に知ったか」の状態を通す
必要がある)ため、ユーザーと合意の上でスコープを**単一ホップ分のstem**(自分が新規に検出した
objectを1回だけ子ピアへstem中継し、タイムアウトでfluffへ強制遷移させる)に絞って実装した。
dinvで受信したobjectを自分も継続してstem中継する多段リレー部分は次回以降のbacklog。

**着手前の確認:** 実装が無駄足にならないか不安との声があったため、この3日間観測した
実peerのversionメッセージ(85件、Stage 1の節で集計済み)が全てDandelion対応を表明して
いることを踏まえた上で着手した。

**実装内容:**
- `infra/network.h`の`struct bm_fd_data`に`services`(相手のversion messageの
  servicesビットフィールド)を追加。`object_sync.c`のversion受信処理で記録する
  (stem successor選定に使う)
- `infra/peer_registry.c`に`bm_peer_registry_pick_random_dandelion_peer`を追加。
  outbound(`BM_FD_CLIENT_SOCKET`)かつ`BM_SERVICE_NODE_DANDELION`を立てている接続から
  古典的reservoir samplingで一様ランダムに1つ選ぶ
- `infra/peer_registry.c`の`bm_peer_registry_broadcast_inv`をさらに拡張し、接続ごとに
  FLUFF判定されたhashは通常の`inv`、STEM判定されたhashは`dinv`として、同じ接続へ別々の
  パケットで送るようにした(Stage 1で予告していた設計そのまま)
- `infra/dandelion.c`/`.h`を新規追加。プロセス内シングルトン(`struct`、DB永続化無し、
  §9.2通り)として、(1) 600秒ごとのstem successor再抽選
  (`bm_dandelion_maybe_reshuffle`)、(2) objectのhashごとの状態管理
  (`fluff_deadline` = 固定10秒 + 平均30秒の指数分布、「ポアソン分布」の近似)と
  それに基づくFLUFF/STEM/SKIP判定(`bm_dandelion_decide`、`infra/object.c`の
  `bm_decide_propagation`から委譲される)、(3) タイムアウトを過ぎても誰も呼び直さない
  限りstemのまま埋もれてしまうhashを能動的にfluffする
  `bm_dandelion_expire_and_refluff`(古いfluff済みエントリの間引きも兼ねる)、を実装した。
  時刻は全て呼び出し側が明示的に渡す設計にしてテスト容易性を確保した(内部で`time(NULL)`を
  呼ぶのは`bm_decide_propagation`の薄いラッパー部分のみ)
- `infra/peer_connector.c`の`bm_peer_connector_thread`(既存の1秒間隔ポーリングループ)に
  相乗りさせ、`bm_dandelion_maybe_reshuffle`/`bm_dandelion_expire_and_refluff`を毎秒
  呼ぶ(PyBitmessageの`InvThread.expire()`相当の頻度、DESIGN.md §9.2で「実装着手時に
  判断する」としていた点を解消)。専用スレッドは新設しなかった
- `main.c`起動時に`bm_dandelion_module_init()`を呼ぶ

**テスト:** `tests/test_dandelion_stage2.c`を新規追加。(1)stem successor候補選定が
outbound+`NODE_DANDELION`の接続だけを対象にすること(reservoir samplingの安定性も
20回試行で確認)、(2)stem successor無し/タイムアウト前/タイムアウト後でFLUFF/STEM/SKIPが
正しく切り替わること、(3)`bm_dandelion_expire_and_refluff`がタイムアウト経過後に
実際に`inv`をbroadcastし、それまでSKIPだった接続にも届くようになることを、実TCPソケット+
決定的な時刻注入で確認した。開発中、`bm_peer_registry_broadcast_inv`経由の呼び出しが
内部で`time(NULL)`(実時刻)を使う一方、テスト側が固定の架空時刻を使っていたために
発生した不整合(タイムアウト計算がかみ合わずFLUFF/STEM判定が不安定になる)を実際に
踏んだため、該当シナリオはテスト側も実時刻基準に統一して解消した。`tests/test_dandelion_
stage1.c`の一部チェックも「v1は常にFLUFFのダミー」という古い前提から「stem successor
無しなら常にFLUFF」という現状の実装に合わせて文言を更新した。ctest 26件全通過。

### 9.5 Stage 3実装状況: inv/dinvの来歴を区別してstem要否を判定(2026-08-22)

Stage 2と同じ日、ユーザーから続けて依頼を受けて着手。Stage 2まででは、objectを最初に
`inv`(既に他ノードがfluff済み)で知ったか`dinv`(まだstem中)で知ったかを区別せず、
新規object全てに同じstem→タイムアウトfluff処理をかけていた。既に公開済みのobjectを
それ以上stemしても匿名性の得は無く、遅延させるだけ無駄なため、この区別を追加した。
自分発object(getpubkey自応答・onionpeer announce等、inv/dinvを受信していないもの)は
従来通りstemから開始する(provenance不明のまま、既定でstem対象)。

**実装内容:**
- `infra/dandelion.c`の`struct dandelion_entry`に`learned_via_plain_inv`を追加。
  `bm_dandelion_note_source(hash, is_dinv, now)`を新規追加し、`is_dinv=0`(通常のinv)
  の場合のみエントリを先回りして作成・マークする(`is_dinv=1`は「stem継続」という
  既定動作を変えないため何もしない早期return)
- `bm_dandelion_decide`のFLUFF判定条件に`e->learned_via_plain_inv`を追加(タイムアウト・
  stem successor無しと同列の「即FLUFF」条件として扱う)
- `infra/object_sync.c`の`handle_inv`(Stage 1で`inv`/`dinv`共通処理にしていた関数)が、
  未所持hashについてのみ`msg->command`(`"inv"`か`"dinv"`か)を見て
  `bm_dandelion_note_source`を呼ぶようにした。ワイヤーフォーマットが同一なため
  パース・未所持判定・getdata送信自体はStage 1から変更していない

**テスト:** `tests/test_dandelion_stage3.c`を新規追加。(1)`is_dinv=0`で記録した
hashは、stem successorが存在してもタイムアウト前から常にFLUFFになること、(2)
`is_dinv=1`で記録したhashは、記録しなかった場合と同じくSTEM判定されうること(既定動作を
変えないことの確認)、(3)実際に`bm_object_sync_dispatch`へ`"inv"`コマンドを流し込み、
そのhashについて`bm_decide_propagation`を呼ぶと(stem successorが利用可能でも)FLUFFに
なることを、実際のdispatch経路を通して確認した。ctest 27件全通過。

dinvで受信したobjectを自分も継続してstem中継する「多段リレー」の実質的な部分
(自分がstem successorとしてdinvを受け取った際、単に既存のstem successorへdinvを
中継する)は今回実装した設計で既に自然にカバーされている: `handle_inv`が`dinv`受信時に
`is_dinv=1`で記録し、後で`handle_object`がobject本体を受け取った際に呼ぶ
`bm_decide_propagation`は(provenance不明の自分発objectと同じく)通常のstem→タイムアウト
fluff経路を通るため、結果的に「dinvで受け取ったobjectを自分のstem successorへ中継する」
という多段リレーの1ホップが実現されている。DESIGN.md §9.2で当初懸念していたほど大きな
実装は不要だった。

### 9.6 自己announceでのNODE_DANDELION表明(完成、2026-08-22)

Stage 1〜3の完了時点で、`bm_create_version_payload`(`infra/protocol.c`)は§9.2の当初方針
通り自分のversion messageの`services`を`0`固定にしており、`BM_SERVICE_NODE_DANDELION`を
一切表明していなかった。この状態だと、こちらは他ピアへstemを送る側にはなれるが、
**他の実peerからは「stem継続してくれない相手」とみなされ、stem successorとして選んで
もらえない**という一方通行の状態だった。

Stage 3までで`dinv`受信→自分のstem successorへの中継は実装・テスト・実daemonでの
安定稼働まで確認済みだったため、表明しない理由が無くなっていた。`services`を
`BM_SERVICE_NODE_DANDELION`固定に変更し、双方向の参加者にした。ctest 27件全通過
(既存テストは`services=0`を前提にしていなかったため影響無し)。

これでDandelion++はDESIGN.md §9.1の設計目標(単一ホップのstem中継・タイムアウトに
よるfluffへの強制遷移・多段のランダムウォーク・双方向の参加)を一通り満たした。
DB永続化を伴う本格的なper-parent nodeMap(PyBitmessageの実装により近い形)は採用せず、
プロセス全体で単一のstem successorを使う簡略化した設計(形式的なDandelion++の
1-regularな中継グラフとしては正しい)を意図的に選んでいる。

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

過去のセッションでの経緯記録(バグの発覚経緯・議論の顛末・PyBitmessage本家との比較調査
結果など、日付順)は肥大化のため [DESIGN-LOG.md](DESIGN-LOG.md) へ分離した
(2026-08-24)。以下は現在のbacklog(次にやること一覧)。

### v1.1以降のbacklog

2026-08-21に洗い出した項目(優先順位付けした6項目・peers.dbクリーンアップ・
手動peer追加/observed_nodesリスト)は全て完了した。それ以降のセッション(詳細は
DESIGN-LOG.md参照)で新たに洗い出した項目を含め、残るのは以下の通り(優先度順)。

1. ~~**inbound接続のアイドル/ハンドシェイクタイムアウトが無い、keepalive `ping`の自発送信も
   無い**~~: 2026-08-23完了(DESIGN-LOG.mdの該当セッション参照)。
2. ~~**inbound接続のレート制限が無い**~~: 2026-08-23完了(DESIGN-LOG.mdの該当セッション参照)。同時接続数
   上限(`BM_MAX_INBOUND_CONNECTIONS`)・単位時間あたりaccept数上限
   (`BM_INBOUND_ACCEPT_MAX_PER_WINDOW`)ともIPに依存しない固定値で実装した。
   実運用でこれらの定数に頻繁に到達するようなら、`config_store.c`への設定化を
   改めて検討する(ユーザーからの申し送り、未着手)。
3. ~~**プロトコルバージョンの互換性チェックが無い**~~: 2026-08-23完了(DESIGN-LOG.mdの該当セッション参照)。
   `BM_MIN_PROTOCOL_VERSION`(=3)未満を名乗る相手にはfatal errorを送って切断する。
4. ~~**version messageの`timestamp`が未検証**~~: 2026-08-23完了(DESIGN-LOG.mdの該当セッション参照)。
   `BM_MAX_TIME_OFFSET_SECONDS`(=3600秒)を超えて自分の時計とズレていればfatal
   errorを送って切断する。
5. ~~**`listConnections`的なAPI(接続一覧取得)**~~: MVP(host/port/fullyEstablished/
   userAgent、PyBitmessage本家と同形式)、送受信バイト数(接続ごと+`getNetworkStats`
   での全体累積)とも2026-08-23完了(DESIGN-LOG.mdの該当セッション参照)。PyBitmessage自体には無い機能
   (本家の`self.sentBytes`/`self.receivedBytes`は実質デッドなフィールドで、どこからも
   参照・表示されていなかった)を一歩進めて実装した形になる。
6. ~~**onionpeer自己announceの定期再送・TTL見直し**~~: 2026-08-24完了(DESIGN-LOG.mdの該当セッション参照)。
   定期再送(peer_connector_threadへの相乗り、7380秒間隔)のみ実装し、TTL自体
   (2日)は意図的に変更していない(既存の安全マージンで十分と判断、DESIGN-LOG.mdの該当セッション参照)。
7. ~~**LAN内UDP broadcastによるpeer発見が無い**~~: 2026-08-24、ユーザーと相談の上で
   優先度をさらに下げ、末尾の項目10へ移動(詳細は項目10参照)。
8. ~~**ログレベル(DEBUG/INFO/WARN/ERROR)が無い**~~: 2026-08-24完了(DESIGN-LOG.mdの該当セッション参照)。
   `BM_LOG_LEVEL`環境変数(既定`INFO`)によるフィルタリングを実装し、約140箇所の
   呼び出しを全て`bm_log_debug/info/warn/error`へ移行した。
9. ~~**ASan/UBSan/TSanによるメモリリーク・バッファオーバーフロー・メモリ管理ミス・
   データ競合の検査体制が無い**~~: 2026-08-24完了(DESIGN-LOG.mdの該当セッション参照)。ASan/UBSanで
   テストハーネスのリーク2件、TSanで`stop_flag`のスレッド間可視性問題と
   dandelion/peer_registry間のロック順序逆転(潜在的デッドロック)を発見・修正した。
   いずれもCIへ別ジョブとして統合済み。
10. ~~**Releaseビルドでのテスト・インストール・systemdサービス化が未着手**~~:
    2026-08-23にユーザーと議論。2026-08-24にユーザーと合意の上で5つに分割し
    (依存順)、同日中に全て完了した:
    1. ~~Releaseビルド検証~~ 完了(DESIGN-LOG.mdの該当セッション参照)。`-DCMAKE_BUILD_TYPE=Release`で
       初めて顕在化した警告(バグ1件含む)を修正し、`build-Debug`/`build-Release`/
       `build-Sanitize`/`build-TSan`全てクリーンビルドで警告ゼロ・ctest全通過を確認した。
    2. ~~DBファイル置き場をCWD依存から固定パスへ切り替える設計判断~~ 完了(上記まとめ
       参照)。既定はCWDのまま据え置き、`BM_DATA_DIR`環境変数で明示的に上書き可能にする
       非破壊的な方式にした(既存のdaemon Aへの影響ゼロ)。
    3. ~~`cmake --install`用の`install()`定義~~ 完了(DESIGN-LOG.mdの該当セッション参照)。GNUInstallDirsで
       `bitmessaged`/`bitmessage-cli`/`seeds/observed_nodes.txt`をインストールできる。
    4. ~~`.service`ユニットファイル作成~~ 完了(DESIGN-LOG.mdの該当セッション参照)。`systemd/bitmessaged.service`、
       `DynamicUser`+`StateDirectory`/`ConfigurationDirectory`でシステムユーザー・
       ディレクトリ作成を自動化、`Restart=on-failure`。当日夜に実装した
       `common/logging.c`の`JOURNAL_STREAM`自動判定は、まさにこのsystemd化を見越したもの。
       2026-08-25追記: `watchdog_daemon_a.sh`からの実移行検討時に、Tor ControlPort連携
       (`BM_TOR_CONTROL=1`)利用時は`DynamicUser`ユーザーが`debian-tor`グループに
       属さずControlPortソケットへアクセスできない問題と、`tor.service`への起動順序
       依存が無い問題が未対応だったことが判明、修正した(詳細はDESIGN-LOG.mdの
       該当セッション参照)。
    5. ~~非Ubuntu環境への軽い手当て~~ 完了(DESIGN-LOG.mdの該当セッション参照)。CIへFedoraでのビルド確認
       ジョブを追加、Tor control socket既定値のディストリ依存性をコメント/READMEへ
       明記。詳細は元の判断根拠含め下記参照。
    - **非Ubuntu環境への対応について**: `infra/network.c`が`epoll`(Linux固有API、POSIXでは
      ない)に依存しているため、macOS/BSDを含む「Unix全般への移植性」はそもそも設計上
      視野に入れていない(対応するなら`kqueue`バックエンド追加という別の大仕事になる)。
      現実的な論点は「Linuxのどのディストリまで」に限られる。実質Ubuntu前提になっている
      箇所: (a) CIが`ubuntu-latest`のみ(`.github/workflows/ci.yml`)、(b)
      `core/config_file.c`の既定値`tor_control_socket = "/run/tor/control"`
      (Debian/Ubuntu系のTorパッケージのデフォルトパスで、Fedora/Arch等は異なる可能性)。
      ビルド依存(OpenSSL/SQLite3/pthread)自体はどのディストリでもパッケージ名が違うだけで
      標準的に入手可能なため、大掛かりな対応は不要。CIにもう1ディストリ(Fedora等)を
      追加する、Tor control socketの既定値をドキュメントで明記する、程度の軽い手当てで
      十分と判断。
11. **LAN内UDP broadcastによるpeer発見が無い**(旧項目7、2026-08-24に優先順位を下げて
    ここへ移動): 2026-08-23にPyBitmessage本家を調査していて判明。`network/udp.py`の
    UDPSocketは実際に`connectionpool.py`から起動される機能で、死んだコードではない。
    同一LAN上のノードをUDPブロードキャストで発見する。以前ユーザーと「LAN discoveryは
    優先度低い」と合意していたが、それは「あなたの具体的なユースケース(自分のノード
    同士をLANで繋ぐ用途)には手動peer追加で十分」という判断であり、「PyBitmessage自体に
    存在しない」という前提ではなかった点を訂正(2026-08-23)。2026-08-24にユーザーと
    再度確認し、この訂正は優先度を上げる根拠にはならない(Tor onion peer運用が主軸の
    このプロジェクトではLAN discoveryはそもそもユースケース外)と判断、backlog内で
    さらに優先度を下げて末尾へ移動した。2026-08-24、ユーザーと再度確認し「当分
    着手しなくてよい」と明示的に合意(単なる優先度低ではなく、事実上の凍結扱い)。
12. **`core/crypto.c`のEC_KEY/ECDSA系をEVP_PKEYベースAPIへ移行**: 2026-08-24、
    backlog項目10(Releaseビルド検証)着手中に発覚。`EC_KEY_new_by_curve_name`/
    `EC_KEY_set_private_key`/`o2i_ECPublicKey`/`ECDSA_size`/`ECDSA_sign`/
    `ECDSA_verify`/`EC_KEY_free`がOpenSSL 3.0で非推奨(`-Wdeprecated-declarations`)。
    現状は`build_ec_key`〜`bm_crypto_verify`の範囲を`#pragma GCC diagnostic ignored`
    で局所的に警告抑制して凌いでいる(署名結果はビット単位で同一かつAPI自体は当面
    removeされない見込みのため、というのが既存の判断、DESIGN-LOG.mdの該当セッション参照)。将来的に
    OpenSSLがこれらのAPIを実際に削除する場合に備え、`EVP_PKEY_new_raw_private_key`
    (secp256k1)+`EVP_DigestSign`/`EVP_DigestVerify`ベースへの書き換えが必要になる。
    ECIES側(`ecdh_shared_secret`等)にも同様のEC_KEY依存が無いか要確認。署名アルゴリズム
    自体を変えない書き換えなので理論上は機械的だが、鍵管理・エラーハンドリング含め
    署名・検証という認証の根幹に関わるコードのため、慎重なテスト(既存署名データとの
    後方互換確認含む)が要る。優先度低(OpenSSLが実際に削除を予告するまでは急がない)。
    2026-08-24、ユーザーと再度確認し「当分着手しなくてよい」と明示的に合意(単なる
    優先度低ではなく、事実上の凍結扱い。OpenSSLが実際に非推奨APIの削除を予告する等、
    状況が変わるまでは見送る)。
13. **系統的なセキュリティレビューが未着手**: 2026-08-24、ユーザーから「脆弱性チェックは
    終わったと判定していいのか」と問われて発覚。backlog項目9(ASan/UBSan/TSan)は
    あくまでメモリ安全性(メモリ破壊・UB・データ競合)の検査であり、脆弱性チェック
    全般ではない。同日、軽くコードを見ただけで`src/cli/http_client.c`の
    `bm_http_post_json`のリクエストバッファ確保サイズがhostの長さを考慮していない
    問題(実際には`connect_to`のIPv4形式チェックにより到達不能と判明、念のため
    防御的に修正・テスト追加済み、DESIGN-LOG.mdの該当セッション参照)が見つかったのが
    その端緒。系統的なレビューはまだしていない。優先度を検討すべき観点:
    - **P2Pメッセージパーサ群**(`infra/protocol.c`・`infra/object.c`・
      `infra/object_sync.c`等)がこのプロジェクトの本来の脅威モデルの中心
      (untrustedな実ネットワークからの入力を直接パースする)であり、最優先で見るべき
      箇所。既存のDoS対策(申告lengthの上限チェック等)はあるが、個々のフィールド
      パース処理(varint/varstr展開、objectヘッダ解析等)の境界値・不正値に対する
      堅牢性を体系的に確認したことはない
    - 認証まわり(`core/api_server.c`のBasic認証、既に定数時間比較は実装済み)の
      再確認
    - SQLクエリの組み立て方(ざっと見た限り`sqlite3_bind_*`によるパラメータバインドが
      徹底されており、文字列結合によるSQL構築は見当たらなかったが、全箇所の
      網羅確認はしていない)
    - 秘密鍵等の機密情報がログ・エラーメッセージ・core dumpに漏れていないか
    - 依存ライブラリ(OpenSSL/SQLite3)のバージョン・既知CVEの確認
14. **`peers.db`の再シード条件が厳しすぎる**: 2026-08-24〜25、Releaseビルドへ切り替えて
    長期運用テストを開始した直後、ユーザーから「selfの他に3件しかpeerが残っていない」と
    報告を受けて発覚。`bm_peer_manager_cleanup`(28日間音信不通、または3時間以上音信不通
    かつ`rating<=-0.5`のホストを削除)自体は正しく動作しており、daemonが長時間停止していた
    間にratingの悪いpeerがまとめて削除された結果だった(データ消失やバグではない)。
    ただし`bm_peer_manager_seed_bootstrap`(ブートストラップシード再投入)は
    `hosts`テーブルが**完全に空(0件)の時だけ**発動する設計になっており、「self以外に
    数件しか残っていない」ような実質的にほぼ空の状態を救済できない。残った数件が
    同時に不通になった場合、自力で回復できなくなるリスクがある。閾値を`==0`から
    「一定数未満(例: <3〜5)」へ緩める等の対応を検討する。優先度は中程度(実際には
    addr/onionpeer受信で徐々にpeerが増えていくため即座に詰むわけではないが、
    レジリエンスの観点で改善余地がある)。
16. ~~**join-chan(=unlock)する前に既にobject_pool.dbへ届いていたchan宛msgオブジェクト
    (過去ログ)が、unlock後も自動でinboxに現れない**~~: 2026-08-25完了。ユーザーから
    「`join-chan`したときに`object_pool`から対象chan宛のメッセージをルックアップする
    処理を作っていたか」と問われて発覚。調査の結果、通常の受信フロー
    (`infra/object_sync.c`の`handle_object`)はBM_OBJECT_MSGオブジェクトを**新規受信した
    瞬間に一度だけ**`bm_trial_decrypt_and_store`(`core/trial_decrypt.c`)を試す設計で、
    keyring中の全unlocked identityを順に試すため以後届く投稿は自動的に拾えるが、
    「そのchan鍵をunlockする前から既にobject_pool.dbに保存されていた(復号できずに
    残っている)msgオブジェクト」を後から再走査する経路が存在しなかった。加えて
    `joinChan` API(`core/api_server.c`の`h_joinChan`)自体はDBへidentityを保存する
    だけでkeyring(メモリ上のunlocked list)には載せないため、trial_decryptが意味を
    持つのは実際には`unlockAddress`のタイミングだと判明した(DESIGN-LOG.mdの
    2026-08-21付chan仕様セッション時点でも「chan用の鍵をunlockしてさえいれば新規の
    受信処理は不要」と書かれていた通り、"新規"受信のみを想定した設計だった)。
    対応として、`infra/object_store.c`に`bm_object_store_list_hashes_by_type`
    (指定object_typeのhashを期限切れ含め全件列挙、既存の`list_hashes_by_stream`と
    同型)を追加、`infra/object_sync.c`に`bm_object_sync_backfill_trial_decrypt`
    (object_pool_db中の全MSGオブジェクトをkrの現在unlocked全identityで再トライアル
    復号し、成功分をmessages_db inboxへ挿入。`bm_messages_store_insert_inbox`が
    msg_idユニーク制約でIGNORE済みのため複数回呼んでも重複挿入されない)を新設し、
    `core/api_server.c`の`h_unlockAddress`がunlock成功直後に呼ぶよう配線した
    (`bm_api_server_config`へ`object_pool_db`フィールドを追加、NULL可でtest/CLI単体
    動作には影響しない)。専用スレッドは新設していない(CLAUDE.mdの方針通り、
    unlockAddressという既存の同期APIハンドラ内で完結する処理のため、そもそも周期
    ポーリングの対象ではない)。埋め込みack_payload(§5.5)の検証・再送はスコープ外とした
    (api_server.cからの呼び出しには生きたpeer接続/peer_registryが無いため。送信元への
    ack配送が遅れる可能性はあるが、「chan参加前の過去ログが読めるようになる」ことを
    優先し許容)。`tests/test_chan.c`にシナリオ5として、Bがunlockする前にAが投稿した
    msgオブジェクトを直接object_pool_db_bへ挿入し、unlock後の`bm_object_sync_backfill_
    trial_decrypt`で1件だけ復号されinboxに正しい内容(subject/body)で現れること、
    再実行しても重複挿入されないことを確認するテストを追加。なお本項目は`join-chan`
    という通常identityでも起きうる一般的な問題への対応であり、chan専用の修正では
    ない(unlockAddress全般に対して効く)。ctest 39件全通過。
17. Dandelion++・inbound接続・outbound addrメッセージ送信・inbound接続のアイドル/
    ハンドシェイクタイムアウト+keepalive ping・inbound接続のレート制限・
    プロトコルバージョン互換性チェック・version messageのtimestamp検証・
    listConnections API(MVP)・onionpeer自己announceの定期再送・ログレベル
    (DEBUG/INFO/WARN/ERROR)導入・ASan/UBSan/TSan導入(CI統合含む)・Releaseビルド
    検証/BM_DATA_DIR/cmake --install/systemdユニット/非Ubuntu環境への軽い手当て
    (計5分割)はいずれも完了(DESIGN-LOG.mdの該当セッション参照)。GPU/OpenCL PoWは§8で明示的にv1スコープ外と
    決めた項目のため対象外(引き続き見送り)。
18. ~~**送信済みボックス(sentテーブル)を一覧する手段が無い**~~: 2026-08-25完了
    (DESIGN-LOG.mdの該当セッション参照)。watchdog_daemon_a.shからsystemdへの移行作業を
    やり取りしていた流れでユーザーから「そういえば送信済みボックスが無い」と指摘され
    発覚。`messages.db`の`sent`テーブル自体は§2.4の設計時から存在したが、実際の用途は
    ack追跡・再送判定(`bm_messages_store_list_resend_candidates`)専用で、
    `get-inbox`/`getInboxMessages`に相当するユーザー向けの一覧経路が丸ごと無かった
    (過去の議論・backlog化の跡も無く、意図的な先送りではなく単純な実装漏れと判断)。
    `bm_messages_store_list_sent`(`core/messages_store.c`、`list_inbox`と同型、送信時刻降順)・
    `getSentMessages` API(`core/api_server.c`、`getInboxMessages`と同型)・`get-sent`
    CLIサブコマンド(`cli/main.c`)の3点を追加。`tests/test_api_server.c`に
    `getSentMessages`のテストを追加(既存の`sendMessage`テスト2件が同一`messages_db`へ
    実際の送信パイプライン経由で`sent`行を挿入済みのため、件数を決め打ちせず自分が
    挿入したmsgIdを配列内から探す形にした)。ctest 39件全通過。

19. ~~**アドレスロック形式(§7)が数千件規模の一括インポート運用に対して非現実的**~~:
    2026-08-29完了。vault方式(2段階KDF)による`unlockAllAddresses`を実装した。詳細は§7.4参照。
    以下は解決までの経緯(検討過程の記録として残す)。

    **アドレスロック形式(§7)が数千件規模の一括インポート運用に対して非現実的**:
    2026-08-25、ユーザーから「後々アドレスを数千件オーダーでインポートする予定が
    あるのにこの形式は面倒くさくてしょうがない」「インポートした後にも起動のたびに
    一つ一つunlockするのが面倒くさい」との指摘で発覚。現行設計(§7.1/§7.2)は
    `createDeterministicAddress`・`importAddress`(いずれも1アドレス1passphraseで
    KEKラッピングする前提、`importAddress`自体は2026-08-25時点でコード未実装)・
    `unlockAddress`(1アドレスずつpassphraseを渡して呼ぶAPI、DESIGN.md §6.2の表)を
    含め、すべて「アドレス単位でpassphraseを都度入力する」ことを前提にしている。
    数千件オーダーのアドレスを一括インポートし、かつdaemon再起動のたびにそれら全件を
    改めてunlockする運用は、この設計のままでは非現実的。対応方針は未定
    (ユーザーとの追加相談待ち、優先度も未検討)。検討候補: 単一のマスター
    passphrase/共通KEKで複数アドレスをまとめてラップ・unlockする一括API、
    起動時に一括unlockする仕組み、大量インポート専用の別の鍵保護方式の是非、等。
    §7の鍵ライフサイクル設計そのものに関わる決定のため、着手前に必ずユーザーと
    設計方針を合意すること。

    **2026-08-25追記(方向性の相談)**: ユーザーから「パスワード一つで全部のアドレスを
    unlockするようにするのはどう思うか。saltは別個のままでいいと思う」と相談があった。
    以下は検討結果(まだ合意・実装はしていない、設計メモとして記録):
    - saltをアドレスごとに分けたまま(=identity.dbのスキーマ変更不要、既存の`kdf_salt`列
      をそのまま使える)で、`unlockAllAddresses(passphrase)`のようなAPIを新設し、
      locked状態の全identityに対し「各行の`kdf_salt`でKEKを導出→AES-256-GCM復号を試す」を
      ループする案が最小の変更で済む。GCMタグ検証に失敗した行はエラー中断せず黙って
      スキップする設計にしておけば、将来一部のアドレスだけ別passphraseを使うケースが
      混在しても壊れない(「全アドレスが同一passphrase」を強制しない)。
    - ただし性能上の懸念がある。現行のscrypt(N=2^15,r=8,p=1、§7.1)は意図的に重く
      (1回あたり数十〜百数十ms、メモリ32MB)、これを行ごとに愚直に実行すると数千件では
      起動時の一括unlockが数分オーダーになりうる。「個別にunlockする面倒」を解消しても
      「起動時に数分固まる」という別の面倒が生じかねない。
    - 対策候補(salt別のままでも両立可能な2段階KDF): passphraseから重いKDF
      (scrypt/argon2id)を**1回だけ**実行してmaster KEKを導出し(salt=identity.db全体で
      共有する1個のvault salt)、各アドレスの実際のラッピング鍵はmaster KEKと
      **そのアドレス固有のsalt**を使った軽量なHKDF-Expandで導出する方式。これなら
      「saltはアドレスごとに別」という要望を保ったまま、重い計算を起動時1回に抑えられる。
      ただしidentity.dbのスキーマ変更(共有vault_salt列の追加、既存行の移行)を伴い、
      単純ループ案より実装コストは上がる。
    - 次のアクション案(未着手): まず単純ループ案で数千件相当のベンチを実測し、
      許容できない遅さであれば2段階KDF方式へ切り替える、という段階的な進め方を提案した。
      どちらで進めるかはユーザーとの合意待ち。

    **2026-08-25追記(exportAddressの欠落)**: ユーザーから「importということはexportも
    ですね」と指摘され発覚。§6.2の表には`importAddress`があるがexport側は表にもコードにも
    存在しない、という完全な抜けだった。`importAddress`と対称な設計にするのが自然:
    - `exportAddress(address, passphrase)`: passphraseでその行のKEKを導出しGCM復号、
      `signingWIF`/`encryptionWIF`を返す。`unlockAddress`とは独立させ、既存keyringには
      触らずその場限りで復号して返すだけの一回性操作にする(呼び出し元へ渡したら
      プロセス側では即破棄、keyring常駐はさせない)
    - 数千件の一括インポートと対になる「一括export(バックアップ用途)」も同じ理由で
      必要になるはずで、上記の一括unlock案(単一passphraseで各行のsaltを使って復号)と
      ほぼ同じロジックを流用できる
    - 注意点: WIFという平文の秘密鍵そのものを返す設計なので、ログ・エラーメッセージに
      絶対載せない配慮がpassphrase同様に必須
    - 「機能的にimportとexportはペアであるべき」とユーザーと合意。未実装・未着手、
      §7/§6.2の設計反映も含めて別途着手が必要。

**2026-08-26完了: outbound SOCKS5設定をonion peer専用/クリアネットIP専用に分離**。
以前は単一のsocks_proxy設定(config.db)を全outbound接続に適用しており、有効化すると
クリアネットIP宛の接続まで無条件でTor出口ノード経由になっていた。これがTor出口ノードの
共有IPゆえのレート制限("Too many connections from your IP"等)を招き、外部ノードへの
接続性を悪化させていた原因だった。PyBitmessage本家(`network/connectionpool.py`の
`socksproxytype`/`onionsocksproxytype`分離)に合わせ、`config_store.c`の
`socks_proxy`(onion専用に意味を絞った、既存設定はそのまま引き継がれる)と新設の
`socks_proxy_clearnet`(既定disabled=直結)へ分離。`peer_connector.c`が接続先の
`.onion`サフィックスで使う設定を選択する。API(`getSocksProxyOnion`/`Clearnet`等)・
CLI(`get/set-socks-proxy-onion`/`-clearnet`)も追随。詳細な調査経緯はDESIGN-LOG.md
「outbound SOCKS5設定をonion peer専用/クリアネットIP専用に分離」参照。

**2026-08-26完了: big invのチャンク分割+ペーシング**。上記のSOCKS5分離後もdaemon Aの
接続性が改善せず、tcpdumpで調査した結果、`send_big_inv`(handshake直後に自分が保有する
全objectのhashを一括送信)が原因と判明した。1万件超(260KB超)を無間隔で送ると、相手
(実測: `PyBitmessage:0.6.3.2`)のTCP受信ウィンドウが数秒でゼロまで埋まり、相手から
RSTで強制切断される(受信は完了しているのでフォーマット破損ではなく、相手のアプリ層の
処理待ちバッファ枯渇)ことを複数接続で確認した。`sleep()`でチャンク間隔を空けると
`network_epoll_thread`(単一スレッドで全接続を処理)が丸ごと止まってしまうため、
専用スレッドを新設せず既存の1秒間隔ポーリング(`bm_network_idle_sweep`)に相乗りさせる
既存方針に倣い、`struct bm_fd_data`へ送信途中状態を保持させる非同期チャンク送信
(`bm_network_begin_big_inv`、`BM_BIG_INV_CHUNK_SIZE`=1000件・`BM_BIG_INV_CHUNK_
INTERVAL_SECONDS`=1秒)に変更した。詳細はDESIGN-LOG.md「big invのチャンク分割+
ペーシング」参照。

**2026-08-26完了: verack交換完了直後のaddr/big inv送信をBM_VERACK_REPLY_DELAY_
SECONDS(5秒)遅らせるよう変更**。上記のペーシングを反映してもdaemon Aの即切断率が
ほぼ改善しなかったため、内容(addr単体/inv単体/1件のみ等)を変えて切り分ける診断実験を
行った結果、送信する内容や量ではなく「verack交換完了直後という早すぎるタイミングで
能動的に何か送り返すこと自体」が相手からの即時切断を誘発していると判明した(即切断率
99%→5秒遅延で6%まで改善、study/src/bm.cが同じ相手に対し何も送り返さず切られたことが
無かった観察が調査の端緒)。`bm_object_sync_dispatch`のverackハンドラは実際の送信を
即座に行わず`conn->pending_verack_reply_at`(`network.h`)へ記録するだけにし、
`bm_object_sync_flush_pending_verack_replies`(peer_connector_threadの既存1秒間隔
ポーリングに相乗り)が期限到来後に実際の送信を行う。詳細な調査経緯(tcpdump解析・
診断実験の全結果)はDESIGN-LOG.md「verack直後のaddr/big inv送信を遅延させる」参照。

調査の過程で判明した副次的な既知差分(今回の主要因ではないと確認済み、backlog):
- こちらのversion messageのservicesが`BM_SERVICE_NODE_DANDELION`のみで、本家が
  常に立てる`NODE_NETWORK`(=1)を立てていない(`protocol.c`の`bm_create_version_
  payload`)。実害未確認だが本家準拠に寄せる余地がある。
- こちらのuser agentは`/BitmessageC:x.y.z/`に修正済み(旧`/bitmessage-c:x.y.z/`は
  ハイフンのせいで本家のuser agent検証正規表現にマッチせず`/INVALID:0/`扱いされて
  いた、2026-08-26修正)。
- ~~`pong`受信が`bm_object_sync_dispatch`で専用ハンドラを持たず"unhandled command"
  ログに落ちている~~: 2026-08-26完了。専用の空ハンドラ(NOP)を追加した
  (PyBitmessage本家の`bm_command_pong`も無視するだけ)。ついでに調査した結果、
  ping/pongはTCP自体のタイムアウト回避ではなく、経路上のNAT/ファイアウォールが
  無通信の接続を勝手に切るのを防ぐキープアライブであり、このプロジェクト・本家とも
  「pongが実際に返ってきたか」で生死判定して切断するロジックは持たない(生死判定は
  TCPレベルの読み取りエラーRST/EOFにのみ依存する)ことを確認した。

**2026-08-26調査: big invチャンク送信失敗(`failed to send big-inv chunk`警告)の原因**。
v1.3.0リリース後にdaemon Aのログを見ていて、上記のチャンク分割+ペーシング送信
導入後もこの警告が散発している(過去複数プロセスの起動を通じて計12回)ことに気付いた。
journalctlで各発生の前後ログを個別に確認した結果、12件全てで`failed to send
big-inv chunk`の直後(同秒〜数秒以内)に同じ接続(または同時にqueueされていた別の
接続)が`closing outbound connection: peer closed (EOF)`または`read error`
(`Connection reset by peer`)で切断されているという相関が確認できた。これは新設した
チャンク分割機能固有のバグというより、「相手が既に切断済み/切断中の接続へ、1秒間隔の
ペーシングループが後続チャンクを送ろうとして空振りする」自然な現象である可能性が高いと
判断した。残りhashを相手に伝えられないだけで、相手はその後addr/inv経由で自然に
補完できる範囲のため実害は小さいと見ている。

ただし従来の`bm_network_write_all`(`infra/network.c`)は失敗理由(タイムアウトか、
相手切断EOFか、その他のwrite()エラーか)を呼び出し元に返しておらず、`send_inv_chunk`の
ログにもどのpeer(host:port/fd)への送信だったかが含まれていなかったため、上記の判断は
あくまでログの前後relationからの推測にとどまっていた。原因究明の確度を上げるため、
`bm_network_write_all`に`reason_buf`/`reason_buf_len`引数を追加し(不要な呼び出し元は
`NULL, 0`を渡せばよい後方互換な拡張)、失敗時に「timeout (Ns)」「select: <strerror>」
「peer closed (EOF)」「write: <strerror>」のいずれかをNUL終端で書き込むようにした。
`send_inv_chunk`はこれと`bm_network_resolve_peer_ip_port`を使い、
`failed to send big-inv chunk to <host>:<port> (fd=<fd>): <reason>, dropping
remaining N hash(es)`という形でどのpeerへのどの理由の失敗かを直接ログへ残すよう
変更した。`tests/test_network_testnet.c`の`test_network_write_all`(タイムアウトで
諦めるケース)にも、`reason_buf`が実際に"timeout"を含むことを確認するアサーションを
追加した。次に発生した際はログから直接原因が分かるはずなので、実際に相手切断以外の
理由(例えばselect()エラーやEAGAIN以外のwrite()エラー)が頻発するようなら、その時点で
改めて対応を検討する。ctest 39件全通過。

**2026-08-23調査時に「あるように見えて実は無い」と判明したもの(参考、backlog対象外)**:
`protocol.py`の`OBJECT_I2P`/`OBJECT_ADDR`というobject type定数、`knownnodes.dns()`という
DNS bootstrap関数(`bootstrap8444.bitmessage.org`等)は、いずれも定義はあるがPyBitmessage
自体のどこからも呼ばれておらず、本家で未実装のまま放置されている死んだコードだった。
今後追いかける必要は無い。

**対応しないと決めたもの(参考、backlogではなく明示的な非対応判断):**
- `bm_post_version`の`addr_recv`/`addr_from`がSOCKS5経由で不正確(検証・利用している
  実装が見当たらず実害が無いと判断)
- SOCKS5クライアント認証(Tor自体がSocksPortに認証を要求しないため実質価値が薄い)
- Namecoin RPC連携(`.bit`アドレス解決)・帯域制限・blacklist/whitelistフィルタリング
  (いずれも別途大きな機能が必要なため見送り)
- `NODE_SSL`(接続全体を認証なしTLSで包む本家プロトコルのオプション、2026-08-23に
  議論): 実装しない。認証なし(自己署名・cert pinningなし)TLSは受動的盗聴や
  DPIフィンガープリンティングは防げても能動的MITMは防げず、しかもBitmessageの
  payload自体は既にECIESでend-to-end暗号化済みのため、得られる効果は接続メタデータの
  秘匿程度に限られる。それなら「メタデータも含めて隠したいなら、相手アドレス自体が
  自己認証になるTorを使ってくれ」というスタンスの方が一貫しており、TLSハンドシェイク・
  証明書生成まわりの実装/保守コストも避けられる。outbound SOCKS5・inbound onion対応が
  既にあるため、この判断でも実用上のデメリットは小さい。

**2026-08-29完了: keys.datインポート・API経由の秘密鍵インポート(WIF)・アドレス帳操作**。
ユーザーからの質問で「いずれも未実装」と発覚(調査時点の詳細は元の記述として下記に残す)。
まず一括unlockの性能問題(§7.4、上記19番で解決)を先に片付けた上で、以下を実装した:

- `bm_address_decode_wif`(`src/core/address.c`): WIF文字列→秘密鍵のデコード関数を新設
  (PyBitmessage `highlevelcrypto.decodeWalletImportFormat`準拠、0x80プレフィックス+32byte+
  4byteチェックサム、圧縮鍵フラグは扱わない)。既存の`bm_address_encode_wif`と対になる
- `importAddress`(§6.2表参照、`src/core/api_server.c`): address文字列も引数に取る形へ確定
  (WIFは秘密鍵のみでaddressVersion/streamを含まないため)。addressから復元したripeと
  WIFの公開鍵から計算したripeが一致するか検証してから保存する。PyBitmessage本家調査
  (`/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`)の結果、本家にはWIFを
  直接インポートするAPI/UIが存在しない(決定論的/ランダム生成経由の保存のみ)と確認済みで、
  本実装独自の拡張
- `exportAddress`(`address, passphrase`): importAddressと対称。2026-08-25に合意済みだった
  「importとexportはペアであるべき」への対応。unlockAddressとは独立し、keyringに触れず
  その場限りで復号してWIFを返す一回性操作。vault-hkdf/scrypt両方式に対応
- アドレス帳CRUD(`bm_messages_store_add/remove/list_address_book_entry`、
  `addAddressBookEntry`/`deleteAddressBookEntry`/`listAddressBookEntries` API):
  PyBitmessage本家`api.py`の同名メソッド準拠(addは重複禁止、deleteは冪等、base64ラップは
  JSON-RPCでは不要なため省略)
- `import-keys-dat <path> <storePassphrase>`(CLI、`src/cli/main.c`): keys.dat(PyBitmessage
  本家、INI形式)を丸ごと一括インポートする簡易INIパーサ。**daemonのHTTPリクエストボディには
  1MiBのDoS対策上限(`MAX_REQUEST_SIZE`)があり、1.5MB規模のkeys.datをAPI越しに丸ごと送る
  方式は取れない**と判明したため、CLI側でINIをパースしアドレスごとに`importAddress`を
  個別に呼ぶ方式にした(ユーザーと合意)。`[bitmessagesettings]`等の特殊セクションは無視し
  セクション名が`"BM-"`で始まるものだけをアドレスとして扱う(PyBitmessage本家
  `bmconfigparser.py`の`addresses()`と同じ判定)。storePassphraseは全件で共通の1つを使う
  (§7.4のvault方式が単一passphraseでの一括unlockを前提にしているため)
- `call_rpc`(CLI)の内部実装を`call_rpc_raw`(HTTP送受信+エラー判定のみ、結果printfはしない)
  へ抽出し、5000件規模のループから静かに呼べるようにした
- `isChan`(`importAddress`/keys.datの`chan = true`キー): ユーザーの指摘で発覚。当初の
  `import-keys-dat`実装はkeys.datの`chan`キーを読んでおらず、chanアドレスも`is_chan=0`の
  通常アドレスとしてインポートされていた。`importAddress`に`isChan`引数を追加し
  (成功後`bm_keyring_mark_as_chan`を呼ぶ)、CLIのINIパーサに`chan`キー認識を追加した
- `importAddressesBulk`(§7.5参照): importAddressを1件ずつ個別のHTTPリクエストで呼ぶと
  リクエストのたびにvaultのmaster KEK導出(scrypt)が再実行されてしまいvault化の効果が
  出ない問題への対応。CLIの`import-keys-dat`はこちらを`KEYS_DAT_BATCH_SIZE`(300)件ずつ
  呼ぶ方式に変更した
- version2/3アドレスのdecode寛容化(§3.3追記参照): 5143件規模の実keys.datを使った実地検証で、
  4byte分のゼロを圧縮した非正規のversion3アドレスが実在すると判明し、`bm_address_decode`の
  ゼロパディングを2byte固定の3ケース限定から可変長(0〜20byte)に一般化した

いずれも`tests/test_api_server.c`(importAddress/exportAddress のend-to-end検証、WIF不一致の
拒否含む)・`tests/test_address_book.c`(新設、CRUD単体テスト)・`tests/test_cli_integration.sh`
(export→delete→import-address→unlockの往復、import-keys-datのファイル経由インポート、
chan=trueの再現、アドレス帳CRUDのCLI配線)・`tests/test_address_vectors.c`(非正規version3
アドレスのdecode救済)でカバーした。ctest 41件全通過。

**実地検証(2026-08-29、ユーザー提供の実keys.dat、5143件・1.5MB)**: `import-keys-dat`で
約15秒(5142件成功、1件は既知の重複エントリとして意図的にスキップ対象、§3.3追記参照)、
続く`unlock-all`で0.6秒(vault方式、全件が最初からvault-hkdfで保存されているため)。
§11-19発端の「5000件規模のkeys.datインポート・一括unlock」という当初目標を実測で達成した。

以下、調査時点(2026-08-29着手前)の記録:
ユーザーからの質問で発覚。PyBitmessageの`keys.dat`(INI形式)を読み込んでアドレスをインポートする機能は
コード上どこにも無く、`bitmessage.conf`(本実装独自の起動設定ファイル)とは別物。§6.2の表にある
`importAddress`(signingWIF, encryptionWIF, storePassphrase)もコード未実装で、土台となるWIF文字列→
秘密鍵のデコード関数自体が無い(`src/core/address.c`にあるのはエクスポート方向の`bm_address_encode_wif`
のみ)。`address_book`テーブル(`messages_store.c`)もCREATE TABLEのスキーマ定義のみで、追加・削除・
一覧のCRUD関数もAPIハンドラも一切無い(同型の`subscriptions`は`addSubscription`等まで完成済みなのと対照的)。
この調査の過程で「keys.datバックアップ(1.5MB、5000件規模のアドレス)が見つかった」という話になった。

**vault管理系ライフサイクルAPI群(未着手、2026-08-29バックログ化)**: §7.4のvault方式実装後、
ユーザーから「マスターパスフレーズの変更ができない」「変更できるなら対称的に無効化(個別管理方式へ
戻す)もできないと筋が通らない」との指摘があり、いずれも現行実装に無いことを確認した。具体的には:
- `changeMasterPassphrase(oldPassphrase, newPassphrase)`: 全`vault-hkdf`行を旧passphraseで
  unlockし直し、新しい`vault_salt`/`canary`を作成、全行を新master KEKでre-wrapする
- vault方式の無効化: 全`vault-hkdf`行を個別scrypt方式へ戻す、または`kdf_vault`行自体を削除する手段

いずれも既存の`unlockAllAddresses`の機能には影響しないため、別セッションで着手する方針。

**2026-08-30完了: trashMessage API/CLI**。ユーザーからの質問「PyBitmessage本家の`trashMessage`
相当のAPIは作っていなかったか」で発覚(メッセージ関連APIは`sendMessage`/`sendBroadcast`/
`getInboxMessages`/`getSentMessages`のみで、削除系が未実装だった)。実装方針についてユーザーと
2回相談した:

1. 「物理削除か論理削除か」→当初「inboxのみ物理削除」と合意しかけたが、`inbox`テーブルの
   `folder`列(`'inbox'|'trash'`、§2.4で当初から定義済み)がまさにこの用途のために用意されて
   いたこと、`getInboxMessages`も`folder`引数で絞り込み可能なことにユーザーが気付き、
   PyBitmessage本家api.pyの実ソース確認(`HandleTrashMessage`は`helper_inbox.trash(msgid)`+
   `UPDATE sent SET folder='trash' WHERE msgid=?`という論理削除)で本家も同じ設計と確認できた
   ため、論理削除(`folder='trash'`更新)へ方針転換した
2. 「実装範囲」→本家には`trashMessage`(inbox/sent両対応)/`trashInboxMessage`/`trashSentMessage`/
   `trashSentMessageByAckData`の4種があるが、まず`trashMessage`のみを移植する方針で合意
   (inbox/sent個別指定用の3種は必要になったら追加)

実装内容:
- `sent`テーブルに`folder TEXT NOT NULL DEFAULT 'sent'`列を追加(新規は`CREATE TABLE`、既存DBは
  `peer_manager.c`の`is_self`追加時と同じ`ALTER TABLE ... ADD COLUMN`パターンで後付け)。
  従来`sent`にはfolder概念が無く(DESIGN-LOG.md参照)、trash化した行を隠す手段が無かったため
- `bm_messages_store_trash_inbox_message`/`bm_messages_store_trash_sent_message`
  (`messages_store.c`): それぞれ`UPDATE inbox/sent SET folder='trash' WHERE msg_id=?1`。
  該当行が無くてもエラーにしない(本家の「存在したと仮定して削除した」という応答仕様に合わせる)
- `bm_messages_store_list_sent`のSQLに`WHERE folder = 'sent'`を追加。追加しないとtrash化しても
  `getSentMessages`から消えず実質何も隠せないため(`getInboxMessages`は元々`folder_filter`引数が
  あるのでこちらは変更不要、無指定なら全件・`'inbox'`指定でtrashを除外できる)
- `trashMessage`API(`api_server.c`)・`trash-message`CLIサブコマンド(`main.c`): `[msgId(hex)]`を
  受け取り、inbox/sent両方に対して上記2関数を無条件に呼ぶ(呼び出し側はmsgIdがinbox由来か
  sent由来か意識しなくてよい、本家と同じ構成)。SQL自体が失敗した場合のみエラーを返す
- `tests/test_api_server.c`に追記: inbox/sent双方への適用、存在しないmsgIdでもエラーにならない
  こと、不正な長さのhexはエラーになること、`getInboxMessages(['inbox'])`から消えて無指定では
  `folder='trash'`として残ること、`getSentMessages`から消えることを検証。ctest 41件全通過

**2026-08-30完了: sendMessageからtoPubEncryptionHex引数を廃止(pubkey_cache経由に一本化)**。
ユーザーから「toaddressと一致しないpubEncHexを渡したときって考慮に入ってましたっけ?」と
指摘され発覚。`api_server.c`のh_sendMessage・`send_pipeline.c`のいずれも、直接渡された
`toPubEncryptionHex`が`toAddress`のripeと対応するかの検証(渡された鍵から
`ripe=RIPEMD160(SHA512(pub_signing||pub_encryption))`を計算してaddressのripeと突き合わせる)を
一切行っていなかった。実害は2点: ①toAddressと無関係な鍵で暗号化してしまう(意図した相手が
復号できない、あるいはなりすまし鍵なら盗聴されうる)、②検証されない鍵がそのまま
`send_pipeline.c`の自動upsertで`pubkey_cache`へ書き込まれ、以後の`toPubEncryptionHex`省略の
送信も汚染する(本物のpubkeyオブジェクトがネットワークから届けば`object_sync.c`側で無条件に
上書きされるため恒久的ではないが、届くまでの間は誤った鍵が使われ続ける)。

ユーザーからtoPubEncryptionHex自体を引数から外す提案があり、「段階を踏んで完全削除」する
方針で合意。`cachePubkey`側にも同種の検証漏れ(`address, signingPubkeyHex, encryptionPubkeyHex`
を全部受け取るのでripe再計算による検証は可能)があるが、こちらは今回スコープ外とし別件の
backlogとして記録するに留めた(下記backlog項目20参照)。

実装内容:
- `api_server.c`の`sendMessage`パラメータを`[fromAddress, toAddress, toPubEncryptionHex|null,
  subject, body, ttlSeconds?, ackStealthLevel?]`から`[fromAddress, toAddress, subject, body,
  ttlSeconds?, ackStealthLevel?]`へ変更。宛先の鍵は常に`pubkey_cache`から解決し、未登録なら
  従来通りgetpubkey要求を自動broadcastして失敗を返す(§5.0)
- `cli/main.c`の`send-message`サブコマンドから`<toPubEncryptionHex|->`引数を削除
  (`<fromAddress> <toAddress> <subject> <body> [ttlSeconds] [ackStealthLevel]`に変更)
- `send_pipeline.c`の`bm_send_pipeline_send_message`自体のシグネチャからも`to_pub_encryption`
  引数を削除した(API層だけでなく内部関数のレベルで直接pubkey送信の経路自体を廃止)。常に
  「to_address==from_addressならfrom_id自身のpub_encryption(chan投稿)、それ以外は
  pubkey_cache参照」のみを行う。これに伴い、直接pubkey送信成功時の自動upsertロジック
  (2026-08-23実装分、DESIGN-LOG.md参照)も不要になったため削除した
- `object_sync.c`の再送呼び出し・`api_server.c`のsendMessage呼び出しを新シグネチャに追従
- `tests/test_send_pipeline.c`/`test_resend.c`/`test_object_sync.c`: 直接pubkey渡しで送信して
  いた箇所を、送信前に`bm_pubkey_cache_upsert`で明示的に登録してから送るよう書き換え。
  直接pubkey送信の自動upsertを検証していたcaseは削除(経路自体が無くなったため)
- `tests/test_chan.c`: 自分自身宛(chan投稿)の呼び出しはcache不要のfallbackで変わらず動くため、
  削除された引数を取り除くだけで済んだ
- `tests/test_api_server.c`: 直接pubkey指定でのsendMessage+自動upsert検証を、
  「pubkey_cache未登録の宛先へのsendMessageはエラーになる」検証に置き換えたうえで、
  `cachePubkey`+`sendMessage`(pubkey_cache経由)のテストは維持
- `tests/test_cli_integration.sh`: 130hex桁数不正・非curve point pubkeyのエラー検証(引数自体が
  無くなったため意味を失った)を、「pubkey_cache未登録の宛先へのsend-messageはエラーになる」
  検証に置き換え。`send-message ... "-"`(cache利用の合図)も不要になったため削除
- ctest 41件全通過

出典・詳細はこのファイル内の各章の実装状況ノートを参照(pubkey_cacheは§2.3、send_pipeline/ackは
§5末尾、object_sync_threadは§1、api_serverは§6.1末尾)。

### backlogへの追記(2026-08-30)

20. **`cachePubkey`にripe整合性検証が無い**: 上記sendMessageのtoPubEncryptionHex削除と同時に
    発覚した別件。`cachePubkey([address, signingPubkeyHex, encryptionPubkeyHex])`は、渡された
    `signing_pubkey`/`encryption_pubkey`から`ripe=RIPEMD160(SHA512(signing||encryption))`を
    計算し`address`をデコードして得たripeと突き合わせる検証を一切行っていない(こちらは
    `sendMessage`の直接指定パスと違い`pub_signing`も引数にあるため、検証は技術的に可能)。
    誤った/なりすましの鍵をユーザーが手動登録してしまうリスクは残るが、`sendMessage`と違い
    「ユーザーが意図して明示的に登録する」操作である点、および本件のセッションでは
    スコープ外として見送る合意になった点を踏まえ、優先度は低めとして次点に置く。

### backlogへの追記(2026-08-31)

21. **unlockAddress後のbackfill_trial_decryptがkeyring全体を対象にしていた問題を修正**:
    unlock-all(§7.4のlazy migration経由でも使われる`unlockAllAddresses`)で数千件規模の
    identityを既にunlockedにしてある状態で、単体の`unlockAddress`(join-chan後の初回unlock含む)
    を1件叩くと、`h_unlockAddress`が呼ぶ`bm_object_sync_backfill_trial_decrypt`
    (§11 2026-08-25追加、object_pool.db中の未復号MSGオブジェクトを再走査する処理)が
    `bm_trial_decrypt_msg`経由でkeyring内の**現在unlockedな全identity**に対してECIES復号を
    総当たりしていたことが発覚した。実運用(ユーザー環境: unlock-all済みでidentity 5000件超、
    object_pool.db内MSGオブジェクト約11000件)で、単体unlockAddress 1回が
    「11000×5000+ ≒ 5500万回のECDH試行」となり9時間以上完了しなかった。しかも
    api_server.cのRPCサーバーは完全シングルスレッド(`accept()`直後に
    `bm_api_server_handle_connection`を同期呼び出しするだけで、リクエストごとのスレッド分岐が
    無い)のため、この間`listAddresses`のような無関係な読み取り専用RPCすら一切応答不能になる
    ことを実測で確認した(`bitmessage-cli list-addresses`が10秒timeoutで無応答、デーモンの
    CPU時間はunlock開始からの経過時間とほぼ一致する速度で伸び続けていた)。

    対策として、`bm_trial_decrypt_msg`/`bm_trial_decrypt_and_store`のヘッダ解析・ECIES復号後の
    共通処理を`trial_decrypt_body`(trial_decrypt.c、static)へ切り出した上で、単一identity限定版
    `bm_trial_decrypt_msg_single`/`bm_trial_decrypt_and_store_single`(trial_decrypt.h/.c)を追加。
    `bm_object_sync_backfill_trial_decrypt`(object_sync.h/.c)に`address_filter`引数を追加し、
    NULLなら従来通りkeyring全体(将来的にunlock-all等、複数identityへの一括backfillが要る
    場面向けに温存)、非NULLならその1アドレスのみ`bm_keyring_find_by_address`で解決して単一
    identity版を使うようにした。`core/api_server.c`の`h_unlockAddress`は今回unlockした
    address自身を渡すよう変更し、これによりunlockAddress 1回あたりのコストを
    「MSGオブジェクト数×既存unlockedアドレス数」から「MSGオブジェクト数×1」に戻した。
    `h_unlockAllAddresses`はそもそもbackfillを呼ばない設計(§11 2026-08-29のコメント参照、
    この一括unlock自体で既に同種の計算爆発が起きるため意図的に省略されている)なので変更不要。

    テストは`tests/test_chan.c`のシナリオ5(既存の過去ログbackfillテスト、`chan_address_b`を
    `address_filter`として渡すよう変更)とシナリオ6(新規: keyringにchanと無関係なidentityを
    追加unlockした状態で、`address_filter`に無関係な方のアドレスを渡すと復号が0件になり、
    正しいアドレスを渡した場合のみ復号されることを確認)で検証している。

    なお、この問題自体は「バグ」というよりは「keyring内のunlocked identity数が想定より
    遥かに大きいスケール(数千件)で運用される」という、v1設計時に想定していなかった利用
    パターン(§7.4の一括import機能を実際に数千件規模で使うユーザーが現れたこと)によって
    表面化したもの。RPCサーバー自体をマルチスレッド化する根本対応(unlockAddress以外の
    リクエストが道連れでブロックされる問題自体は今回は未解決)は別途backlogとして残す。

22. **自分自身宛/chan宛のsendMessageが、ack生成・再送・inbox反映のいずれも通常の他人宛と
    同じ扱いだった問題を修正**: ユーザーから「CLIのsend-messageでchanアドレスをtoAddressに
    指定した場合、自分自身宛の特別処理(pubkey_cache参照スキップ)は入っているのに、そこから
    先(ackの要否・再送・inbox反映)には何も入っていないのでは」との指摘があり調査。
    `send_pipeline.c`の`bm_send_pipeline_send_message`を確認した結果、指摘通り
    以下3点が通常の他人宛と全く同じコードパスを通っていたことが判明した。

    - ackの生成・埋め込み: is_self(自分自身宛)でも`generate_full_ack`を無条件に呼び、
      ackobjectを組み立ててmsgへ埋め込んでいた。しかし自分自身宛/chan宛には誰もackを
      返送してこない(chanの場合、自分が投稿した内容を復号できるのは自分自身であり、
      他メンバーが「あなたの投稿を受け取った」というackを返す設計にはそもそもなっていない)ため、
      PoW計算も含めて完全に無駄だった。
    - 再送(resend): `bm_messages_store_list_resend_candidates`は`status != 'ackreceived'`
      のみを条件にしており、is_self送信もack未着として扱われ`BM_RESEND_MAX_ATTEMPTS`
      (5回)まで無駄な再送を繰り返してから諦めていた。
    - inboxへの反映: is_self送信が送信者自身のinboxに現れる手段が、ネットワーク経由で
      戻ってくる(chanなら他メンバーのgossip、孤立ノードや他メンバー不在なら永久に届かない)か、
      `bm_object_sync_backfill_trial_decrypt`(§11項目21参照、`unlockAddress`時のみ発火)しか
      無く、「送った内容がすぐ自分のinboxに見える」設計にすらなっていなかった。

    PyBitmessage本家(`/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`)の
    `class_singleWorker.py`を確認したところ、`config.has_section(toaddress)`(toAddressが
    自分の持ついずれかのidentityかどうか)で自分/chan宛を判定し、①`fullAckPayload = ''`
    (ackを一切埋め込まない、コメント"Not bothering to include ackdata because we are sending
    to ourselves or a chan.")、②status`'msgsentnoackexpected'`(通常は`'msgsent'`)を設定、
    ③`class_singleCleaner.py`の再送候補SQLがこのstatusを明示的に除外、④送信直後に
    `helper_inbox.insert()`で同期的に自分のinboxへコピーを挿入、という4点セットで
    軽量化・即時反映していることを確認した。これに合わせて実装した。

    さらに実装中、ユーザーから「is_selfの判定はto_ripe==from_id.ripe(fromAddressと
    toAddressが完全に同一)だけでよいのか、identity全部を見なくていいのか」という指摘が
    入った。旧実装(直近の2026-08-30セッションでpubkey_cache参照スキップのために書かれた
    判定式)は`to_ripe == from_id.ripe`のみを見ており、「fromAddressとtoAddressが同一
    (chan投稿含む)」の場合しか捕捉できず、「fromAddressとtoAddressが別だが、toAddressも
    このノードが持つ別のidentityである」場合(例: identity Aからidentity Bへ送る、両方
    自分がunlock/lock問わず所有している)を捕捉できていなかった。これはPyBitmessage本家の
    `config.has_section(toaddress)`(自分の持つ**いずれかの**identityかどうか、fromAddressとは
    無関係)より狭い判定であり、正確な指摘だった。

    実装内容(`src/core/send_pipeline.c`):
    - is_selfの判定を`memcmp(to_ripe, from_id.ripe, ...)`から
      `bm_identity_store_load(identity_db, to_address, &to_identity_row) == 0`
      (toAddressがidentity.dbに存在するか)へ変更。公開鍵はunlock不要でidentity.dbに
      平文保存されている(§2.3)ため、to_identity_row.encryption_pubkeyをそのまま使える。
      toAddressのidentityがkeyringでunlock中かどうかは一切問わない(PyBitmessage本家の
      `has_section`もrunlock状態を見ていないことと整合)。
    - is_selfの場合、`generate_full_ack`自体を呼ばずack_data/ack_packetをNULLのまま
      進める(sent.ack_dataのNOT NULL制約に合わせ、DB保存時のみ長さ0の非NULLバッファに
      差し替える)。
    - sent.statusをis_selfなら`'msgsentnoackexpected'`、それ以外は従来通り`'sent'`に設定。
    - `bm_messages_store_list_resend_candidates`(messages_store.c)のWHERE句に
      `AND status != 'msgsentnoackexpected'`を追加し、再送候補から除外。
    - `struct bm_sent_message`の`status[16]`は`'msgsentnoackexpected'`(21文字)が
      収まらないため`status[24]`へ拡張。
    - is_self送信が成功したら、object全体のinventory hash(trial_decrypt.c等inbox側の
      慣習に合わせる、sentテーブルの乱数msg_idとは別概念)をキーに
      `bm_messages_store_insert_inbox`を同期的に呼び、messages.dbのinboxへ即時反映する
      (INSERT OR IGNOREのため、後からネットワーク経由で同じobjectを受信しても重複しない)。

    テスト:
    - `tests/test_send_pipeline.c`: 従来「2つの別identityを同一identity_dbにcreate_and_unlock
      して送受信roundtripを見る」構成になっていたテストが、is_selfの新判定により
      そのままis_self経路を通るようになった。status='msgsentnoackexpected'・ack省略
      (`decoded.ack_payload_len == 0`)・inboxへの即時ループバックを確認するよう更新。
      さらに、受信者identityをlockした状態でもis_self経路(ack省略・inboxループバック)が
      機能することを確認するケースを追加(is_self判定がunlock状態に依存しないことの担保)。
    - `tests/test_object_sync.c`: 「ack往復」を検証する既存セクション(4節目)は、sender/receiver
      両identityを同一identity_dbに置いていたため、is_self化の影響でack自体が生成されなくなり
      検証が成立しなくなった。receiver identityの作成・unlockだけ使い捨ての別identity_db
      (`test_object_sync_recv_identity.db`)で行うよう分離し(unlock後は`&kr`に載るだけなので
      trial_decrypt側の検証には影響しない)、sender側の`identity_db`(ctx全体で共有、is_self判定
      に使われる)にreceiverが登録されない状態を維持することで、本来検証したかった
      「別ノード宛のack往復」シナリオを保った。
    - `tests/test_cli_integration.sh`: 「pubkey_cache未登録の宛先へのsend-messageは失敗する」
      検証で使っていたADDR2Bが`create-address`で作られた(=identity.db在籍の)自分のidentityだった
      ため、is_self化によりpubkey_cache無しでも送信が成功するようになってしまった。send-message
      呼び出し前に`delete ADDR2B`してidentity.dbから除いてから検証するよう修正。
    - ctest 41件全通過。

    出典・詳細はこのファイル内§5末尾(send_pipeline/ack)、§7.3(送信パイプラインとの関係)も参照。

23. **version messageのaddrFromがephemeralなローカルポートを漏らし、自宅IPv4+
    ephemeralポートが自分自身のpeers.dbへ混入する問題を修正**: ユーザーから「peers DBに
    自分自身のIPv4アドレスが登録されている。手動で`is_self`は立てたが、自分自身かどうかを
    知る本来の方法が無い」との指摘で発覚。調査の結果、ユーザーの自宅IPv4回線は
    外部から確実にアクセス不能(NAT配下・ポート転送なし)であり、他peerとの実接続による
    self-connection検知(version messageの`nonce`比較、PyBitmessage本家の
    `isAlreadyConnected`相当)は接続自体が成立しないため機能しない。既存の`is_self`
    フラグ機構(`bm_peer_manager_mark_self`、`peer_manager.c`)もonionアドレス専用で、
    IPv4向けの自動検知経路が皆無だった。

    根本原因を`infra/network.c`/`infra/protocol.c`を実際に読んで特定した:
    version messageの`addrFrom`(送信者が主張する「自分自身のアドレス」)に、
    `bm_fd_data_new`(`network.c`)が接続確立直後に`getsockname(fd,...)`で取得した
    `conn->local_addr`(=そのTCP接続のOSが選んだephemeralなローカル送信元ポート)を
    そのまま使っていた(`peer_connector.c:545`, `object_sync.c:1127`)。設定済みの
    リッスンポート(`inbound_port`)は一切参照されていなかった。SOCKS5/Tor経由の
    `peer_addr`(addrRecv相当)側は既に`logical_peer_ip`でプロキシアドレスとの混同を
    回避済みなのに、`local_addr`(addrFrom)側だけ対応漏れという非対称な実装だった。
    この誤ったaddrFromを受け取ったpeerがaddr messageで再共有すると、自宅IP+
    ephemeralポートが正規のpeer候補として流通し、addr relay経由で(第三者経由の
    伝聞のため直接のnonce比較では検知不能な形で)自分自身のpeers.dbにも巡り巡って
    戻ってくる。

    PyBitmessage本家(`/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`)の
    `bmproto.py`も調査したが、`bm_command_version`が受信した`addrRecv`(=相手から見た
    自分)を`logger.debug('my external IP: %s', ...)`とデバッグログに出すだけで、
    自己IP学習も`bm_command_addr`側の自己アドレス除外フィルタも存在しなかった。
    「複数peerが報告したaddrRecvの一致から自分の外部IPを推定する」ようなBitcoin Core的な
    仕組みは本家にも無く、この設計上の穴は本家にも共通することを確認した上で、
    今回はC実装側の非対称バグ(addrFrom生成)の是正を優先した。

    対応: `infra/protocol.c`に`bm_unspecified_ipv4_address()`を新設し、addrFromには
    「自分の到達可能なIPv4アドレスは分からない」ことを正直に示す`0.0.0.0`を常に使う
    ようにした(`peer_connector.c`/`object_sync.c`の`bm_post_version`呼び出し2箇所を
    修正)。`is_routable_ipv4_peer_address`(`object_sync.c`)は既に`0.0.0.0`を
    非routableとして弾く設計になっているため、これを受け取ったpeerがaddr messageで
    さらに広めることもない。`conn->local_addr`/`getsockname()`自体は
    `tests/test_object_sync.c`が独立にテスト用version packet組み立てに使っているため
    struct/取得処理は変更せず、production側の2呼び出し箇所だけ切り離した。

    自分の実際の外部到達可能アドレスを学習・活用する仕組み(Bitcoin Core的な複数peer
    合意によるself-IP推定)は今回はスコープ外(本家にも無い設計であり、ユーザーの
    IPv4回線はそもそも外部到達不能と確定しているため実益が薄い)。既に混入している
    自宅IP+ephemeralポートのpeers.dbエントリは、レイティング減衰(`bm_peer_manager_
    cleanup`)による自然消滅を待つか、手動でDELETEする。

    テスト: `tests/test_version_addr_from.c`を新設。`bm_unspecified_ipv4_address()`が
    `AF_INET`+`0.0.0.0`+port 0を返すこと、ephemeralなローカルアドレスを渡しても
    実際にbm_new_version_messageが組み立てるversion payloadのaddrFromが常に
    `0.0.0.0:0`になること、addrRecv(peer_addr)側は影響を受けないことを確認する。

23. `[peer_registry] failed to send inv to fd=N(write: Broken pipe)`ログ頻発の調査(2026-09-05、
    ユーザー指摘)。

    本番daemon(daemon A)のjournalctlログで、数分おきのinv broadcastのたびに同じ
    8〜9本ぶんの書き込み失敗警告が繰り返し出ていた。まずこのfd番号自体は
    `bm_peer_registry_broadcast_inv`が`dup()`した使い捨て複製fd(書き込み直後に
    close()される、`peer_registry.c`のdocコメント参照)であり、番号が固定的に
    見えるのは単に小さい未使用番号から再利用されているだけで、それ自体は異常の
    兆候ではないと確認した。

    `list-connections` API(`BM_API_PORT=8442`、認証情報は`/etc/bitmessage/
    bitmessage.conf`とは別に起動時表示されるパスワード)で実接続状態を確認した
    ところ、outbound 7本は全て`fullyEstablished:true`かつ数十万バイト送受信済みで
    正常。一方inbound 8本は**全て`fullyEstablished:false`・送受信0バイトのまま**
    (これがinv broadcast失敗の対象と一致する数)。

    さらに`ss -tan 'sport = :8444'`で実OSソケット状態を確認すると、registryが
    報告する8本のポート番号はどれも現存する実ソケットと一致せず、代わりに全く別の
    2本が`CLOSE-WAIT`(相手は既にFIN送信済み、Recv-Q=130バイトの未読データが
    残ったまま)で滞留していた。`bm_fd_data.last_activity`は`bm_network_
    handle_readable`の読み取り成功時にしか更新されず(`network.c`)、
    `BM_HANDSHAKE_TIMEOUT_SECONDS`は20秒(`network.h`)なので、
    handshake未完了のまま何時間も残り続けているのは`bm_network_idle_sweep`の
    ハンドシェイクタイムアウト判定が本来なら20秒で刈り取るはずの接続だと確定した。
    ただし「なぜ刈り取られないか」の根本原因(read側のepoll検知がこれらの接続に
    対してだけ働いていないように見える)は、稼働中の本番daemonにgdb/strace等の
    侵襲的なデバッグを行わずには特定できず、今回はここまでの切り分けに留めた
    (本番daemonへのアタッチは要ユーザー確認、CLAUDE.md「安全に関する厳守事項」の
    範囲外の行為のため今回は実施していない)。

    上記調査中、fd番号がdup()複製なのか実registry上のfdなのか区別できず苦労した
    (ユーザー指摘)ため、`list-connections`の各接続エントリに実fd番号(`conn->fd`)を
    追加した(`core/api_server.c`の`list_connections_one`、`cli/main.c`のヘルプ文言も
    同期)。broadcast_inv失敗ログの"fd=N"とは無関係である旨をコメントで明記した。

    残タスク(backlog、うち(1)は同日中に実装、下記追記参照): (1) `bm_peer_registry_
    broadcast_inv`の書き込み失敗(EPIPE等)を検知した際、ログを出すだけでなく該当接続を
    能動的に`close_connection`相当で除去する防御的な修正(read側検知に依存しない独立した
    安全網になる)、(2) idle_sweepのハンドシェイクタイムアウトが特定の接続に対して
    機能しない根本原因の特定(本番daemonへの侵襲的デバッグが必要、要ユーザー承認、
    未着手)。inbound上限`BM_MAX_INBOUND_CONNECTIONS`(64)に対し現状8本程度なので
    即座の実害(新規inbound拒否)には至っていないが、リークが継続すれば将来的に枯渇しうる。
    ctest 42件全通過。

    追記(2026-09-05、同日中): 上記残タスク(1)を実装した。`bm_peer_registry_broadcast_inv`は
    `object_sync_broadcast_thread`(network_epoll_threadとは別スレッド)から呼ばれるため、
    write失敗時に対象の`struct bm_fd_data *conn`へ素朴に触れて`close`+`free`すると、
    ロック解放後dup()した複製fdへ書き込むまでの間に、network_epoll_thread側がread側検知で
    先にclose_connection済み+free()し、同じヒープアドレスへ別の新しいaccept()由来のconnが
    割り当てられていた場合、無関係な生きている接続を誤って破壊してしまう(ABA問題)。

    対策として`struct bm_fd_data`に`generation`(uint64_t)を追加し、`bm_peer_registry_add`が
    登録のたびに`reg->next_generation`(1始まりの単調増加カウンタ、レジストリ自身の
    mutexで保護)から払い出すようにした。`bm_peer_registry_broadcast_inv`はdup()前の
    ロック区間で`pending[].conn`と`pending[].generation`を一緒に記録しておき、write失敗後に
    新設した`bm_peer_registry_evict_if_current(reg, conn, generation)`を呼ぶ。この関数は
    ロックを取り直して`reg->conns[]`を線形探索し、**ポインタが一致した配列要素**(=この時点で
    確実に生きている、dereferenceして安全)の`generation`を読んで比較し、両方一致した場合
    のみ除去(registryから外す)・`close`・`bm_fd_data_free`を行う。ポインタ不一致(既に
    別経路で除去済み)はもちろん、ポインタ一致でもgeneration不一致(ABA発生、別の新しい
    接続が同じアドレスを再利用している)の場合も一切dereferenceせず0を返して何もしない。
    close_connection側(network.c、単一スレッドの中でしか動かない既存経路)はこの
    generationチェックが無くても元々安全(スナップショットと同じロックスコープ内で
    即座に使う既存の`bm_peer_registry_for_each`/`for_each_locked`とは異なり、こちらは
    ロック解放後・別スレッドから“後で”触るケースなので、この2つは区別して考える必要がある)
    ため、既存の`bm_peer_registry_remove`(pointerのみ比較)はそのまま維持し、新関数は
    broadcast_inv専用として追加した。

    書き込み失敗時のサマリログ(既存の`bm_log_debug("[peer_registry] broadcast inv: ..."`)
    に`evicted %zu dead peer(s)`を追記し、除去件数も可視化した。

    テスト: `tests/test_peer_registry_evict.c`を新設し`tests/CMakeLists.txt`へ登録
    (`peer_registry_evict`)。(a) `bm_peer_registry_add`のたびにgenerationが1から単調増加
    すること、(b) generation不一致なら(ポインタが登録済みでも)除去せず登録数も減らない
    こと(ABA対策の核心)、(c) ポインタ+generation一致なら除去され登録数が減ること、
    (d) 既にregistryから外れている(free済みの)connへ`evict_if_current`を呼んでも0を返し
    dangling pointerをdereferenceしないこと、をそれぞれ確認する。(d)はfree済みポインタを
    そのまま関数へ渡すと`-Wuse-after-free`(gcc)で警告になるため、`uintptr_t`経由で
    コンパイラの変数追跡を意図的に切り離した(コメントで理由を明記)。ctest 43件全通過。

    なお残タスク(2)(idle_sweepが特定の接続を刈り取らない根本原因の特定)は本修正の
    スコープ外のまま。今回の(1)は「read側検知が機能しない接続」を独立した経路で救済する
    安全網であり、(2)自体の原因究明が完了したわけではない。

    追記(2026-09-05、根本原因(2)の調査続き): journalctlを時系列で洗い直したところ、
    問題のinbound 8本は「じわじわ」発生したのではなく、9/4 22:50:29の1秒の間にまとめて
    (fd=24,29〜35として)acceptされていたことが判明した。同時刻に既存outbound接続1本の
    EOF切断+再接続も起きている。同時刻帯の他サービス(本機で常時クラッシュループしている
    `anbox-cloud-appliance`関連、dashboard再起動カウンタ48,308回)のノイズとの相関も
    疑ったが、これは1日中絶え間なく発生している背景ノイズであり22:50:29固有の現象では
    ないと判断した。`tor@default.service`は該当時間帯にログを一切出しておらず、Tor側の
    直接的な裏付けは取れなかった。

    この「バーストaccept」を手掛かりに、ローカルで2種類の再現テストを作成した:

    1. `tests/test_burst_accept_idle_sweep.c`(新設、`burst_accept_idle_sweep`として登録):
       `bm_network_handle_accept`と`bm_network_idle_sweep`を合成時刻で直接呼ぶ方式
       (test_idle_sweep.c等と同じ決定的テスト方針)。listen backlog(16、`network.c`の
       `listen(sock, 16)`)を超える本数(32本)を無防備にblocking connect()すると、
       backlogを超えた分のSYNがカーネル側で詰まりconnect()自体が長時間ブロックして
       テストがハングすることが判明した(実際に120秒タイムアウトを確認)ため、本番と
       同じ実測値である8本に抑えた。シナリオ1(接続だけして即座に消えるpeer)・
       シナリオ2(本番のss調査で見つかったCLOSE-WAIT/Recv-Q=130に近い状況を模した、
       130バイトの不正データ送信後に消えるpeer)いずれも、ハンドシェイクタイムアウト後に
       全数正しく刈り取られ、**再現しなかった**。
    2. `tests/test_burst_accept_real_epoll_thread.c`(新設、`burst_accept_real_epoll_thread`
       として登録): 直接呼び出しでは`bm_network_idle_sweep`のタイムアウト計算ロジックしか
       検証できず、本番で観測した「CLOSE-WAIT状態でRecv-Q=130バイトの未読データが残った
       まま」(=epoll_waitがそのfdに対して一度もreadableイベントを配送していない可能性)は
       検証できていなかったため、`bm_network_epoll_thread`を実スレッドとしてpthread_create
       し、本物の`epoll_wait`経由で同じシナリオ(バーストaccept→130バイトの不正データ→
       即座にclose())を再現するテスト。`tests/test_peer_rating_on_disconnect.c`と同じ
       「実スレッド起動+ポーリング待機」方式。結果、read側のEOF検知(`"peer closed (EOF)"`)が
       1秒未満で即座に正しく働き、**これも再現しなかった**。

    2件とも失敗したことで、「バーストaccept+早期切断」という単純なTCP/epollレベルの条件
    だけでは再現せず、本番固有の要因(Tor hidden service経由という要素そのもの、
    peer_connector_thread/object_sync_broadcast_thread等他スレッドとの競合、24時間以上の
    稼働・大量のfd churnを経た状態固有の何か)が絡んでいる可能性が高いと判断した。ユーザーと
    相談の上、これ以上ローカルでの条件作り込みには進まず、計装ビルドを本番daemon(daemon A)
    へ実際にデプロイして自然発生を待つ方針に切り替えた(ユーザーが就寝前に手離れさせたい
    という事情もあった)。

    `src/infra/network.c`の`idle_sweep_one`(ハンドシェイク未完了の接続を評価するたびに
    fd・経過秒数・閾値を記録)と`bm_network_epoll_thread`のepoll_wait配送ループ
    (ハンドシェイク未完了の接続にイベントが配送されるたびにfdとevents bitmaskを記録)の
    2箇所へ、`bm_log_debug`での一時的な調査用ログを追加した(原因特定後は削除する想定)。
    もしゴースト化した接続のfdが、accept直後を最後に後者のログへ二度と現れなくなれば、
    epoll_wait自体がそのfdへイベントを配送していないことの直接証拠になる。ctest 45件
    全通過。

    本番daemon Aは`BM_LOG_LEVEL`が既定(DEBUG無効)のままだったため、上記ログを実際に
    観測するには有効化が必要だった。ユーザー提案により、systemd unitの
    `Environment=`を直接書き換えるのではなく、`EnvironmentFile=-/etc/bitmessage/
    bitmessaged.env`(存在しなくても起動を妨げないよう`-`プレフィックス付き)を
    `bitmessaged.service.d/override.conf`へ追加し、実体である`BM_LOG_LEVEL=DEBUG`は
    `/etc/bitmessage/bitmessaged.env`側に置く方式にした(unitファイル自体を触らずに
    済み、`systemctl daemon-reload`だけで反映できる)。既存の`bitmessage.conf`(アプリ本体の
    設定、INI形式)とは役割・形式が異なる別ファイルとして`/etc/bitmessage/`配下に並置した。

    追記(2026-09-08、`/loop`による継続監視中に疑わしい接続を捕捉): 本番daemon Aの
    journalctlを30分間隔で監視していたところ、inbound fd=38
    (Tor hidden service経由、`127.0.0.1:8444`⇔`127.0.0.1:56270`のrendezvous接続)で
    以下の挙動を観測した。

    - 14:07:59 accept、14:08:08まで`idle_sweep(handshake未完了)`ログが正常に(1秒間隔で)
      出力されるが、**その後22分間、このfdに関するログ(idle_sweep/epoll_wait event両方)が
      完全に途絶えた**。
    - `idle_sweep_one`(network.c)は`handshake_complete==0`の間、判定のたびに必ずこの
      ログを出す構造になっているため、ログが消えたこと自体は「この時点でhandshakeが
      完了した」ことを示唆する一方、`BM_IDLE_PING_TIMEOUT_SECONDS`(300秒)後に出るはずの
      最初のkeepaliveログが実際に出たのは22分後(14:35:49、`idle 304s`)だった。同時刻に
      acceptされた比較対象のfd(fd=37)は約5分19秒で最初のkeepaliveが出ており、fd=38だけが
      異常に遅かった。
    - `bitmessage-cli list-connections`(ユーザーからAPI認証情報の提供を受け、初めて本番の
      内部状態を直接確認できた)で調べたところ、この時点で該当接続は`fullyEstablished:true`
      となっており、以後は正常なトラフィックパターン(2回目以降のkeepaliveは想定通り
      300秒強の間隔)に復帰していた。
    - `/var/log/tor/info.log`(teruteruがadmグループのため`sudo`無しで直接閲覧可能)を
      該当時間帯で確認したところ、`hs_circ_service_rp_has_opened`によりrendezvous circuit
      自体は14:07:58〜14:08:00の数秒で構築完了していたが、その後この特定circuitに関する
      追跡ログ(実際にTCPストリームがbitmessagedへ渡るタイミングを示すもの)が見当たらず、
      22分間の空白がTor側の遅延によるものか、bitmessaged側の何らかの処理漏れによるものかを
      ログだけからは断定できなかった。

    現時点の判断: 「epoll_waitが特定fdへのイベント配送を完全に停止する」という当初の
    最有力仮説を裏付ける決定的証拠は得られなかった(epollはlevel-triggered、`EPOLLET`
    未使用であり、取りこぼしたイベントは次回のepoll_wait呼び出しで再度検出されるはずの
    設計になっている点もこの仮説への疑問材料)。一方で「Tor hidden service経由の接続は
    rendezvous circuit確立後もアプリケーションへの引き渡しに数分〜数十分単位の遅延が
    生じうる」という別の仮説(bitmessaged側のバグではない)の方が現状では有力候補だが、
    これも確証には至っていない。`idle_sweep(handshake未完了)`ログが本当に「20秒の
    タイムアウトを超えても切断されない」形で残り続けた実例はまだ一度も観測できていない
    (今回はログが途絶えただけで、実際に無限に待たされたわけではなく、最終的には
    正常完了している)ため、残タスク(2)は依然として未解決のまま、`/loop`による監視を
    継続する。次回類似の事象が発生した際は、ログが途絶えた直後(検知まで30分待たず)に
    Torの`info.log`と突き合わせられるよう、疑わしい兆候を検知した時点で監視間隔を
    5〜10分に短縮する運用とした。

24. **`received getdata`のnot_found大量発生・`sent getdata`に対する`received object`不足の
    調査(2026-09-07、進行中)**: ユーザーから「`received getdata: N item(s) requested,
    0 sent, N not found`が大量発生している、`sent getdata`に対する`received object`も
    少ないのでは」との指摘で調査開始。

    まず本番daemon A(systemd管理、journalctl経由。ローカルの`bitmessaged_bootstrap.log`は
    2026-08-25で止まっており現状を反映していなかった)の直近約1日分(9/6 11:53〜)を
    集計した:
    - `received getdata`(相手→自分): requested合計6897件中、**not_found 4409件(63.9%)**。
      特定の時間帯のバーストではなく30分バケットで見ても常時289〜309件と定常的に高い。
    - `sent getdata`(自分→相手)796件に対し`received object`577件、比率0.72。
    - `received inv`(missing>0)から`sent getdata`送信までの遅延は中央値0.112ms・
      最大1.7ms(=事実上ゼロ遅延)。同一秒内に複数接続からmissing>0のinvを受けた
      ケースが605秒中130秒(21%)。

    ユーザーの「invに対してgetdataが早すぎるのでは」という仮説を検証するため、
    PyBitmessage本家(`/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`)の
    `network/objectracker.py`/`network/downloadthread.py`を確認した。本家は
    `handleReceivedInventory`ではgetdataを送らず接続ごとの`objectsNewToMe`
    (`RandomTrackingDict`)に積むだけで、別スレッド`DownloadThread`が**1秒間隔**で
    全established接続を横断し、`missingObjects`というグローバル辞書を介して
    ランダムにチャンク要求する設計(`minPending=200`/`maxRequestChunk=1000`)。
    対してこのC実装の`handle_inv`(`object_sync.c`)はinv受信のその場で、他の接続との
    調整なしに即座にgetdataを送る。この「無条件・即時・接続間非協調」がnot_found
    大量発生や0.72という比率に寄与している可能性が高いが、not_foundの直接原因
    (GCによる期限切れ削除が先に走っているのか、そもそも要求元が実際にobjectを
    持つnodeではないのか)は、既存ログにhashも接続識別子も含まれておらず特定できて
    いなかった。

    ログにはhash・接続識別子(hash単位で追跡するため)が一切含まれておらず、
    journalctlでの集計はできても個々のhashの生死を追えなかったため、計測強化の
    ログを追加した(挙動は変更していない、ログ追加のみ):
    - `handle_inv`: `sent getdata`成功時に、送った各hash(64桁hex)+送信先peer
      (`bm_network_resolve_peer_ip_port`)+fdを1行ずつ`sent getdata item`として出す。
    - `handle_getdata`: not_found発生時に、該当hash+要求元peer+fdを`getdata not found`
      として出す。
    - `handle_object`: 保存成功時の既存ログ(`received object`)にhashを追加。加えて、
      既知object(重複)として無言returnしていた分岐にも`hash=... already known
      (duplicate), ignoring`ログを追加した。これは0.72という比率が「本当に届かなかった」
      のか「届いたが2件目以降として黙って捨てられただけ」なのかを切り分けるための計測
      (`bm_object_store_has`による重複判定は元々`received object`ログより前にあり、
      複数peerから同一objectをinvされて複数接続へgetdataを送った場合、2件目以降は
      これまで一切ログに残らなかった)。

    `hash_hex`(api_server.cの`hex_encode`と同じ実装、共通化するほどの規模ではないため
    このファイルにも複製)を追加。ビルド警告ゼロ、ctest 45件全通過を確認済み。

    デプロイは一旦保留(項目23の観測を優先)としたが、その後ユーザーが項目23側の状況を
    確認・調整の上で「デプロイ&再起動やっちゃいましょう」と明示的に指示したため、
    2026-09-07 21:38:56 JSTに計測ログ入りビルドを本番daemon Aへ反映・再起動した(ビルド
    バイナリsha256: `932dcb4a...`)。再起動直後にjournalctlで実際に`sent getdata item`→
    `received object`が同一hashで正しく対応するログを確認できた(項目23のidle_sweep/
    epoll_wait調査用ログも継続して出力されており、計装は失われていない)。

    根本原因の特定(2026-09-07、同日中): デプロイ後まもなく、ユーザーが実際のnot_foundバースト
    (`hash=7805056a...`、12接続から数分間・約60秒おきに繰り返しnot_found)を発見し、
    「`sent getdata item`してから`received object`していないのに`broadcast_inv`するから
    ではないか」と指摘。該当hashのjournalctlログを時系列で確認したところ:
    23:23:56に1接続(45.136.157.154:8444)へ`sent getdata item`を送ったのを最後に
    `received object`は一度も無いまま、15秒後の23:24:11から、全く別の12接続(45.136.157.154
    以外)がほぼ同時に`getdata not found`を要求してくるバーストが発生し、以後23:28台まで
    ~60秒おきに同じパターンが繰り返された。

    `bm_peer_registry_broadcast_inv`の全呼び出し箇所(`grep`で洗い出し)を確認したところ、
    `object_sync.c`側の6箇所は全て「`bm_object_store_insert`で実際に保存した後」にのみ
    呼ばれており問題無かったが、`dandelion.c:385`(`bm_dandelion_expire_and_refluff`、
    Dandelion++のstemタイムアウト処理、`peer_connector.c`の1秒間隔ポーリングから毎秒呼ばれる)
    が**object_pool_dbの保有確認を一切せず**、stemタイムアウト(固定10秒+平均30秒の指数分布)
    を迎えたhashを無条件で全peerへbroadcast_invしていたことが判明した。実際の発生経路:

    1. `handle_inv`(通常の"inv"、"dinv"ではない)で未所持hashを受信 →
       `bm_dandelion_note_source(hash, is_dinv=0, now)`が呼ばれ、`find_or_create_entry`が
       実時刻ベースのfluff_deadline(10〜40秒後)を持つ`dandelion_entry`を作る
       (is_dinv=1のdinv経由はこの時点では何もしないno-opであることに注意、
       `bm_dandelion_note_source`参照)。
    2. 同じ`handle_inv`が、そのhashをgetdataで要求する(今回の相手45.136.157.154宛)。
    3. 相手が応答しない(または遅延する)まま10〜40秒が経過し、`bm_dandelion_expire_and_refluff`
       の毎秒スキャンが`fluff_deadline`超過を検出、`bm_object_store_has`による確認なしに
       `bm_peer_registry_broadcast_inv(registry, &hash, 1, NULL)`を全接続(除外無し)へ実行。
    4. broadcastを受け取った全peerが(自分たちは実際にhashを知らなかった、あるいは
       広告を信じて)一斉にgetdataを送ってくるが、こちらは依然として本体を持っておらず
       `getdata not found`を返し続ける。相手側の再要求ロジックにより、これが約60秒おきに
       繰り返される。

    修正: `bm_dandelion_expire_and_refluff`に`object_pool_db`引数を追加し(`dandelion.h`/
    `dandelion.c`)、fluffループ内で`bm_object_store_has(object_pool_db, hash)`が真の
    hashだけをbroadcastするよう変更した。stem状態からの離脱(`fluffed_at`更新)自体は
    従来通り無条件で行う(まだ持っていなくても、以後stemを再試行する意味は無いため)。
    `object_pool_db`がNULLの場合は何もbroadcastしないfail-safe側に倒した(元の
    無条件broadcastへ暗黙に後退させない)。呼び出し元`peer_connector.c`は
    `args->config.object_sync_ctx->object_pool_db`を渡すよう変更(`object_sync_ctx`は
    `main.c`で`registry`と常に同時に設定されるため、`registry != NULL`の構成では
    実質的に必ず非NULL)。

    テスト: `tests/test_dandelion_stage2.c`のシナリオ3(既存)にobject_pool_dbを追加し、
    「stemタイムアウト後、実際に保存済みのhashは従来通りbroadcastされること」を維持しつつ、
    新設のシナリオ4で「`bm_dandelion_note_source(hash, is_dinv=0, now)`だけでobject_pool_dbに
    未保存のhashについては、stemタイムアウト後もbroadcastされない(fluffed状態には遷移する
    がpeerには何も送られない)こと」「後から実際にobjectを受信・保存できれば、通常の
    `handle_object`経路のbroadcast_invで正規にannounceされること」を確認する回帰テストを
    追加した。ビルド警告ゼロ、ctest 45件全通過(Debug/Release両方)。

    本家との比較(2026-09-07、ユーザーから「これはバグか、本家ではどうなっているか」との
    質問で調査): `/home/teruteru/Documents/Projects/teruteru128/PyBitmessage`の
    `network/dandelion.py`(`Dandelion.expire()`)と`network/invthread.py`
    (`handleExpiredDandelion`/`InvThread.run()`)を実際に読んだ。**「stemタイムアウト時に
    所持確認(`state.Inventory`)せずbroadcastする」という構造上のギャップ自体は本家にも
    存在する**(`expire()`は`state.Inventory`を一切参照せず`invQueue`へ積み、
    `InvThread.run()`のchunk処理・実送信箇所にも所持確認が無い)。したがって今回の
    C実装のバグは、本家にも共通する設計上の穴を偶然踏み抜いた形と言える。

    ただし発火条件は本家と逆転していた: 本家`bmproto.py`の`_command_inv`
    (`extend_dandelion_stem`引数で`inv`/`dinv`を共通処理)を見ると、
    `dandelion_ins.addHash()`(=タイムアウト追跡エントリ作成)を呼ぶのは**`dinv`受信時
    (`extend_dandelion_stem=True`)だけ**で、通常の`inv`では呼ばれない。対してこのC実装の
    `bm_dandelion_note_source`は逆に、**`is_dinv=0`(=通常の`inv`)の場合にだけ**
    `find_or_create_entry`でエントリを作り、`is_dinv=1`(`dinv`)は早期returnして何もしない
    (§9.5 Stage 3の「既に他ノードがfluff済みのinv経由objectは即座にfluffしてよい」という
    意図自体は妥当だが、実装が「即座に」ではなく「タイムアウト待ちのエントリを作る」形に
    なってしまっていた)。本家では発生頻度の低い`dinv`(今まさにstem中継されている新規
    object)だけがこの危険な経路に入るのに対し、この実装ではネットワーク上のごく普通の
    `inv`トラフィック(大半を占める)全てがこの経路に入ってしまっており、本家に共通する
    ギャップが母数の違いで大きく顕在化していた。

    ユーザーと相談の上、今回は「所持確認せずbroadcastする」直接の原因(今回の修正)だけを
    先にdeployし、この`is_dinv`条件の逆転(本家同様`dinv`受信時のみエントリを作るよう
    変更する件)は別途backlog化して改めて着手することにした。次回はis_dinv=0/1双方の
    エントリ作成条件を本家の`_command_inv`ロジックと突き合わせて設計し直し、Stage 3の
    元々の意図(「既にfluff済みのobjectは即座にfluffしてよい」)をタイムアウト経由ではなく
    別の形(例えば即座に`bm_decide_propagation`相当を呼んでその場でfluffする等)で実現する
    ことを検討する。

25. **`bm_dandelion_note_source`の`is_dinv`判定が本家と逆転している(項目24から分離、
    未着手)**: 本家PyBitmessageは`dinv`受信時(`extend_dandelion_stem=True`)にのみ
    `dandelion_ins.addHash()`でタイムアウト追跡エントリを作るのに対し、このC実装は
    `is_dinv=0`(通常の`inv`)の場合にだけエントリを作り、`dinv`は早期returnして
    何もしない(`bm_dandelion_note_source`、`dandelion.c`)。項目24の根本原因(stem
    タイムアウト時の無条件broadcast)は修正済みだが、この条件の逆転自体はネットワーク上の
    大半を占める通常の`inv`トラフィックを毎回タイムアウト追跡対象にしてしまう非効率
    (と、まだ見つかっていない副作用の可能性)を残したままである。本家の`_command_inv`
    (`bmproto.py`)のロジックに合わせて設計し直す必要がある(項目24の該当セッション参照)。

26. **`bm_network_epoll_thread`にグレースフルシャットダウン機構が無い(未着手)**:
    現状は`main.c`の通常終了時も含め、このスレッドをjoinせずプロセス終了に道連れにする
    設計になっており、`test_peer_rating_on_disconnect.c`・`test_burst_accept_real_epoll_thread.c`
    等の実スレッドテストも明示的にこの方針を踏襲している。本番の終了パスを忠実に
    再現できる利点はあるが、CI `sanitize`ジョブでのLeakSanitizer対応のたびに「意図的な
    道連れリークか、本物の意図しないリークか」を判別して`__lsan_ignore_object()`等で
    個別に除外する対症療法が必要になり、同種の実スレッドテストが増えるほど保守コストが
    積み重なる(2026-09-08のCI失敗調査で発覚、DESIGN-LOG.mdの該当セッション参照)。
    `stop_flag`+`eventfd`等で`epoll_wait`を起こしてループを抜けさせ、`pthread_join`で
    正しく終了を待つ機構を実装すれば、テスト側でも安全に`bm_fd_data_free`/
    `bm_peer_registry_destroy`を呼んでクリーンに終了できるようになる。

27. **`bm_peer_registry_evict_if_current`のマルチスレッド競合によるdouble free事故
    (2026-09-09発覚・同日修正完了)**: 本番daemon(daemon A)が
    `double free or corruption (out)`でSIGABRT死し、systemdの自動再起動で復旧する事故が
    発生した(ユーザー報告のjournalログ: `epoll_wait event: fd=29863 outbound events=0x19`
    → `read (fd=29863): Bad file descriptor` → `closing outbound connection (fd=29863):
    read error` → `double free or corruption (out)`)。コアダンプは`/var/crash/`に残らず
    (apport管理外バイナリ)、`coredumpctl`も未導入のため、journalログとソース読解のみで
    原因を特定した。

    根本原因: `bm_peer_registry_evict_if_current`(`peer_registry.c`)は
    `bm_peer_registry_broadcast_inv`経由で`network_epoll_thread`以外のスレッド
    (`peer_connector_thread`の1秒間隔ループに相乗りしている`bm_dandelion_expire_and_
    refluff`等)からも呼ばれる。§11 2026-09-05時点の実装は、connポインタ+generation
    (ABA問題対策、`network.h`の`conn->generation`のdoc参照)が一致した時点で、その場で
    `close(conn->fd)`・`bm_fd_data_free(conn)`まで直接実行していた。しかしgeneration
    照合は「このconnがまだregistryに実在するか」しか保証せず、「他スレッドが今まさに
    このメモリへアクセスしていないか」は保証できない。まさに同じ瞬間に
    `network_epoll_thread`が`epoll_wait()`で同じconnへのイベントを既に受け取り
    (`events[]`配列にdata.ptrとして保持済み)、これから読み取ろうとしていた場合、
    evict側が先に`close`・`free`し、直後に`network_epoll_thread`側が「まだ生きている」
    と思い込んだまま同じconnを`read()`(既にcloseされたfdへの`EBADF`="Bad file
    descriptor"を経て)、さらに`close_connection()`で**二重close・二重free**してしまう
    (実際のクラッシュ手順そのもの)。`tests/test_peer_registry_evict.c`の当時のコメントは
    「broadcast_inv側が先に捕まえ、network_epoll_thread側が後から先にfree済みのconnへ
    ABA的に触れてしまう」逆方向の競合しか想定しておらず、この「evict側が先に実行し、
    epoll_thread側がまだ生きた参照を保持している」向きの競合は未対策だった。

    修正: `bm_peer_registry_evict_if_current`は実際のclose/freeを行わず、
    `conn->pending_eviction`(新設フィールド、`network.h`)フラグを立てるだけに変更した。
    実際の`close_connection`呼び出しは常に`network_epoll_thread`単一スレッド内
    (`network.c`の`idle_sweep_one`、`bm_network_idle_sweep`経由で最大`BM_IDLE_SWEEP_
    INTERVAL_MS`=5秒間隔)に一元化し、`bm_fd_data_free`が常にその1スレッドからしか
    呼ばれないようにすることで、double freeを構造的に防ぐ。`pending_eviction`はロック
    (`reg->lock`)下で書き込まれるが、`idle_sweep_one`側はロック無しで読む(int型の
    読み書き自体は破損しない、最悪でも次のidle sweepまで最大5秒検出が遅れるだけで安全性
    上の問題は無い、という設計)。read側検知に依存しない安全網としての即応性は多少
    落ちる(以前は即座にfree、現在は最大5秒後)が、詰まった接続の除去という用途では
    許容範囲と判断した。

    テスト: `tests/test_peer_registry_evict.c`を新動作(フラグを立てるだけ、free/closeは
    しない)に合わせて書き換え、`tests/test_idle_sweep.c`にシナリオ4として
    「`pending_eviction`が立った接続は、他のタイムアウト判定より優先して次のidle sweepで
    確実に`close_connection`される」ことを検証する回帰テストを追加した。ビルド警告ゼロ、
    ctest 45件全通過。

    残課題: `evicted_peers`カウンタ・関連ログ文言(`peer_registry.c`)は「実際に除去した
    数」から意味的には「除去をマークした数」に変わったが、実用上ほぼ即座に処理される
    ため文言はそのままにした(次にこの周辺を触る際に気になったら見直す程度の軽微な項目)。

    追記(2026-09-09、ユーザーによる軽微な計装追加): 本番daemon Aのログで
    `[object_sync] object already expired, ignoring`がそこそこの頻度で出ていることに
    ユーザーが気づき、`handle_object`(`object_sync.c`)の該当ログへ`expires_time`を
    追加した(`bm_log_debug("...ignoring(%"PRId64")\n", (int64_t)hdr.expires_time)`)。
    挙動変更は無く計装のみ。ビルド警告ゼロ、ctest 45件全通過を確認済み。本番daemon Aへ
    ビルド・デプロイ・再起動済み(21:03:22 JST、PID変更、`NRestarts=0`の正常な意図的
    再起動)。根本原因(なぜ期限切れobjectがそこそこ受信されているのか)はまだ未調査。

    根本原因の特定と修正(2026-09-10): 上記の計装ログを本番daemon Aで観測したところ、
    `expires_time`と実際の受信時刻の差が18件全てで184〜358秒(約3〜6分)という狭い
    範囲に収まっており、単なるランダムな遅延にしては不自然に一貫していることにユーザーが
    気づいた。「有効期限切れをすぐ消すのではなく猶予をおいて消す仕様がプロトコルに
    あったか」という質問を受け、PyBitmessage本家を実ソースで確認した結果:
    - 受信時の猶予: `network/bmobject.py`の`BMObject.minTTL = -3600`(値は3600秒=1時間。
      コード上のコメントには「3 hour」とあるが実際の値は1時間で、コメントの方が誤記と
      判断した)。`expiresTime - now() < minTTL`の場合のみ拒否する。
    - GC削除時の猶予: `storage/sqlite.py`の`SqliteInventory.clean()`、
      `DELETE FROM inventory WHERE expirestime<?`に`now() - 60*60*3`(3時間)を渡している。
      受信時とGC時で異なる値(1時間 vs 3時間)を使っている点に注意(本家内でも一貫していない)。

    対してこのC実装(`object_sync.c`の`handle_object`・`validate_and_store_ack`、
    `object_store.c`の`bm_object_store_delete_expired`呼び出し元)はいずれも猶予なしで
    `expires_time <= now`の時点で即座に拒否・削除していた。これが「本家なら受け入れる
    はずの期限切れ直後のobjectを無条件で捨てていた」直接原因だったと判明した。

    修正: `object_sync.c`に`BM_OBJECT_EXPIRE_GRACE_PERIOD_SECONDS`(3600、受信時用)と
    `BM_OBJECT_GC_GRACE_PERIOD_SECONDS`(3*60*60、GC用)を新設し、本家の値をそのまま
    移植した。`handle_object`・`validate_and_store_ack`の判定を
    `expires_time < now - BM_OBJECT_EXPIRE_GRACE_PERIOD_SECONDS`に、`bm_object_sync_gc`が
    `bm_object_store_delete_expired`へ渡す閾値を`now - BM_OBJECT_GC_GRACE_PERIOD_SECONDS`に
    変更した(`object_store.c`自体は汎用的な`expires_time < ?1`のままで変更不要、猶予の
    計算は呼び出し元のビジネスロジック側に置いた)。PoW検証用の`object_pow_is_valid`の
    ttl計算(期限切れならttl=0として最も厳しく判定する既存ロジック)はこの変更と独立して
    安全なため変更していない。

    副次的に見つかったbuild-Release固有の警告3件も合わせて修正した(`-O2`でのみ顕在化、
    `build-Debug`では警告なしだった):
    - `tests/test_burst_accept_real_epoll_thread.c`: `write()`の戻り値未チェック
      (`-Wunused-result`)。同じシナリオを持つ`tests/test_burst_accept_idle_sweep.c`の
      既存パターン(戻り値を`ssize_t n`で受けて`CHECK`する)に合わせた。
    - `src/core/keyring.c`(2箇所): `strncpy`の`-Wstringop-truncation`
      (コピー先とコピー元の長さがちょうど一致しうる場合にGCCが警告する)。`memset`済み
      バッファへの`strncpy`+手動nul終端という元のロジックは実害がなかったが、静的解析上の
      警告を消すため`snprintf(dst, LEN, "%s", src)`に置き換えた。
    - `tests/test_peer_registry_evict.c`: 項目27で`uintptr_t`経由に回避したはずの
      `-Wuse-after-free`が、`-O2`最適化下でGCCの変数追跡が復元されて再度検出された。
      このテストの意図(dereferenceされないことの検証)自体は変えず、該当1行だけ
      `#pragma GCC diagnostic push/ignored "-Wuse-after-free"/pop`で抑制した。
      `-Wuse-after-free`はGCC固有(clangには存在しない)警告のため、`#if defined(__GNUC__)
      && !defined(__clang__)`でガードし、clang環境で「未知の警告オプション」という
      別の警告が新たに出ないようにした。

    `build-Debug`・`build-Release`双方をclean+再ビルドしてビルド警告ゼロ、ctest 45件
    全通過を確認済み(このプロジェクトは現状GCC専用、CIもclangは使っていない。clangでの
    追加検証は将来の任意タスクとしてbacklog化を検討)。

28. **ログレベルを4段階(DEBUG/INFO/WARN/ERROR)から8段階へ拡張**: 2026-09-12、運用が進みログの出力量・種類が
    増えたことで、DEBUG一段階では「常時見たい詳細情報」と「特定の調査時にしか要らない
    大量トレース」を分離できなくなってきたため、ユーザー発案でログレベルを8段階に
    拡張した。`logging.h`のenum定義と`logging.c`の`parse_log_level`/`level_tag`のみを
    変更し、既存呼び出し箇所の移行はbacklog項目8の時と同様に1箇所ずつ判断してから
    行う方針のため、このコミットでは未着手(挙動・出力内容は変わらない)。

    設計: DEBUGをDEBUG1/DEBUG2/DEBUG3の3段階に分割し、INFOとWARNの間にNOTICEを
    追加した。DEBUG1/2/3は数字が大きいほど詳細(sshの`-v`/`-vv`/`-vvv`に倣った)に
    しており、`bm_log_leveled`の`level < g_min_level`で足切りする既存ロジックは
    変更していないため、この向きに合わせてenum値を`BM_LOG_DEBUG3`=0を最小として
    `DEBUG3 < DEBUG2 < DEBUG1 < DEBUG < INFO < NOTICE < WARN < ERROR`の順に割り当てた
    (`BM_LOG_LEVEL=DEBUG1`ならDEBUG2/DEBUG3のみ抑制、`DEBUG3`なら3段階とも出る)。
    NOTICEはINFOより注目してほしいがWARNほど異常ではない事象(設定値のフォールバック
    発動、再接続成功など)用に追加した。

    ついでに、`parse_log_level`に元々あったNOTICEのエイリアス`"NOTIFICATE"`
    (英語として非標準の綴り、タイポと判断)を`"NOTIFY"`に修正した。

    テスト: `tests/test_logging.c`に8段階のフィルタ順序(DEBUG1指定でDEBUG2/DEBUG3が
    抑制されること、DEBUG3指定で3段階とも出ること)とNOTICE/NOTIFYエイリアスの検証を
    追加した。ビルド警告ゼロ、ctest 45件全通過。

    **既存呼び出し箇所の移行(2026-09-12、同日追記)**: 上記コミット時点では未着手だった
    約140箇所の`bm_log_debug/info/warn/error`呼び出しの再割り当てを完了した。移行対象は
    `bm_log_debug`(26箇所、無番号DEBUG・DEBUG1/2/3の4段階への再分配)と`bm_log_info`
    (32箇所、一部をNOTICEへ)の2つのみで、WARN/ERROR(63+31箇所)は8段階化前後で境界
    (INFOとWARNの間にNOTICEが挟まっただけ)が変わっていないため移行不要と判断した。

    §11 2026-09-12実装時のミス訂正: 当初、無番号DEBUGを一切使わずDEBUG1/2/3の3分割だけで
    26箇所を割り振ってしまった(enumの大小関係を「DEBUG1が最も粗い基本階層」と誤読し、
    `BM_LOG_DEBUG3 < BM_LOG_DEBUG2 < BM_LOG_DEBUG1 < BM_LOG_DEBUG`という実際の並び
    ―`bm_log_leveled`の`level < g_min_level`足切りにより、無番号DEBUGは`BM_LOG_LEVEL=DEBUG`
    だけで表示される最も粗い(控えめな)デバッグ階層であり、DEBUG1/2/3はそこからさらに
    詳細化した3段階―を踏まえていなかった)。ユーザー指摘で発覚し、4段階(無番号DEBUGを
    最も粗い階層、DEBUG1→DEBUG2→DEBUG3の順に詳細化)へ組み直した。

    DEBUG→無番号DEBUG/DEBUG1/2/3の判断基準: 「1メッセージ・1接続・1回の呼び出しにつき
    1行」のサマリ系ログ(受信/送信イベントの件数集計、接続確立、handshake完了等、19箇所)は
    無番号DEBUG(`BM_LOG_LEVEL=DEBUG`だけで見える最も粗い階層)。個別アイテム単位の失敗や
    調査用ログのうち出現頻度が中程度のもの(`keyring.c`の一括unlock個別失敗、
    `object_sync.c`の期限切れobject受信、計2箇所)はDEBUG1。`network.c`のhandshake未完了
    接続に対する調査専用ログ(`idle_sweep`/`epoll_wait event`、1秒間隔ポーリングのたび
    出力されるが対象は個体数の少ないhandshake未完了接続に限られる、計2箇所)はDEBUG2。
    inv/getdata内の1hashごとの相関ログ(`object_sync.c`の`sent getdata item`/
    `getdata not found`)、重複object受信ログ(通常のflooding gossipで全接続・全objectに
    対して出る、このファイル内で最も出現頻度が高い部類、計3箇所)は「特定の調査時にしか
    要らない大量トレース」としてDEBUG3にした。

    INFO→NOTICE: 全32箇所のうち、通常運用からの逸脱・特殊モード発動・リトライ
    (`main.c`の`BM_NO_CONNECT=1`スキップ、シグナル受信による終了処理開始、
    `object_sync.c`の未ack再送、`peer_connector.c`の新規outbound接続確立サマリ)の
    4箇所をNOTICEへ昇格した。起動時の設定表示・DB初期化完了・メッセージ復号・
    pubkeyキャッシュ等、通常運用で定常的に発生する残り28箇所はINFOのまま維持した
    (NOTICEを「INFOの大量出力で見落とされては困る、通常運用からの逸脱」に限定する
    ことで、NOTICEの希少性=注目に値する信号としての価値を保つ狙い)。

    ビルド警告ゼロ、`build-Debug`でctest 45件全通過を確認済み(レベル再割り当てのみで
    ログ本文・出力条件自体は変更していないため、既存テストの追加は不要と判断)。

29. **`handle_getdata`(object_sync.c)にもwrite失敗時の能動的接続除去を追加**: 2026-09-13、
    daemon Aのjournalctl/syslog調査で、`[peer_registry] failed to send inv`ログが
    2026-08-末に1日270件超のピークから項目27の`evict_if_current`導入(2026-09-05、
    commit 2ec2393)を境にほぼゼロへ激減していた一方、`[object_sync] failed to send
    object for getdata`ログも同時期に同様の推移(8/30-9/1ピーク時635件→9/6以降は
    9/12の単発バースト143件を除き実質4件のみ→9/13以降0件)を辿っていたことが分かった。
    ただし後者はevict_if_currentが呼ばれるbroadcast_inv(peer_registry.c)とは別の
    コードパス(handle_getdata、getdata要求への応答書き込み)であり、この期間
    `object_sync.c`・`network.c`とも該当箇所への修正コミットは一切無かった(投機的な
    調査用ログ追加のみ)。つまり「evict_if_currentと一緒に直った」わけではなく、原因
    不明のまま自然に収まっていたことが判明した(ユーザー指摘、根拠のない安心は
    危険という所感で一致)。

    原因不明の減少そのものを追うのは費用対効果が低いと判断し、代わりに`handle_getdata`
    側にも同種の安全網を追加することにした。`bm_object_sync_dispatch`(→`handle_getdata`)
    は`main.c`で`net_args->handler`として登録され、常に`bm_network_epoll_thread`
    単一スレッド内から呼ばれる(broadcast_invのように別スレッド(object_sync_broadcast_
    thread)からconnを触るわけではない)ため、ABA問題対策のgeneration照合は不要で、
    write失敗を検知したその場で`conn->pending_eviction = 1`を直接代入するだけでよい。
    実際のclose_connectionは既存のidle_sweep_one(network.c、1秒間隔ポーリング)が
    次回走査時に行う。あわせて、1件書き込みに失敗した接続はそれ以降のitemも送れない
    可能性が高いため、残りのitemをnot_found扱いにせずループを抜けるようにした
    (2026-09-12 05:43に観測した「peer切断とgetdata応答の競合で145件連続warn」のような
    無駄なログ連発を今後は1件で止める)。

    `tests/test_object_sync.c`にシナリオ18を追加し、相手側socketを先にcloseした状態で
    保有objectのgetdataを受けた際、`conn->pending_eviction`が立つこと・`bytes_sent`が
    0のままであることを検証した。標準の`write()`はSIGPIPEでプロセスごと落ちるため
    (`main.c`が本番で`signal(SIGPIPE, SIG_IGN)`している対策と同じ理由)、テスト内でも
    同様に無視するよう追加した。ビルド警告ゼロ、`build-Debug`でctest 45件全通過。

    なお、`failed to send inv`側の減少はcommit 2ec2393という明確なコードレベルの
    原因があるのに対し、`failed to send object for getdata`側の8月末→9月上旬の
    自然な激減については根本原因が未解明のまま残っている。ネットワーク側の一時的な
    事情(不安定なpeerの入れ替わり等)による可能性はあるが確証はなく、今回追加した
    安全網はあくまで「発生した場合に素早く刈り取る」ものであり、なぜ発生頻度自体が
    下がったのかという問いには答えていない点に注意。

30. **API層のHTTP/JSONを自前実装からlibmicrohttpd + cJSONへ移行**: 2026-09-15、ユーザーからの
    「HTTPパースとBASIC認証を独自実装しているが、libmicrohttpdとcJSONに書き換えるべきか」
    という問いから着手した。設計・根拠の本体は§6.3・§6.4に記述したので、ここには経緯と
    残件のみ記す。

    「書き換えるべきか」を好みで答えないため、まず自前実装の実害を実測した。(1)
    `read_until_double_crlf()`が受理済みfdに読み取りタイムアウトを設定しておらず、
    接続だけして何も送らないクライアント1つでRPCサーバー全体が無期限停止する(Basic認証の
    検証より手前なので資格情報不要)、(2) 自前JSONパーサ`bm_json_parse`に再帰深さ制限が無く、
    `[`を10万個並べた入力で実際にSIGSEGVする(ボディ上限1MiBなので深さ約100万まで送れる)、
    の2点を確認できたため「書き換えるべき」と判断した。どちらもライブラリ側では解決済みの
    問題(MHDはノンブロッキングI/O+接続タイムアウト、cJSONは`CJSON_NESTING_LIMIT`)である。

    移行の副産物として、ディスパッチ層を書き直すのに合わせJSON-RPC 2.0のバッチリクエストと
    通知(notification)に対応し、エラーコードを仕様の予約値へ整理した(§6.4)。バッチ対応は
    ユーザーからの「特に指定してないがバッチリクエストにも対応できているのか」という
    問いがきっかけで、確認したところ未対応(ボディがJSONオブジェクトであることを要求して
    いた)だったため、この機会に入れた。

    `tests/test_api_transport.c`を新設(46件目)。ビルド警告ゼロ、`build-Debug`でctest 46件全通過。

    **残件**: 自前JSON実装(`src/common/json.c`、803行)はCLI(`src/cli/main.c`、約130箇所)と
    一部のテストが引き続き使っており、削除していない。今回の移行スコープを
    「daemon側のAPIサーバー」に限定したのは、(a) ユーザーの依頼がHTTPパースとBASIC認証、
    すなわちサーバー側を対象にしていたこと、(b) 上記2件の実害はいずれもサーバー側(外部から
    任意の入力を受け取る側)にしか存在せず、CLIがパースするのはローカルのdaemonが返した
    応答であること、(c) CLIはユーザーが数千件規模の一括操作に日常的に使っており、機能上の
    利得が無い機械的な置換で回帰を招くリスクの方が大きいこと、による。CLIも
    cJSONへ寄せてツリーからJSON実装を1つに減らすのは、優先度は低いが妥当な後続作業。

31. **peer_registryのマルチスレッド・ストレステストが無い(未着手)**: 2026-09-15、
    libmicrohttpd移行作業中にTSanの話題から派生してユーザーが
    「項目27のdouble free事故はマルチスレッド絡みだったのに、なぜTSanで事前に
    検出できなかったのか」と疑問を呈したのが発端。調べた結果、**TSanの取りこぼしではなく、
    競合の両側が同一テストプロセス内で同時に実行されたことが一度も無かった**ことが分かった。

    テストの担当範囲を実際に確認した内訳(2026-09-15時点):
    - `bm_peer_registry_evict_if_current`を呼ぶテスト:
      `tests/test_peer_registry_evict.c`、`tests/test_idle_sweep.c`
      → **どちらも`pthread_create`が0件のシングルスレッドテスト**
    - `bm_network_epoll_thread`を実際に起動するテスト:
      `tests/test_burst_accept_real_epoll_thread.c`、`tests/test_peer_rating_on_disconnect.c`
      → **どちらも`evict_if_current`も`broadcast_inv`も呼ばない**

    つまり2つの集合は素で、事故を起こした「evict側スレッドとnetwork_epoll_thread」の
    組み合わせはテスト上に存在しない。TSanは静的解析を一切せず、実行時に起きたメモリ
    アクセスのhappens-before関係を観測するだけの動的検出器なので、片側しか走っていなければ
    報告する材料が無い。「安全と判断した」のではなく判断材料を与えていなかった。

    加えて、仮にマルチスレッドテストがあっても検出は自明ではない:
    - TSanはスケジュールを揺さぶらない(実際に起きた順序を観測するだけで、危険な交錯を
      意図的に作り出す機能は無い)。項目27の窓は「`epoll_wait()`が既にイベントを`events[]`へ
      返していて、まだ`data.ptr`を参照していない瞬間」という極めて狭いもので、
      実行のたびに踏むとは限らない。
    - generation照合自体は`reg->lock`下で行われており、その範囲だけ見れば正しく同期されて
      いる。問題の本質は「generation一致はregistryに実在することしか保証せず、他スレッドが
      今この瞬間にそのメモリを参照していないことは保証しない」という**生存期間の論理の誤り**
      であって、ロックで順序づけられた論理バグはdata raceの定義から外れ、TSanの検出対象に
      そもそも入らない。

    **やること**: 本物の`bm_network_epoll_thread`を回しながら、別スレッドから
    `bm_peer_registry_evict_if_current`/`bm_peer_registry_broadcast_inv`を連打する
    ストレステストを追加し、ASan(heap-use-after-free)とTSan(data race)に初めて観測材料を
    与える。現在の修正(close/freeを`network_epoll_thread`単一スレッドへ一元化し、他スレッドは
    `pending_eviction`を立てるだけ)は構造的な対策なので今この瞬間に競合があるとは考えて
    いないが、将来この方向の競合が再導入された場合に気づける網が無い状態を解消するのが目的。

    **設計上の注意**: この種のテストは本質的に確率的で、素朴に書くとflakyになる。
    合否判定は「競合を観測できたこと」ではなく「規定回数のループを完走してASan/TSanの指摘が
    無く、クラッシュもしないこと」に置くこと(競合が起きなかった実行でも成功扱いになるが、
    それでよい。ここで欲しいのは回帰の検出網であって、競合の存在証明ではない)。
    ループ回数・実行時間は固定上限にし、CIの実行時間(特に約219秒かかるTSanジョブ)を
    大きく延ばさない範囲に収めること。時刻依存の判定を持つ既存コード(`idle_sweep_one`等)を
    巻き込むので、CLAUDE.mdの「時刻は明示引数で受け取る」規律に沿って壁時計待ちを
    入れずに済む形にできないか先に検討する。

    優先度は中程度。本番で再発しているわけではなく、構造的な対策は既に入っているため
    緊急ではないが、項目27のような「事故ってから原因究明」を繰り返さないための投資として
    意味がある。

32. **起動直後のonionpeer自己announceがbroadcast_invの空振りに終わり、広告がsend_big_invという
    別経路へ暗黙に依存している(未着手)**: 2026-09-15、ユーザーから「起動2時間経過以降の
    `announced our onion peer`で、dinvで1ピアに対してのみ広告した直後にinvで接続している全ピアに
    広告しているように見えるが気のせいか」という指摘があり、本番daemon(daemon A)の直近20時間の
    journalを調査した。

    **まず指摘そのものは気のせいではなく、かつバグでもなくDandelion++の設計通りだった。**
    `bm_object_sync_announce_onion_peer`(`src/infra/object_sync.c`)はobject_pool.dbへinsert後に
    `bm_peer_registry_broadcast_inv`を呼ぶが、自分発のobjectなので`bm_dandelion_decide`がSTEM判定し、
    stem successor 1本にだけdinvが出る(ログの`inv to 0 peer(s), dinv to 1 peer(s)`)。その後
    `bm_dandelion_expire_and_refluff`(`src/infra/dandelion.c`)が`peer_connector_thread`の1秒
    ポーリング経由で`fluff_deadline`(= `BM_DANDELION_TIMEOUT_BASE_SECONDS`(10秒) +
    平均30秒の指数分布)の到来を検出し、同じhashを通常のinvで全ピアへ再ブロードキャストする。
    つまりDandelion++として振る舞うのは最初の「10秒 + α」だけで、fluff後(`fluffed_at != 0`)は
    以降の`bm_dandelion_decide`が常にFLUFFを返し、通常のobjectと完全に同じ扱いになる。

    実測(9/14 05:40〜9/15 01:37の20時間、announce 9件。onionアドレスはマスク済み):
    dinv送出からその直後のinvブロードキャストまでの間隔は+10s/+10s/+14s/+18s/+19s/+21s/+22s/
    +28s/+37s/+50sで、平均24.3秒・**最小値がちょうど10秒**と、`10 + Exp(平均30)`の分布に整合する。
    同期間のinvブロードキャストの背景レートは94.3秒に1回なので、無関係なinvがたまたま
    [+10s, +50s]の窓に入る確率は1件あたり0.35、announce由来の9件すべてでそうなる確率は
    7×10⁻⁵。偶然ではない。(同期間のdinvは全35件あるが、残り26件は他ノードからdinvで
    受け取ったobjectのstem中継で、9/14 15:07〜15:17に集中している。こちらは+3s/+4s等
    10秒未満の間隔も含むが、それは当該バースト中に流れていた別objectのfluffが
    「次のinv」として先に観測されているだけなので、上記の確率計算の母数には入れていない。)

    **本題(この項目で残す課題)は、その調査の副産物として見つかった起動直後の挙動。**
    9/15 01:04:22の再起動直後のannounceには、`[peer_registry] broadcast inv:`のログが1行も
    出ていない。`bm_peer_registry_broadcast_inv`は`pending_count > 0`のときだけサマリを出す
    (§11 2026-08-24)ので、これは**接続ピア数0の状態でannounceした**ことを意味する(直後の行が
    最初の`peer_connector connecting to ...`)。それでも`src/main.c`は
    `object_sync_ctx.last_onion_announce = time(NULL)`を無条件にセットするため、
    `bm_object_sync_maybe_reannounce_onion_peer`による次の能動的な広告機会は
    `BM_ONIONPEER_REANNOUNCE_INTERVAL_SECONDS`(7380秒 = 約2時間3分)後になる。

    ただし**実際には広告は届いている**。`send_big_inv`(`src/infra/object_sync.c`)が新規ピアとの
    handshakeごとにobject_pool.dbの保有hash全件をinvで送るため、announce済みのonionpeer
    objectもそこに含まれる。実ログでも01:05:18〜01:05:24に7本の
    `queued big inv for new peer: 11842 of 11842 (excluded 0 still-stemming)`が出ており、
    起動時のannounceから約1分で接続先全ピアへ渡っている。`excluded 0`なのは、announce時に
    `reg->count == 0`で`bm_dandelion_decide`が一度も呼ばれずdandelionエントリ自体が作られて
    おらず、副作用の無い`bm_dandelion_is_stemming`が0を返すため。

    **したがってこれは現時点の実害ではなく、「壊れやすい暗黙の依存」として残す項目。**
    問題は以下3点:
    - `announce` → `broadcast_inv`が空振りしたことを呼び出し側が検知できず、ログ上は
      `announced our onion peer`だけが出るので「広告できた」ように見える(可視性の欠如)。
    - 起動直後の広告の成立が`send_big_inv`が全件送っていることに完全に依存している。
      `send_big_inv`は元々「新規ピアへ自分の保有物一覧を知らせる」ための処理であって、
      自己announceを配送する意図で書かれていない。保有hash数が既に11842件あり、将来
      「big invで送る件数を直近N件に絞る」「TTLの短いobjectを除外する」といった素直な
      最適化を入れた瞬間に、起動直後の自己announceが誰にも届かない状態へ静かに退行する。
    - 起動直後のannounceはDandelion++のstemフェーズを完全にバイパスして通常invで拡散される
      (dandelionエントリが作られないため)。onionpeer objectは自分のonionアドレスの公表が
      目的なので匿名性上の実害は無いが、「自分発のobjectは必ずstemを経る」という§9の
      不変条件が起動直後だけ成立していない点は記録しておく。

    **対策案**: `bm_peer_registry_broadcast_inv`に「実際に何ピアへ送ったか」の戻り値を持たせ、
    `main.c`の起動時announceが0だった場合は`last_onion_announce`をセットしない(0のままにする)。
    そうすれば`bm_object_sync_maybe_reannounce_onion_peer`の次の1秒ポーリングで
    「`last_onion_announce == 0`なので即座にannounce」の既存パスが自然に再試行に使える
    (`tests/test_object_sync.c`シナリオ16が既にこの初回即時announceの挙動を検証している)。
    ただしこの再試行はPoW計算をやり直すことになるため、objectを作り直さず既存hashだけ
    再broadcastする形にするか、announce自体を「最初のピア接続が確立してから」へ遅延させるかは
    設計判断が要る。後者の場合、`peer_connector`が最初のhandshake完了を検知する仕組みが
    現状無いので、`last_onion_announce = 0`のまま放置して1秒ポーリングに任せる前者の方が
    既存の構造には素直。

    **対応済み(2026-09-15、同日中にユーザー承認のうえ実装)**: 上記「対策案」のうち、
    `broadcast_inv`に戻り値を持たせる案ではなく、より単純な次の形を採った。

    - `bm_object_sync_validate_onion_address`(object_sync.h/.c)を新設。`bm_build_onionpeer`を
      呼んで`free`するだけの、PoWもDB登録もbroadcastもしない形式検証専用の関数。
    - `main.c`の起動時処理2箇所から`bm_object_sync_announce_onion_peer`の呼び出しを除去した。
      `manual_onion_address`分岐は、announceの成否を`bm_peer_manager_mark_self`と
      `self_onion_address`のセットのゲートにも使っていた(§11 2026-08-23のバグ修正)ため、
      そのゲートを上記の検証関数へ置き換えてゲート自体は維持している。Tor ControlPort分岐は
      アドレスがADD_ONION応答由来で元々ゲートが無いので、announce呼び出しを消すだけ。
      どちらも`object_sync_ctx.last_onion_announce = time(NULL)`を削除し、0のままにする。
    - `bm_object_sync_maybe_reannounce_onion_peer`に
      `if (ctx->registry != NULL && bm_peer_registry_count(ctx->registry) == 0) return;`を追加。
      `bm_peer_registry_count`が返す`reg->count`は`bm_peer_registry_broadcast_inv`が実際に
      ループする対象そのものなので、「broadcastが空振りになる条件」と過不足なく一致する。
      `registry == NULL`(ネットワークを張らないDBレベルのテスト)は従来通り素通りさせる。

    これにより、`peer_connector_thread`の1秒間隔ポーリングが最初のピア確立を検出した時点で、
    既存の「`last_onion_announce == 0`なら即announce」パスがそのまま初回announceとして働く。
    新しい状態機械もスレッドもフラグも増えていない(増えたのは`if`1つと検証関数1つ)。
    起動直後だけDandelion++をバイパスしていた状態も構造的に解消された(ピアが居る
    ⇒`bm_dandelion_decide`が呼ばれる⇒stemエントリが必ず作られる)。副次効果として起動時の
    PoWが`main()`から無くなり、起動が速くなる。

    検証は`tests/test_object_sync.c`シナリオ16へ追記(空のregistryではannounceされず
    `last_onion_announce`も0のまま、その直後にピアのあるregistryへ戻すと同じ
    `last_onion_announce == 0`の状態から初回announceが成立すること)。ガードを一時的に
    `if (0)`へ潰すと当該2件が実際にFAILすることを確認済み(テストが空振りでないことの確認)。
    ビルド警告ゼロ、ctest 46件100%通過。

    **不採用にした案**: 「起動直後もstemを徹底する」(ピアが繋がるまでstem待ちのエントリを
    保持し、最初のoutbound接続が確立した時点でそれをstem先に割り当てて送る)は見送った。
    本家PyBitmessageは実際にこれをやっており(`network/dandelion.py`の`maybeAddStem`が
    `child=None`のstemエントリを保持し、新規接続時に割り当てて`invQueue`へ再投入、対になる
    `maybeRemoveStem`が切断時にchildをNoneへ戻してタイムアウトを引き直す)、移植は可能。
    しかし我々の`bm_dandelion_decide`は「接続ごとに呼ばれてその場で判定する」設計なので、
    「エントリを先に作ってchildを後から埋める」構造を持ち込むとエントリの生存期間管理が
    丸ごと増える。これは項目27のdouble-free事故と同じ領域で、得られるのは再起動時1回分の
    stem保護のみ。ユーザーからも「複雑になってそこの部分が逆に安全から遠ざかりそう」という
    懸念が出ており、同意して不採用とした。

    **併せて調査し、変更しないと決めた件(再announce間隔)**: 実装作業の前に、
    `BM_ONIONPEER_REANNOUNCE_INTERVAL_SECONDS`(7380秒)が本家より過剰ではないかを検討した。
    本家の`sendOnionPeerObj`には
    `if state.Inventory.by_type_and_tag(objectType, tag): return  # not expired`
    という早期returnがあり(tagは`port + host`のみのhashで時刻を含まないため自ノードでは不変)、
    ソースだけ読むと実効間隔はTTL(本家は7日)相当に見える。これを根拠に一度は
    「我々は本家の約80倍の頻度で流している」と判断しかけたが、**ユーザーから
    「journalctlで見る限り`discovered v3 onion peer`で同じアドレスが2時間おきに飛んできている、
    実態では早期リターンしていないのでは」との指摘があり、実測で否定された。**
    直近20時間のjournalをアドレス別に集計すると、外部2ノードがいずれもちょうど125分
    (≒7500秒)間隔で同一アドレスを再announceし続けていた(10回・9回)。125分は本家
    `singleCleaner`のループが`cycleLength`(300秒)ごとに`tick - 7380`を判定する構造から
    出る値(7380を300の倍数へ切り上げると7500)と一致する。つまり早期returnは実ネットワーク上
    では効いておらず、本家の実挙動は我々の7380秒とほぼ同じ。早期returnが効かない理由は
    ソースからは特定できていない(`by_type_and_tag`のSQL経路も`flush`のtag書き込みも
    正しく見える)。参考までにMiNode-Refined(`minode/manager.py:publish_tor_onion`)は
    TTL 7日 + `REFRESH_MARGIN` 45分で明示的にスキップしており、実装ごとに方針が割れている。
    以上より間隔は7380秒のまま変更しない。CLAUDE.mdの「本家との一致・不一致は必ず実ソースを
    確認してから判断する」について、**実ソースを読んでもなお実挙動とは異なりうる**という
    実例として記録しておく(この経緯は`object_sync.c`の当該`#define`のコメントにも残した)。

    なお`bm_peer_registry_pick_random_dandelion_peer`は既に`BM_SERVICE_NODE_DANDELION`と
    outbound(`BM_FD_CLIENT_SOCKET`)で絞っており、本家invthread.pyの「stem先がNODE_DANDELION
    非対応ならfluffへフォールバック」という意図と揃っている。こちらは変更不要。

    **残件**: 上記対応後も`send_big_inv`が新規ピアへ保有hash全件を送る挙動自体は変えていない
    ため、起動直後のannounceは「最初のピア確立時のannounce」と「そのピアへのbig inv」の両方に
    乗りうる(重複はhashが同じなので受信側で吸収される)。また`bm_dandelion_expire_and_refluff`
    のfluffは`except=NULL`で呼ばれており、直前にdinvを送ったstem successorにも改めてinvが
    飛ぶ(相手は通常getdata済みなので無害だが1パケット無駄)。どちらも優先度は低い。

33. **`bm_peer_manager_seed_bootstrap`が`BM_TOR_CONTROL`利用時の真の新規インストールで
    空振りするバグを修正**: 2026-09-15、項目23(ゴースト接続調査)の再現実験用に、
    報告当時のコミット(`8b96ada`)を、**DBファイルが存在しない真の新規インストール
    状態**かつ`BM_TOR_CONTROL=1`で起動したところ、**起動後何十秒経っても
    outbound接続が1本も試みられない**(`connecting to ...`のDEBUGログすら出ない)
    現象に遭遇し、副産物として発見した。

    原因は`bm_peer_manager_seed_bootstrap`(`src/core/peer_manager.c`)の「`hosts`
    テーブルが空の時だけmainnet seed 9件+`observed_nodes.txt`3件を投入する」という
    ガード(`SELECT COUNT(*) FROM hosts;`)。`main.c`は`BM_TOR_CONTROL`で作成した
    自分自身のonionアドレスを`bm_peer_manager_mark_self`で`is_self=1`として`hosts`へ
    登録するが、この登録は`peer_connector_thread`(この関数の唯一の呼び出し元)の
    起動より必ず先に走る。そのため真に新規(DBファイルが存在しない)インストールでは、
    seed_bootstrapが呼ばれた時点で既に自分自身の1行が入っており`existing > 0`が
    真になるため、mainnet seed/observed nodesが一切投入されない。接続候補が
    自分自身(`list_top`で`is_self=0`により除外される)しか無い状態になり、
    `peer_connector`は永久に候補ゼロのまま何もしない。

    daemon Aは既にpeers.dbが確立済みなので実害は無いが、`BM_TOR_CONTROL=1`で
    真っさらな状態から起動する新規ユーザー(またはDBを作り直したテスト環境)は
    確実にこれを踏む。

    **修正**: ガードのSQLを`SELECT COUNT(*) FROM hosts WHERE is_self = 0;`に変更した。
    `is_self=1`の行は元々`list_top`の候補選定からも除外されている(2026-08-22、
    項目未採番)のと同じ理由で、空判定でも無視するのが一貫している。1行の修正で
    済んだため、`main.c`側の初期化順序(mark_selfとpeer_connector_thread起動の
    前後関係)には手を付けていない。ビルド警告ゼロ、ctest 46件100%通過。

    なお、この副産物の発見に至った項目23再現実験そのものでは、
    一時「単一スレッドが1接続の大量受信処理に占有され、他接続のidle_sweep/epoll_wait
    ディスパッチが長時間止まる」という仮説を有力視しかけたが、これは`idle_sweep_one`/
    `bm_network_epoll_thread`の調査用ログが両方とも`!conn->handshake_complete`の
    時にしか出力されない条件付きログであることを見落とした誤読と判明し(ユーザー
    指摘により発覚)、撤回した。項目23の根本原因は本項目時点でも依然未解決のまま。

34. **`bm_peer_registry_broadcast_inv`に所要時間計測を追加(項目23の別仮説の検証用計装)**:
    2026-09-15、項目33の調査の副産物として、`handle_object`(object_sync.c)が**新規object
    受信のたび毎回同期的に`bm_peer_registry_broadcast_inv`を呼んでいる**ことに気付いた
    (ユーザー指摘で発覚)。この関数は主にnetwork_epoll_thread自身から呼ばれるため、
    宛先peerの中に送信バッファが詰まった(TCP的にはまだ生きているが応答が返らない)ものが
    混じっていると、`bm_network_write_all`が`select()`で最大`BM_NETWORK_WRITE_TIMEOUT_
    SHORT_SECONDS`(2秒)ブロックしうる。新規objectを受信するたびにこれが繰り返されると、
    詰まったpeer数×2秒がobject受信のたびに積み上がり、network_epoll_threadがepoll_wait/
    idle_sweepへ戻れない時間が伸びる、という項目23の別の(項目33直前で撤回した「単一
    read()バースト」仮説とは異なる)有力候補が浮上した。実際に項目23の2026-09-05調査では
    `ss`コマンドで該当peerがCLOSE-WAIT・Recv-Q=130バイト残留という「TCP的にはまだ生きて
    いるが応答が無い」状態だったことを確認済みで、この仮説と整合する。

    ただし実測でしか確証は得られないため、`bm_peer_registry_broadcast_inv`の書き込み
    ループ(`CLOCK_MONOTONIC`、壁時計time()はNTP補正で巻き戻りうるため使わない)の所要
    時間を計測し、既存のサマリログ(`broadcast inv: ...`)へ`took Nms`を追記した。加えて
    `BM_BROADCAST_INV_SLOW_WARN_MS`(500ms)以上かかった場合はDEBUGを有効にしなくても
    見えるようWARNでも出す。2026-09-15にidle_sweep/epoll_wait調査ログが`!handshake_
    complete`時にしか出ない条件付きログだったと気付かず誤った結論を出した反省を踏まえ、
    今回の計測ログは接続の状態に一切依存しない無条件のログにした。

    計測コード自体はログ出力のみに使い戻り値・分岐等の制御フローには一切影響しないため、
    CLAUDE.mdの「time(NULL)を直接呼ばない」方針(決定ロジックの決定性確保が目的)の対象外と
    判断し、`clock_gettime`を直接呼んだ(コメントで根拠を明記)。

    **テストは追加しなかった**(ユーザーと合意の上)。正確に検証しようとすると小さい
    `SO_SNDBUF`のsocketpair等で実際に`BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS`(2秒)分
    ブロックさせる統合テストが必要になり、ctest全体を2秒以上延ばしてまで足すほどの
    リスクではない(hash数・evicted数等の既存ロジックは一切変更していない)と判断した。
    既存の`test_peer_registry_evict`等が引き続き全通過することで、この既存ロジックへの
    非破壊は確認済み。ビルド警告ゼロ、ctest 46件100%通過。

    次に本番daemon Aまたは試験用インスタンス(項目23参照)で長時間ログ途絶が再発した際、
    この`took Nms`ログとWARNの有無を確認することで、本仮説を直接検証できる。

35. **CLIの`send-message`/`send-broadcast`へ`--body-file`を追加し、併せて欠落していた
    subject+body長の上限検査を新設**: 2026-09-16、ユーザーから「CLIのsend-messageに長文の
    メッセージボディを付けられるようにしたい。ファイルを指定して読ませるのが適切か」との
    相談があり、設計を検討した上で実装した。

    **なぜファイル経由が必要か。** 従来`send-message`は本文を`argv[5]`としてそのまま受け取って
    いた。問題は「長い文字列を渡しづらい」ことよりも、渡せてしまった場合の実害の方にある:

    - 本文が`ps aux`で他ユーザーから丸見えになる。メッセージ本文としてはこれが最も深刻
    - シェル履歴に本文が残る
    - 改行を含む本文のクォートが現実的でなく、`$(cat ...)`で回避しても`ARG_MAX`の制約が残る

    **インターフェースの選択。** curl流の「本文が`@`で始まったらファイル名とみなす」方式は
    検討した上で却下した。`@teruteruさん、`のように`@`で始まる本文はメッセージとして普通に
    あり得るので、既存の呼び出しの意味を黙って変えてしまうため。代わりに明示的な
    `--body-file <path>`オプションとし、pathが`-`なら標準入力から読む。標準入力に対応したのは、
    上記(1)(2)を完全に回避できる経路(`--body-file - <<'EOF'`等、本文をファイルにもコマンド
    ラインにも置かない)を用意するため。`send-broadcast`にも同じオプションを付けた。

    実装(`src/cli/main.c`)は、argvから`--body-file`とそのパスを取り除き、読み込んだ本文を
    位置引数`<body>`の位置へ挿入した新しいargvを組み立てる方式にした(`apply_body_file_option`)。
    こうすることで各コマンドのハンドラは従来通りの位置引数だけを見ればよく、「本文が
    位置引数の場合」と「`--body-file`の場合」で引数の数え方を二重に持たずに済む。

    **副産物として`ttlSeconds`/`ackStealthLevel`のパースを厳格化した。** 従来は`atof()`を
    そのまま使っており、数値でない文字列は黙って0になっていた。`--body-file`を指定しつつ
    位置引数の`<body>`も書いてしまうと本文が`ttlSeconds`の位置へずれ込むため、この誤りが
    「ttl=0で送信される」形で表面化してしまう。`strtod`+末尾検査の`parse_number_arg`を
    追加して明示的に弾くようにした(この誤りは`--body-file`以前からtypoで起こり得たので、
    結果的に既存の挙動も改善している)。

    **サーバー側: 本文長の上限検査がどこにも無かった。** 本件の調査中に、`h_sendMessage`にも
    `h_sendBroadcast`にも本文長の検査が一切無いことが判明した。上限超過は
    「PoWを回し切った後に`infra/object_sync.c`の`BM_MAX_OBJECT_PAYLOAD_SIZE`(=1<<18)で
    弾かれる」という形でしか現れず、長時間待たされた末に配信されないことになる。

    PyBitmessage本家の実ソースを確認したところ、`src/api.py:1212`(`HandleSendMessage`)と
    `src/api.py:1258`(`HandleSendBroadcast`)の両方に

    ```python
    if len(subject + message) > (2 ** 18 - 500):
        raise APIError(27, 'Message is too long.')
    ```

    があり、本家はAPI呼び出しの入口で弾いている。これに合わせ、上限値を
    `src/common/message_limits.h`の`BM_MAX_SUBJECT_PLUS_BODY_LEN`(= 2^18 - 500 = 261644)
    として新設し、`check_subject_body_length`(api_server.c)を`h_sendMessage`/
    `h_sendBroadcast`の双方から呼ぶようにした。2^18はオブジェクトpayloadの上限そのもので、
    そこから引く500バイトのマージンは本家のコードにも根拠のコメントが無いが、msgフォーマットの
    ヘッダ・署名・暗号化に伴う増分を吸収するためのものと読める。**独自に広げると本家ノードが
    中継しないサイズのオブジェクトを作りうるため、あえて本家と同じ値のままにしている。**

    `h_sendMessage`では、この検査をgetpubkey要求の自動送出**より前**に置いた。順序を逆にすると、
    送れないと分かっているメッセージのためにネットワークへgetpubkeyを流してしまうため。
    CLI側(`apply_body_file_option`)でも同じ基準で先に弾いているが、これはHTTPへ載せる前に
    落として待ち時間を減らすための早期検査であり、API直叩きの経路が残る以上サーバー側の
    検査が本体である。

    **その他の設計判断:**

    - NULバイトを含むファイルは明示的に拒否する。JSON文字列にもC文字列にも載らないため、
      黙って切り詰めると本文の一部だけが送信されてしまう
    - ファイルは`"rb"`で開き、末尾の改行も含めて内容をそのまま本文とする(勝手にstripしない)
    - 読み込みは上限バイト数を超えた時点で打ち切る。でないと巨大なファイルや終わらない
      標準入力を指定された場合に、エラーを出す前にメモリを食い尽くす。打ち切っているため
      エラーメッセージのバイト数表示には「以上」を付け、実サイズだと誤解させないようにした
    - `common/json.c`の`sb_append_escaped_string`は`unsigned char`で走査しておりUTF-8を
      そのまま通すので、日本語本文でも`\u`エスケープによるリクエストサイズの膨張は起きない。
      上限261644バイトの本文はAPIの`MAX_REQUEST_SIZE`(1MiB)に対して十分余裕がある

    **テスト:**

    - `tests/test_cli_integration.sh`に`--body-file`一式を追加。本文が実際にそのまま届くことを
      確認したいので、自分自身宛の`send-message`(is_self)を使っている。`send_pipeline.c`は
      is_selfの場合に送信と同時に自分のinboxへコピーを入れるため、`get-inbox`で本文を読み返せ、
      pubkey_cacheへの事前登録も要らない。改行・引用符・バックスラッシュ・マルチバイト文字を
      含む本文が保たれることを検証している。加えて標準入力経由、`send-broadcast`での動作、
      およびエラー系(存在しないファイル/パス書き忘れ/NULバイト/上限超過/`--body-file`と
      位置引数`<body>`の併記)を網羅した
    - `tests/test_api_server.c`にサーバー側の上限検査を追加。上限+1バイトで
      `sendMessage`/`sendBroadcast`がエラーになること、および上限ちょうどが長さ検査を
      通ることを確認する。後者は実際に送信まで通すと256KiB級payloadのPoWが走り現実的な時間で
      終わらない(PoWの必要試行回数はpayload長にほぼ比例する)ため、fromAddressだけを
      identity.dbに無いアドレスにして、長さ検査を通過した先のsend_pipelineで(PoWより手前で)
      失敗させ、「長すぎる」以外の理由のエラーになることをもって判定している
    - 同テストの`do_request`は`char request[8192]`固定長だったため、256KiB級のリクエストでは
      snprintfが黙って切り詰めて壊れたリクエストを送ってしまう。ヒープ確保へ変更した

    上限検査を一時的に無効化して回帰を確認したところ、`api_server`テストが失敗すると同時に
    実行時間が7秒から116秒へ伸びた。これは検査が無い場合に実際に256KiB payloadのPoWが
    走ることの実測であり、本検査が回避しているコストがそのまま現れた形になっている。

    **併せてREADME.mdの`send-message`の例を修正した。** commit 8dca672
    (§11 2026-08-30、sendMessageから`toPubEncryptionHex`引数を廃止)の際に更新漏れがあり、
    README.mdの例が廃止済み引数のプレースホルダ`-`を残した
    `send-message BM-from BM-to - "subject" "body" 3600 1`のままだった。現在の実装では引数が
    1個多く、そのまま実行すると使い方エラーになる状態だったので、正しい形に直した上で
    `--body-file`の例を追記した。

    ビルド警告ゼロ、ctest 46件100%通過。

36. **User Agent文字列を`BitmessageC`から`CBitmessage`へ変更**: 2026-09-17、ユーザー指摘。
    2026-08-26(項目未採番、本コメント直上参照)に`bitmessage-c`から`BitmessageC`へ変更した
    際、本家`PyBitmessage`(言語プレフィックス+Bitmessage)の命名パターンと語順が逆になって
    いることに気づかなかった。本家のUA検証正規表現`^/[a-zA-Z]+:[0-9]+...`は語順を区別しない
    (`BitmessageC`/`CBitmessage`どちらも`[a-zA-Z]+`のみで満たす)ため、当時の変更はハイフン
    除去だけが目的で語順は単なる選択ミスだった。長期運用前提のプロジェクトなので、今のうちに
    一貫性のため修正した(`src/main.c`の`BM_USER_AGENT`定義1箇所のみ)。相互運用性への実害は
    無い(UA文字列の中身を見て挙動を分岐させる処理は無い)、純粋に見た目の一貫性のための変更。
    ビルド警告ゼロ、ctest 46件100%通過。daemon Aへのデプロイはbuild-RelWithDebInfoで別途行う
    (メモリfeedback_deploy_relwithdebinfo.md参照)。

37. **ポスト量子(ML-DSA / ML-KEM)拡張の提案ドラフトとプロトタイプ**: 2026-09-17、ユーザー依頼。
    設計提案は独立した文書 [DESIGN-PQ.md](DESIGN-PQ.md) に分離した(§0〜§10が現行v1実装の
    設計であるのに対し、こちらは未実装の将来拡張の提案であり性格が違うため)。調査・判断の
    経緯はDESIGN-LOG.mdの2026-09-17の節。
    現時点の成果物は「アドレスv5 + v5オブジェクト(getpubkey/pubkey/msg/broadcast)の
    プロトタイプ実装(`src/pq/`)、vendorしたML-DSA/ML-KEM参照実装(`third_party/pqcrystals/`)、
    ベンチマークツール(`bm-pq-bench`)、テスト3件」で、**daemon本体(bm_core/bm_infra)からは
    一切参照していない**。実運用へ組み込む段階のロードマップはDESIGN-PQ.md §9、
    未解決事項(本文長上限の再設定・pubkey v5のPoWが重い問題・identity.dbスキーマ・
    X-Wingテストベクタでの検証)は同§9.3。ビルド警告ゼロ、ctest 49件100%通過。

    同日のユーザーとの往復で3点が確定・追加された(詳細はDESIGN-LOG.md)。(a) ハイブリッドの
    古典側はEd25519/X25519で確定。(b) id先頭1byteの0x00要求は「アドレス長を揃えたい」
    という理由で採用し、鍵導出を4成分独立(root→成分別サブseed)に組み替えて
    「どの成分を引き直して探索するか」を選べるようにした(既定はユーザー提案のX25519、
    v4の13分の1のコスト)。(c) オブジェクト発行のPoWを実オブジェクト6種で実測した結果、
    **v5 pubkeyは16コアで期待144秒**かかることが分かり、`network_epoll_thread`を
    ブロックしない形へPoWを追い出す改修がv5実装の前提条件という結論になった
    (DESIGN-PQ.md §8.4・§9.3)。

    2026-09-18の設計レビュー第2ラウンドで、初版に足していた「モダンな作法」の多くを
    取り下げてv4の意味論へ揃える方向に単純化した(詳細はDESIGN-LOG.md)。
    (a) ドメイン分離ラベルはパスフレーズ由来のseed導出1箇所を除いて全廃(署名対象には
    共通ヘッダが含まれるので種別間の分離は既に達成されている)。(b) idは
    `SHA3-256(pk_sig || pk_kem)` に簡約し、version/streamを混ぜるのをやめた(束縛はtagと
    署名対象のヘッダが担っており二重だった一方、v3/v4のripeが持つ「同じ鍵を別version・
    別streamでも表現できる」性質を潰す副作用があった)。(c) 前回の4成分独立導出を撤回し、
    決定性生成はv4と同じ2 nonce構成へ戻した(KEM鍵はX-Wing仕様通りseed 1本から生成し、
    探索ではKEM鍵ペアをまるごと引き直す。期待43ms、v4は313ms)。ランダム生成は
    X25519だけを引き直す(1本14.7ms)。経路ごとに作法が違うのはv4も同じ
    (本家のcreateRandomAddressは署名鍵を固定して暗号化鍵だけ引き直している)。
    さらに同日の追加検討で、(c)の「決定性生成でKEM鍵だけ引き直す」最適化も撤回し、
    v4と同じ「両方のnonceを2ずつ進める」に戻した。節約81msに対しpubkey告知PoWが141秒で
    効果が0.06%しかないうえ、署名鍵をstart_nonceだけで決めると同じstart_nonceで
    null_bytesを変えた2本のアドレスが署名鍵を共有し公開的に紐付け可能になる穴があった
    ため。結果、決定性・ランダムの両経路ともv4と同じ作法に収束した。


38. **PoWをワーカースレッドへ追い出す(呼び出し元スレッドをブロックしない形にする)**: 2026-09-18に
    規模を見積もり、backlogへ登録。現状`bm_pow_run`は全て同期呼び出しで、**呼び出し元スレッドを
    PoWが終わるまで止める**。特に`object_sync.c`のpubkey自応答は`network_epoll_thread`を止めるため、
    その間すべてのピア接続が停止する(§5.1の既知の制限。v4で実測20秒超)。
    **ポスト量子v5ではこれが期待141秒になり許容できなくなるため、v5実装の前提条件**
    ([DESIGN-PQ.md](DESIGN-PQ.md) §8.4・§9.3)。ただしv4でも20秒のブロックが消えるので、
    **v5とは独立に価値がある**。

    設計は既にある(§1.1の`pow_worker_thread`、§1.2の`pow_request_queue`/`pow_result_queue`。
    `main.c`の`struct bm_queues`に両キューが定義・init済みで未使用。`bm_queue_t`は
    `broadcast_queue`で実績あり。`bm_send_pipeline_thread()`もスタブとして存在する)。
    したがって新規設計ではなく**配線が主**。

    呼び出し箇所は6つで、性質が2つに割れる:

    | 箇所 | ブロックするスレッド | 分類 |
    |---|---|---|
    | `object_sync.c` pubkey自応答 | **network_epoll_thread** | A |
    | `object_sync.c` onionpeer announce | peer_connector_thread | A |
    | `api_server.c` getpubkey自動要求 | api_server_thread | A |
    | `send_pipeline.c` ack object | api_server_thread | B |
    | `send_pipeline.c` msg | api_server_thread | B |
    | `send_pipeline.c` broadcast | api_server_thread | B |

    **A: 撃ちっぱなし系(3箇所)。** 戻り値を待つ呼び出し元が無く、PoW後の処理も
    ほぼ同一(`nonce前置 → inventory_hash → object_store_insert → broadcast_inv`。
    pubkeyのみ`bm_pubkey_cache_set_self_response`が1行増える)。ジョブ+完了フックの形に
    すれば素直に非同期化できる。

    **B: send_pipeline(3箇所)。** 2つの厄介さがある。(1) **ackのPoWがmsgのPoWの前段に
    必要**(ackPayloadは暗号化されるmsg本文の中に埋まるため)。つまりsendMessageは依存関係の
    ある2段PoWで、ジョブ1本では表現できない。(2) `h_sendMessage`が現在
    `{objectLength, inventoryHash}`を**同期で返している**ので、非同期化するとAPIの契約が変わる。
    本家PyBitmessageはsendMessageが`ackData`を即返してsingleWorkerが裏でPoWする形なので、
    寄せるならその契約になる。

    **段階と規模の見積もり:**

    - **Tier 1(v5のブロッカー解消に必要な最小、300〜450行、1セッション)**: Aの3箇所だけ。
      実害のあるバグは「network/peer_connectorが止まる」であって、APIスレッドが止まるのは
      不細工だがピア接続は落ちない。`src/pow/pow_queue.[ch]`(新規、ジョブ構造体+ワーカー
      スレッド+完了フック)、`object_sync.c` 2箇所と`api_server.c` 1箇所の差し替え、
      `main.c`へのスレッド起動/join、テスト1本(低難易度で「最終的にobject_pool.dbへ入る」
      ことを確認、既存テストと同じ手法)。
    - **Tier 2(send_pipelineも非同期化、さらに400〜600行、1〜2セッション)**:
      `send_request_queue`の結線と`bm_send_pipeline_thread`の実装、ack→msgの2段チェーン、
      sentテーブルのstatus遷移追加。**コード量より既存テストの改修が主コスト**で、
      `test_send_pipeline`/`test_api_server`/`test_broadcast`/`test_getpubkey_automation`/
      `cli_integration`が同期完了を前提にしているため全てに待ち合わせが要る。

    **実装時の注意2点:**

    - **ワーカーは1本にする。** §1.1の`pow_worker_thread × NumCPU`という記述は誤り
      (同節の2026-09-18追記参照)。`bm_pow_run`が内部で既に全コアへstride分割しているため、
      ワーカーをNumCPU本立てると過剰購読になる。
    - **キャンセル手段を足す。** v5 pubkeyの141秒PoWが走行中だとshutdownのjoinがそれだけ
      待たされる。`bm_pow_run`は既に`atomic_bool *found`で早期打ち切りする作りなので、
      `cancel`フラグを追加するのは10行程度。
    - (既知の割り切り)ジョブは直列処理なので、長いジョブ(v5 pubkey)が先行すると後続の
      msgが待たされる。v1では優先度キューまでは作らない。

39. **v5オブジェクトが「v5を理解しないノードを経由して」届くことの実地検証**: 2026-09-18、
    ユーザーとの議論で構成が決まったのでbacklogへ登録。項目37・[DESIGN-PQ.md](DESIGN-PQ.md) §2の
    「既存ノードはv5オブジェクトを理解しないまま正常に中継する」という主張は、提案全体が
    そこに乗っている最重要の前提でありながら、**現状はPyBitmessage・MiNode-Refined・本実装の
    3実装のソースを読んだだけで、実際に流して確かめてはいない**。ここを実測に変えられると
    提案の強度が一段変わる(「仕様を認めてください」ではなく「動いています、経路はこうです」
    から入れる)。

    **構成:**

    ```
    A(v5送信) → v5を一切知らないノード → B(v5受信)
    ```

    中継ノードは**v5を知らないこと**だけが要件なので、v5対応より前のコミットから
    ビルドしたインスタンスを1本用意すれば足りる(本家PyBitmessageでもよい。
    その場合「本家が中継した」という、より直接的な結果になる)。
    v5対応が必要なのは送信側と受信側の2本。

    **観測すべき点:** (1) 中継ノード側のログに、pubkeyなら`pubkey object too short or too long`
    相当、msg/broadcastならversion判定によるスキップが出ていること(=中身を理解していない
    ことの確認)。(2) それにも関わらず中継ノードが`inv`を再広告し、Bが**中継ノード経由で**
    そのオブジェクトを取得できること。(3) Bで復号・署名検証まで通ること。

    **より強い版:** 中継を本番ネットワーク(あるいはtestnet)そのものにする。Aから流した
    v5オブジェクトをBが**ネットワーク経由で**拾えれば、「第三者のノードを通しました」という
    実測になり、本家への提案材料として最も強い。

    ただしこの版は**他人のinventoryに未知のオブジェクトを置くことになる**点に配慮が要る。
    PoWは正規に払っており、サイズも2^18以内、legacy側はversion判定で復号を試みる前に
    捨てるため負荷は通常のメッセージと変わらないが、礼儀として**TTLを短めに(4日ではなく
    数時間)・個数を最小限に**し、相手がいるならtestnet側で行うのが望ましい。

    **前提:** DESIGN-PQ.md §9のフェーズ2〜3(受信側・送信側の実装)まで進んでいること。
    それ以前に項目38(PoWのワーカースレッド化)が必要(v5 pubkeyのPoW 141秒で
    `network_epoll_thread`が止まると、そもそも実験中にピア接続が維持できない)。

40. **web UIを付けるならどのインターフェイス経由にするか(思考実験、実装予定なし)**: 2026-09-19、
    ユーザーとの議論。「webインターフェイスを付けるとしたらJSON-RPC経由は効率が悪いので、別の
    インターフェイス経由で作ることになるのでは」という問いから始まった検討の記録。**現時点で
    実装する予定は無い**が、いざ着手するときに同じ検討を一からやり直さずに済むよう、結論と
    根拠を残しておく。

    **(1) 「JSON-RPCが非効率」の中身は3つあり、どれもエンコーディング由来ではない**

    - **一覧APIの形状**: `h_getInboxMessages`(`src/core/api_server.c`)は`folder`で絞る以外の
      手段を持たず、`limit`/`offset`/`since`/フィールド射影がいずれも無い。一覧画面を描くだけで
      全件の`body`が付いてくる。1通の上限は`BM_MAX_SUBJECT_PLUS_BODY_LEN` = 261,644バイト
      (`src/common/message_limits.h`)なので、通数が増えるほど素朴なポーリングが重くなる。
    - **応答生成で3重に持つ**: `bm_messages_store_list_inbox`が全行をstruct配列へmalloc →
      cJSONツリーへコピー(エスケープ込み) → `cJSON_PrintUnformatted`で1本の文字列へ、と
      inbox全体が同時に3つメモリに乗る。`queue_text_response`も単一バッファ前提でストリーミング
      していないため、ピークメモリがinboxサイズに対して無制限。
    - **pushが無い**: 新着を知る手段がポーリングしかない。本家の`apinotifypath`(§6の調査記録)も
      内部イベント発生時に外部コマンドを起動する代用品で、本実装には移植していない。

    **つまりJSONをprotobufに替えても3つのどれも解決しない。** 替えるべきなのはワイヤー
    フォーマットではなく相互作用のモデルである、というのがこの議論全体の結論。

    **(2) 分岐点: そのUIをどこから叩くか**

    localhostのブラウザから叩くなら帯域は事実上無限でRTTはループバック、「効率」が指すのは
    バイト数ではなくdaemon側のCPU・メモリとポーリングの無駄になる。onion越しに自分のノードを
    見る形にするならRTTが500ms〜数秒になり、ここで初めて往復回数が支配的になる。どちらを
    前提にするかで答えが変わるので、設計の最初に決めること。

    **(3) 候補の評価**

    - **gRPC**: 却下。ブラウザは生のgRPCを喋れずgrpc-web+プロキシが経路に要るので、*web*
      インターフェイスの手段としては構造的に遠回り。grpc-coreも実質C++で、xmlrpc-c/CURLを
      採らなかった依存方針(§10)と衝突する。
    - **protobuf / MessagePack / FlatBuffersを既存HTTPに載せる**: 効く場所が違う。削れるのは
      JSONエスケープとパースのCPUだけで、それを食っている本体は本文。本文を一覧に載せるのを
      やめれば消える問題であり、代わりにブラウザ側デコーダが要り`curl`でのデバッグも失う。
    - **WebSocket**: MHDの`MHD_USE_UPGRADE`は生ソケットを渡してくるだけなので、RFC 6455の
      フレーミング・マスク解除・ping/pong・closeハンドシェイクを全て自前で書くか依存を増やす
      ことになる。双方向が効くのはclient→serverが高頻度な場合で、読み中心のメールUIでは対価が
      見合わない。
    - **UDS + 別プロセスのフロント**: 分離としては正しい。daemonがブラウザとHTTPを喋らなく
      なるので、XSS/CSRF/DNS rebindingの受け口がC実装から消える。増えるのはプロセスとIPC
      プロトコル設計の分。
    - **messages.dbを読み取り専用で直接開く(CQRS)**: 最安。既に`journal_mode=WAL`
      (`src/common/db_common.c`)なので書き込みを止めずに並行読み取りでき、ページング・
      ソート・FTS5全文検索がプロトコル設計ゼロで手に入る。代償はスキーマが公開APIになって
      気軽に変えられなくなること、および`identity.db`を絶対に同じ経路へ乗せない規律。

    **(4) 採るならこの形: トランスポートはHTTP+JSONのまま、相互作用モデルだけ変える**

    既存のMHD daemonに`api_access_handler`でのパス分岐を足し、以下を追加する:

    1. **一覧を射影付きRESTにする** — `GET /inbox?folder=inbox&limit=50&cursor=...`が返すのは
       `{msgId, from, subject, receivedTime, read}`だけで、本文を含めない。
    2. **本文を独立リソースにして不変キャッシュを効かせる** — inboxの`msg_id`はobjectの
       inventory hash、すなわち**コンテンツアドレス**である(`src/core/messages_store.h`の
       `bm_messages_store_insert_inbox`コメント)。`GET /messages/<hash>/body`に
       `Cache-Control: max-age=31536000, immutable`を付ければ、各本文は生涯に一度しかワイヤを
       渡らない。**JSON-RPC over POSTは仕様上キャッシュ不可なので、これは構造的に真似できない。**
       (2)でonion越しを選んだ場合に効き方が桁違いになるのはここ。
    3. **`GET /events`をSSEにする** — MHDは`MHD_create_response_from_callback`でチャンク応答を
       作れるのでSSEは素直に載る。新着・接続数変化・送信ステータス遷移をpushしてポーリングを全廃。
    4. **一覧応答をストリーム生成する** — `sqlite3_step`しながらコールバックでJSONを吐けば、
       メモリがO(inbox)から定数になる((1)の2つ目の解決)。

    JSON-RPCはそのまま残す(CLI・テスト・本家互換がぶら下がっている)。§6.1の「ハンドラ辞書と
    トランスポートを分離した設計」のおかげで、`METHODS[]`は手付かずでパス分岐だけ足せる。

    **(5) 実装時に必ず踏む罠(MHD固有)**

    - `MHD_OPTION_CONNECTION_TIMEOUT`が30秒(`BM_API_CONNECTION_TIMEOUT_SECONDS`)なので、
      **SSE接続が黙って切られる。** keep-aliveコメント行を定期送出するか、SSEのパスだけ
      タイムアウトを免除する必要がある。
    - `MHD_OPTION_CONNECTION_LIMIT`が64(`BM_API_CONNECTION_LIMIT`)。SSEは張りっぱなしなので、
      タブを開くたびに枠を1つ占有し続ける。
    - `MHD_USE_INTERNAL_POLLING_THREAD`下でレスポンスコールバックがブロックするとpollループごと
      止まるため、イベント待ちは`MHD_suspend_connection`/`MHD_resume_connection`で行う。素直に
      書くとビジーループになる。
    - **イベント源が現状どこにも無い。** 新着の発生点は`trial_decrypt.c`・`broadcast_decrypt.c`・
      `send_pipeline.c`の3箇所の`bm_messages_store_insert_inbox`呼び出しで、ここにフックを挿して
      既存の`bm_queue_t`へ積む形になる。keep-alive送出は「周期処理のために専用スレッドを
      新設しない」方針(CLAUDE.md)に従い`peer_connector_thread`の1秒ループへ相乗りさせる。
      判定に使う時刻は他と同様`int64_t now`引数で受ける。

    **(6) 効率より重いのはセキュリティ側**

    - **DNS rebinding**: ブラウザUIを127.0.0.1に置くと任意のWebページが到達を試みられる。
      Basic認証はオリジンが違えば送られないので一枚は守れるが、GETを無認証にした瞬間に穴になる。
      `Host`ヘッダ検証 + CORS全拒否 + セッショントークンが要る。
    - **本文のレンダリングがXSSになる**: `body`は完全に攻撃者制御の文字列で、同一オリジンから
      スクリプトが走ればinbox全件とアドレス一覧が抜かれる。プレーンテキスト固定 + 厳格なCSP
      (`default-src 'none'`)以外に安全な道は無い。
    - **外部リソースを1つも読まない**: フォント1つCDNから引くだけでノードを見ている事実が漏れる。
      UI資産は全てdaemonから配る。
    - **onionで公開する場合**、UIを別のonionサービスにするか同じものへ相乗りさせるかで、
      ノードのonionアドレスとUIのリンカビリティが変わる。公開経路にするなら最初に決めること。

    **(7) 派生議論: libを拡張機能(dlopen)として読めるようにする案 — 不採用**

    「トランスポートだけプラグインで差し替えられるようにすれば」という案も検討したが、
    **効率は1ミリも動かず、攻撃断面とABI凍結の負債だけが増える**という結論になった。

    - **ボトルネックが継ぎ目の向こう側にある。** (1)の3つは全てコア側の問題で、
      `bm_messages_store_list_inbox`が全行をmallocして返す構造は呼び出し元がプラグインでも
      本体でも変わらない。プラグインを効率面で意味あるものにするには、カーソル付き逐次読み出しや
      射影を**プラグインABIとして公開**することになり、結局`messages_store`/`keyring`/
      `peer_registry`の内部APIをほぼ全部エクスポートする羽目になる。それはもう継ぎ目ではない。
    - **本家が何をプラグイン化しているかが示唆的。** PyBitmessageには実際にプラグイン機構が
      あるが(`src/plugins/`、`setup.py`の`entry_points`)、拡張ポイントは
      `bitmessage.gui.menu`(QRコードのメニュー項目)・`bitmessage.notification.message`/`.sound`
      (notify2、canberra、gstreamer)・`bitmessage.indicator`(libmessaging)・
      `bitmessage.desktop`(XDG)・`bitmessage.proxyconfig`(stem)の6群で、**全てが周辺・表示・
      OS統合であり、データ経路上のものが1つも無い。** ネットワークプロトコル・ストレージ・暗号・
      APIトランスポートはどれもプラグイン化されていない。ロード機構も
      `pkg_resources.iter_entry_points`(`src/plugins/plugin.py`)で、ディレクトリに置いたファイルを
      拾うのではなくインストール済みディストリビューションからの発見である。
    - **アドレス空間を鍵と共有する。** `bm_keyring_t`はunlock済み秘密鍵をin-memoryで保持する
      (§7.2、`struct bm_unlocked_identity`)。web UIプラグインの1つのバグがそのまま全identityの
      秘密鍵読み出しになり、分離のつもりの仕組みが分離ゼロの場所に置かれることになる。
    - **ABIが凍る。** `struct bm_api_server_config`や`struct bm_inbox_message`のレイアウトが
      契約になる。このプロジェクトは`is_self`・`last_attempt`・`folder`を`ALTER TABLE`で足して
      いく運用(CLAUDE.md)で構造体フィールドも同様に足してきたので、シンボルバージョニング
      無しでそれを続けると古いプラグインが黙って壊れる。
    - **規約が強制できない。** 「専用スレッドを新設しない」「sqlite3ハンドルは`SQLITE_OPEN_FULLMUTEX`
      前提で共有可」「`last_gc`は単一スレッドからのみ触る」等は全てコメントで書かれた約束であり、
      ABI越しには強制できない。長い読みトランザクションを握るプラグイン1つでWALの前提が崩れる。
    - **コード読み込み経路が新設される。** 現状のdaemonには実行時に外部コードを取り込む経路が
      1本も無い。プラグインディレクトリを作ることは、そこへ`.so`を書ける攻撃者に鍵入りプロセス
      での任意コード実行を与える永続化ベクタを生やすことであり、匿名性ソフトとして割に合わない。

    **継ぎ目が欲しいという直感自体は妥当だが、置き場所はプロセス境界である**((3)のUDS案)。
    そちらならモジュール性は同じだけ得られて攻撃断面はむしろ減る。dlopenは同じ利益を
    アドレス空間の共有と引き換えに得る版で、方向が逆。なお**コンパイル時のモジュール性は既にある**
    — `src/CMakeLists.txt`は`add_subdirectory`で6ターゲットに割っており、`bm_pq`はビルドはされるが
    `bitmessaged`の`target_link_libraries`には入っていない(DESIGN-PQ.mdの「daemon本体からは未参照」
    という状態がランタイムローダー無しで実現できている)。差し替えたいものがあるなら`option()`と
    リンク構成で足りるはずで、実行時の動的ロードが要る場面(第三者がforkせずに拡張したい)は
    現時点では存在しない。

    **(8) onion公開にした場合のマルチユーザー問題(2026-09-19の追加議論)**

    (2)でonion越しを選ぶと、「到達可能になった以上、他人にURLを渡せてしまう」という形で
    マルチユーザーが視野に入る。結論から言うと**これは踏み込まないのが正しい**。

    まず、**現状のコードには「ユーザー」という概念が1つも無い**:

    - `bm_keyring_t`はプロセスに1個だけ(`src/main.c`)で、`api_config.keyring`と
      `bm_object_sync_ctx_init`が同じ実体を共有している。unlockはプロセス全体の状態なので、
      セッションAがunlockしたアドレスはセッションBからも見える。
    - HTTP Basic認証の`username`/`password`は1組(`src/core/api_server.h`)。principalが1人しか
      表現できない。
    - §7.4のvault方式は**1つのパスフレーズで全identityが開く**設計で、「鍵の集合の所有者は1人」
      が前提。
    - 復号は`object_sync.c`の`handle_object`経路で`ctx->keyring`を使って行われる。「誰の鍵で
      開くか」がネットワーク層に溶けていて、セッションの概念を差し込む隙間が無い。

    仮にACLを付けるとして`inbox.to_address`で絞る発想になるが、**broadcastは
    `to_address`に送信者のアドレスを入れて保存している**(`broadcast_decrypt.c`の
    `bm_trial_decrypt_broadcast_and_store`は`insert_inbox`へ`decoded.from_address`を2回渡す)ため、
    `to_address`を所有者キーにしたACLはbroadcastを誤って振り分ける。chanに至っては「鍵を
    複数人が持っている」ことが定義なので、per-userのACLに最初から収まらない。

    より本質的な問題として、**daemonが鍵を持って復号する以上、運営者は全ユーザーのメッセージを
    必ず読める**。暗号で塞ぐ方法は無い(クライアント側で復号するなら、それはもうdaemonに鍵を
    預けていない別アーキテクチャ)。つまりマルチユーザーのweb UIは、**Bitmessageが無くすために
    存在している「信頼できる第三者」を、Bitmessageの上に再建する**ことになる。匿名性の面でも、
    全ユーザーが同じTor回路・同じピア接続・同じDandelion stemを通るので、匿名集合としては得でも
    区画化としては最悪で、運営者からは誰がいつどのアドレスをunlockしたかまで見える。

    そもそも**Bitmessageプロトコル自身が「複数人で1つの受信箱」の答えを持っており、それがchan
    (鍵の共有)である。サーバを共有するのではなく鍵を共有し、各自が自分のノードを走らせる。**
    プロトコルの答えは「マルチユーザーにするな」だと読むべき。

    したがって設計上は**「到達可能性」と「principalの数」を独立した軸として分けて扱う**。
    onion公開のまま厳密にシングルprincipalを保つのが筋で、そのための具体策が項目41。

    それでも本当にN人分必要になった場合の分割だけ書いておく。素朴な「1人1daemon」は、容量の
    大半を占めるobject poolが**公開データで全員同じ**なため、N本立てるとネットワーク全体の
    オブジェクトをN部持つことになり筋が悪い。取るなら:

    - **共有側 = `infra/`**(network、object_sync、object pool、Tor)。秘密を一切持たない
    - **ユーザーごと = `core/`**(keyring、trial_decrypt、messages.db、identity.db)。プロセスも分ける

    §10のディレクトリ境界がそのままこの線に一致しているのは偶然ではないが、**ランタイムの境界は
    まだ無い** — 復号が`object_sync.c`の中で走っているので、そこを「共有プールから読んで自分の
    鍵で試す」形へ切り出す必要がある。(3)のUDS分離案と同じ継ぎ目。

41. **web UI用のonionサービスをP2Pとは別に建て、v3 client authorizationを掛ける(未着手)**:
    2026-09-19、項目40(8)の議論から分離してbacklogへ登録。項目40の他の部分と違い、これは
    **web UIを作るかどうかと独立に価値がある実作業項目**(現状のJSON-RPC APIをonion経由で
    叩きたくなった時点で同じ話になる)。

    **なぜ分けるか(P2Pのonionサービスに別Portとして相乗りさせてはいけない理由):**

    1. **P2Pのonionアドレスはネットワーク全体へ公開される。** `bm_object_sync_announce_onion_peer`
       がonionpeer objectとして告知するので、全ノードが知る前提の値である。同一onionサービスの
       別仮想Portに管理UIを置くと、**Bitmessageネットワークの全参加者が管理画面の所在を知る**
       ことになる。これ単独で決定的。
    2. **client authorizationはサービス単位であってポート単位ではない。** 同一サービスに掛けると
       P2Pの到達性ごと壊れる(ピアはclient auth鍵を持っていない)。**サービスを分けることが
       client authの前提条件**であり、この2つは技術的に不可分。
    3. **ローテーションの独立性。** UI側のアドレスが漏れたと思ったとき、P2Pアドレスを変えずに
       UIだけ捨てられる。P2P側を変えると再announceと到達性の作り直しが要る。
    4. **信頼ゾーンが違う。** P2Pポートは設計上「不特定多数とワイヤープロトコルを喋る」もので、
       UIポートは「自分だけとHTTPを喋る」もの。Torレイヤの識別子を共有する理由が無い。

    コストはほぼ無い。`bm_tor_control_add_onion`は既に`(existing_private_key, virtual_port,
    local_port)`を取って`PrivateKey`を返す形なので、2本目を呼んで鍵を別途永続化するだけで済む
    (現状は`ADD_ONION %s Port=%d,127.0.0.1:%d`の1本のみ)。

    **client authorizationの効果:** 鍵を持たないクライアントはサービス記述子を復号できず、
    **接続すら張れない**。HTTPに到達する前のTor層で落ちるので、スキャナやDNS rebindingの類が
    そもそも届かず、Basic認証と違ってブルートフォースの対象にもならない。「自分のスマホからも
    見たい」は端末ごとにclient auth鍵を配る形になり、**マルチデバイスだがシングルprincipal**
    という項目40(8)で欲しかった形にちょうど収まる。

    **実装時の注意(要確認事項を含む):**

    - 鍵形式は`man tor`で確認済み: `HiddenServiceDir`方式では`authorized_clients/*.auth`に
      `descriptor:x25519:<base32-encoded-public-key>`を1行、x25519の生32バイトをbase32した値を
      置く。少なくとも1つ読み込めた場合のみclient authが有効になる。
    - **ただし`HiddenServiceDir`方式は採ってはいけない。** そのディレクトリは`/var/lib/tor/`以下に
      あり、CLAUDE.mdの安全項目で「パーミッション・所有者・ACLを一切変更しない」と定めている
      (過去に`setfacl`で稼働中のTorをクラッシュさせた実績がある)。したがって**制御ポート経由の
      ADD_ONIONにclient auth引数を付ける経路を採る**。
    - **ADD_ONIONでのclient auth指定の構文はtorspecで確認済み(2026-09-19、ユーザーからの指摘で
      torspecが`.txt`から`.md`へ移行していることが分かり実物を取得)。** 現在の置き場所は
      torspecリポジトリの`spec/control-spec/commands.md`(旧`control-spec.txt`は歴史的名称)。
      ADD_ONIONの文法は:

      ```text
      "ADD_ONION" SP KeyType ":" KeyBlob
              [SP "Flags=" Flag *("," Flag)]
              [SP "MaxStreams=" NumStreams]
              ...
              1*(SP "Port=" VirtPort ["," Target])
              *(SP "ClientAuth=" ClientName [":" ClientBlob]) CRLF
              *(SP "ClientAuthV3=" V3Key) CRLF

      V3Key = The client's base32-encoded x25519 public key, using only the key
              part of rend-spec-v3.txt section G.1.2 (v3 only).
      ```

      要点: (a) `ClientAuthV3=`は**繰り返し指定可**なので、端末ごとに鍵を並べればよい。
      (b) 鍵はx25519公開鍵のbase32で、`authorized_clients/*.auth`の`descriptor:x25519:<base32>`と
      同じ値を使える。(c) 文法上`ClientAuthV3=`は`Port=`より**後ろ**に来るので、現行の
      `ADD_ONION %s Port=%d,127.0.0.1:%d`に対しては末尾へ足すだけでよく、組み立ての作り直しは不要。
    - **`Flags=V3Auth`を併記する必要があるかは仕様上あいまいで、実装時に実機で確認すること。**
      Flagの一覧には`"V3Auth" / ; Version 3 client authorization is required (v3 only).`が
      定義されている一方、**同じ文書の例では`Flags=`無しで`ClientAuthV3=`だけを渡している**
      (`C: ADD_ONION NEW:ED25519-V3 ClientAuthV3=[Blob Redacted] Port=22`)。どちらが正しいかは
      文面からは決まらないので、実際に投げて`250-ClientAuthV3=`が返るかで判断する。
    - **必要なtorのバージョンは0.4.6.1-alpha以降**(`[ClientV3Auth support added 0.4.6.1-alpha]`)。
      開発環境のtorは0.4.9.12で条件を満たしているが、古いtorも想定して、ADD_ONIONが
      エラー応答を返した場合に**client auth無しへフォールバックしてはならない**。UI用サービスの
      作成自体を失敗させること(認証が外れた状態で公開されるほうが遥かに悪い)。
    - **2本目のADD_ONIONは既存の制御接続fdをそのまま使える。** `bm_tor_control_add_onion`は
      意図的に`Flags=Detach`を指定せず、`main()`が`sigwait`でブロックしている間`tor_control_fd`を
      開いたままにする設計になっている(Detachを付けると再起動時に永続化した鍵での再作成が
      `550 Onion address collision`で失敗するため。tor_control.hのコメント参照)。仕様上も
      「制御接続が閉じるとサービスも消える」のが既定の挙動なので、この既存の判断が2本目にも
      そのまま効く。新しい接続を張る必要は無い。
    - 静的torrc設定でonionを建てている利用者(`bitmessage.conf`の`[tor] onion_address`経路、
      `main.c`参照)にはこの機能を自動適用できない。その場合はUI用サービスを自分でtorrcに
      書いてもらい、bind先のローカルポートだけ設定で受け取る形になる。
