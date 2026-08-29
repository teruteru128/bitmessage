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
| `unlockAllAddresses` | passphrase | §7.4参照。数千件規模の一括unlock(vault方式) |
| `importAddress` | address, signingWIF, encryptionWIF, label, storePassphrase, nonceTrialsPerByte?, payloadLengthExtraBytes? | 2026-08-29実装。当初案は`address`を含まなかったが、WIFは秘密鍵のみでaddressVersion/streamを含まないため確定時に追加した(§11参照)。addressから復元したripeとWIFの公開鍵ripeが一致するか検証してから保存する |
| `exportAddress` | address, passphrase | 2026-08-29実装。importAddressと対称。その場でpassphrase復号しsigningWIF/encryptionWIFを返す一回性操作(keyringには触れない) |

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

出典・詳細はこのファイル内の各章の実装状況ノートを参照(pubkey_cacheは§2.3、send_pipeline/ackは
§5末尾、object_sync_threadは§1、api_serverは§6.1末尾)。
