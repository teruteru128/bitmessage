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
`peer_connector_thread`もv1は起動時1回のみの接続で、常駐しての再接続・維持ループは未実装(TODO、
`src/infra/peer_connector.c`)。

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

DoS対策としてinv/getdataの要素数上限(50000)とobject payloadサイズ上限(256KiB、§5.0)を
このディスパッチ内で強制する。v1スコープ外(既知の制限、TODO): 受信objectを他の接続中peerへ
能動的にinv broadcastする処理(接続レジストリが未実装のため、複数peer間の中継はまだできない)、
addrのpeer_manager永続化、getpubkey受信時の自応答、broadcast(type=3)の購読・復号、
pubkey v4の自動キャッシュ(候補ripeが必要なためgetpubkey自動化と合わせて要検討)。
`tests/test_object_sync.c`でinv→getdata、object重複排除、getdata応答、GC、そして
send_pipeline.cで実際に組み立てたmsgをdispatchに流し込み「trial_decrypt→inbox保存→
埋め込みfullAckPayloadのobject_pool.db取り込み→そのack自体を受信した体でdispatchに
流す→sent.statusがackreceivedへ遷移」までのack往復をend-to-endで検証済み(2026-08-22)。

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
自分のobject_pool.dbへ挿入。他peerへの能動的な再送出=inv broadcastは接続レジストリ未実装のため
TODO)。送達確認(`ackreceived`遷移)は`messages_store.c`の`bm_messages_store_try_mark_ack_received`
(§1のobject_sync_thread参照)。

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

既知の制限: `bm_api_server_serve_forever`の`accept()`はブロッキングでシグナル等による
グレースフルシャットダウンの割り込み機構がない(self-pipe trick等が必要、TODO)。
v1の`main.c`ではこのスレッドを`pthread_detach`し、プロセス終了時に道連れで終わらせている。

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

`object_sync_thread`実装完了・push済み(2026-08-22、コミット直前)。ctest 12件全通過。
次に着手する項目は特に指定が無い限り、以下から都度ユーザーに確認して選ぶこと(このセッションの
一貫した進め方: 毎回ユーザーが次の項目を明示的に指名してから着手する)。

- **他peerへのinv broadcast(接続レジストリ)**: 現状`object_sync.c`は受信したobjectを自分の
  `object_pool.db`へ保存する・同じ接続からのgetdataに答えるところまでで、「新しく手に入れたobjectを
  “今つながっている他のpeer”へ`inv`で積極的に知らせる」処理が無い(=複数peer間の中継・拡散が
  まだできない)。これをやるには`network_epoll_thread`が管理している`bm_fd_data`の集合へ
  外部からアクセスする手段(接続レジストリ)が要る。自分が送信したmsg/ack objectを実際にネットワークへ
  流す(`api_server.c`の`h_sendMessage`に元々あった「broadcast_queueへの投入」TODOと同根)のもこれ待ち。
- **`peer_connector`の永続化**: 現在`bm_peer_connector_connect_initial()`は起動時一回きりのoutbound接続。
  再接続・複数peer維持ループが未実装(自宅環境はCGNAT相当でinbound不可、Tor実装までoutbound-onlyの
  前提は継続、§8参照)。
- **`api_server`のgraceful shutdown**: `accept()`がブロッキングでSIGINT等に応答できないため現状は
  `pthread_detach`で逃げている(`main.c`)。self-pipeトリック等で正式に閉じられるようにする。
- **PoW並列化**: `pow/pow_engine.c`は現状シングルスレッド。
- **getpubkey要求の自動化**: `send_pipeline.c`は`pubkey_cache`未登録の宛先には送信失敗するのみで、
  能動的に`getpubkey`オブジェクトを発行して取りに行く経路が無い。受信したgetpubkeyに自分のpubkeyで
  応答する処理も未実装。pubkey v4の自動キャッシュ(候補ripeが要る)もこれと合わせて検討。
- **再送(resend)ロジック**: ack未着のまま一定時間経過した`sent`行を間隔を倍々にして再送する処理
  (今回スコープ外と決めた分、§1参照)。
- **broadcast(type=3)の購読・復号**: 「誰の配信を受信対象にするか」を持つテーブルが無い
  (`address_book`はラベル帳のみ)。
- **設定の永続化・DoS上限の見直し・chan仕様**: 2026-08-21のギャップ洗い出しで指摘した残り3項目
  (日次振り返りの会話参照)。優先度は低いが実運用に近づくほど効いてくる。

出典・詳細はこのファイル内の各章の実装状況ノートを参照(pubkey_cacheは§2.3、send_pipeline/ackは
§5末尾、object_sync_threadは§1、api_serverは§6.1末尾)。
