# Bitmessage ポスト量子拡張(ML-DSA / ML-KEM)提案ドラフト

作成: 2026-09-17 / 対象: Bitmessage protocol v3(wiki "Protocol specification")+ 本実装

この文書は「Bitmessageにポスト量子暗号(ML-DSA / ML-KEM)を導入するとしたら何をどう変えるか」の
設計提案と、その妥当性を確かめるためのプロトタイプ実装・実測の記録である。本体の設計文書は
[DESIGN.md](DESIGN.md)、日付入りの経緯は [DESIGN-LOG.md](DESIGN-LOG.md)。

**この提案の結論を1段落で:** Bitmessageのポスト量子化は、**P2P層(ハンドシェイク・inv/getdata/
object配送・PoW・stream)を1バイトも変えずに実現できる**。変更が必要なのは「オブジェクトの
中身の意味」だけで、具体的には新しいアドレス版(v5)と、それに対応する
getpubkey/pubkey/msg/broadcastの新しいobjectVersionを定義するだけでよい。既存ノードは
これらのオブジェクトを**中身を理解しないまま正常に中継する**(§2で3実装のソースを確認)。
コストは計算時間ではなく**サイズ**に集中する: msgオブジェクトの固定オーバーヘッドが
約200byte → 約7.8KB に増え、PoWの期待所要時間が16コアで msg 6.5秒→26.6秒、
pubkey 22.9秒→**144秒**になる(§8.4)。暗号処理そのもののCPU時間はむしろ**速くなる**
(ML-DSA-65+Ed25519の署名はsecp256k1 ECDSAより速い)。最大の実装上の帰結は
「PoWを専用ワーカーへ追い出す改修がv5の前提条件になる」こと(§9.3)。

---

## 1. 動機と脅威モデル

### 1.1 Bitmessageは "harvest now, decrypt later" の理想的な標的

Bitmessageの設計思想そのものが、暗号学的に関連する量子計算機(CRQC)が現れた場合の被害を
最大化する方向に働く:

- **全オブジェクトが全ノードへ平等に配送される。** 攻撃者は特定の通信路を狙う必要すらなく、
  ノードを1本立てておけば流れる暗号文を全部収集できる。TLSのような「その接続を傍受できた分だけ」
  という制約が無い。
- **収集した暗号文は復号の手がかりと完全にセットになっている。** msgオブジェクトには宛先の
  ECDH公開鍵に対する一時公開鍵(ECIES)が同梱され、pubkeyオブジェクトには長期公開鍵が
  そのまま載る。将来Shorのアルゴリズムでsecp256k1の離散対数が解ける環境が来た時点で、
  過去に収集した全メッセージが**遡って**復号される。
- **匿名性の前提も同時に崩れる。** broadcastやpubkey v4の「アドレスを知っている人だけ読める」
  仕組みはアドレス由来のECDH鍵に依存しているので、同じ計算能力で購読関係が復元される。

つまりBitmessageにとってPQ移行は「TLS 1.3のハイブリッド鍵交換」より切迫している。TLSは
セッションが終われば鍵が消えるが、Bitmessageの暗号文は誰かのobject_pool.dbやアーカイブに
残り続ける。

### 1.2 何が壊れて、何が壊れないか

| 要素 | 使用アルゴリズム | CRQC下での状態 |
|---|---|---|
| ECIES(msg/broadcast/pubkey v4の暗号化) | secp256k1 ECDH | **崩壊**(Shor)。過去の暗号文も遡って復号される |
| ECDSA署名(なりすまし防止) | secp256k1 + SHA256 | **崩壊**(Shor)。ただし遡及被害は「署名の偽造」であり、過去に受信済みのメッセージの信頼性を後から失う程度 |
| アドレスのripe | RIPEMD160(SHA512(...)) | 弱い。衝突2^80、Groverで第二原像2^80。**PQ設計の中では最弱の環になる** |
| PoW | double SHA512 | **維持**。Groverで平方根加速だが、PoWは元々「相手より多く計算する」ゲームなので実害は小さい |
| inventory hash | double SHA512 の先頭32byte | **維持**(衝突2^128相当) |
| メッセージヘッダのchecksum | SHA512先頭4byte | もともと暗号的用途ではない |

### 1.3 スコープ外と割り切る点

- **トラフィック解析・匿名性そのものはPQ化の対象外。** Dandelion++やTor経由の話(DESIGN.md §9)は
  独立した問題として扱う。
- **PoWのアルゴリズム変更はしない。** Groverによる平方根加速はあるが、PoWの意味は相対的な
  コストなので、量子計算機を持つ攻撃者だけが得をするという議論は成立しうるものの、
  現実の攻撃コスト(専用ハードを持つ古典攻撃者の方が先に脅威になる)を考えると
  優先度が低い。
- **既存v2〜v4アドレスの救済はしない。** 過去に送られた暗号文は既に収集済みかもしれず、
  事後に守る方法は無い。移行は「新しいアドレスを作る」形でのみ行う(§9)。

---

## 2. 「手を加えなくてよい部分」の裏取り

ユーザーの当初の見立て(オブジェクト配送周りとハンドシェイクは手を加えなくて良さそう)が
本当に成立するかを、実ソースで確認した。CLAUDE.mdの「本家との一致・不一致は必ず実ソースを
確認してから判断する」に従い、推測ではなく該当コードを引用する。

### 2.1 ハンドシェイク・メッセージ層: 変更不要

`version`/`verack`/`addr`/`inv`/`getdata`/`object` のいずれもオブジェクトの**中身**を見ない。
services bitflagに「PQ対応」を表明するビットを足したくなるが、**足さない方がよい**:

- 中継に理解は不要なので機能上の必要が無い
- ネットワーク上で「PQユーザー」を選別可能にするフィンガープリントを増やすだけになる

### 2.2 未知のobjectVersionは中継されるか(最重要の確認事項)

**3実装すべてで「中継される」ことを確認した。**

**(a) PyBitmessage** (`src/network/bmproto.py` の `bm_command_object`、ローカルクローン
dcbcc4a2で確認)。受信時の検査は次の順で、**型別検査に失敗しても中継は止まらない**:

```python
        try:
            self.object.checkObjectByType()
            objectProcessorQueue.put((...))
        except BMObjectInvalidError:
            self.stopDownloadingObject(self.object.inventoryHash, True)
        else:
            ...
        # ↓ ここから下は例外の有無に関わらず実行される
        state.Inventory[self.object.inventoryHash] = (...)
        self.handleReceivedObject(...)
        invQueue.put((self.object.streamNumber, self.object.inventoryHash, self.destination))
```

つまり `checkObjectByType()` が投げても、オブジェクトはinventoryへ保存され `invQueue` 経由で
他ピアへ再広告される。中継の条件になっているのは **PoW・TTL(28日+3時間)・stream・
MAX_OBJECT_PAYLOAD_SIZE(2^18)** の4つだけ。

**(b) MiNode-Refined** (`minode/structure.py` の `Object.is_valid`、ユーザーのローカルクローン)。
TTL・payload長(2^18)・stream・PoWのみを見ており、**objectType/objectVersionによる分岐が
そもそも存在しない**。

**(c) 本実装** (`src/infra/object_sync.c` の `handle_object`)。同じく
サイズ・ヘッダ妥当性・期限・PoWのみで判定し、通れば `object_pool.db` へ保存して
`bm_peer_registry_broadcast_inv` する。型別処理は保存の後。

### 2.3 既存ノードが「解釈は拒否するが中継はする」境界

PyBitmessageの型別検査(`src/network/bmobject.py`)と処理層(`src/class_objectProcessor.py`)が
どこで新バージョンを落とすかを整理すると、**新objectVersionは非常に安く捨てられる**ことが分かる。

| オブジェクト | PyBitmessage側の判定 | v5を投げたときの挙動 |
|---|---|---|
| getpubkey | `len(data) < 42` で無効 | v5は54byteなので検査通過。`processgetpubkey`がversion>4を無視 |
| pubkey | `len(data) < 146 or > 440` で無効 | v5は約7.8KBなので「無効」判定 → **中継はされるが処理層に渡らない**(ログ1行) |
| msg | 検査なし | `processmsg`が `if msgVersion != 1: return` で**復号を試みる前に**捨てる |
| broadcast | `len < 180`、`version < 2` で無効 | `processbroadcast`が `if broadcastVersion < 4 or > 5: return` で捨てる |

**重要な含意**: msg/broadcastは「トライアル復号を試みる前に」versionで弾かれる。つまりPQ
オブジェクトが流れても、既存ノードに無駄な復号計算を強いることはない。これは新objectTypeを
定義する案(§10で却下)より優れた性質で、**objectVersionを上げる方式を選ぶ最大の理由**である。

### 2.4 したがって守るべき制約は3つだけ

1. オブジェクトのpayloadは **2^18 = 262144 byte** 以下(型依存部の長さで判定される)
2. PoWはネットワーク既定 **nonceTrialsPerByte=1000 / payloadLengthExtraBytes=1000** 以上
3. TTLは最大28日+3時間、過去1時間以上前の期限は不可

---

## 3. 設計方針

### 3.1 スコープ

新規に定義するのは以下だけ:

- **アドレス version 5**(新しい鍵種別・新しいidentifier長)
- **getpubkey objectVersion 5** / **pubkey objectVersion 5** / **msg objectVersion 2** /
  **broadcast objectVersion 6**

変更しないもの: P2Pメッセージ、inventory hash、PoW計算式、stream、Dandelion++、ack機構の考え方。

### 3.2 アルゴリズム選択: ML-DSA-65 + ML-KEM-768(いずれもCategory 3)

| 用途 | 選択 | 理由 |
|---|---|---|
| 署名 | **ML-DSA-65** (FIPS 204) | Category 3(AES-192相当)。pk 1952 / sig 3309 byte |
| KEM | **ML-KEM-768** (FIPS 203) | Category 3。pk 1184 / ct 1088 byte。TLSでもChromeが既定採用している事実上の標準点 |
| 古典側(署名) | **Ed25519** | pk 32 / sig 64。OpenSSL 3.0にEVP APIがある |
| 古典側(KEM) | **X25519** | X-Wing(§5.2)がこの組み合わせで仕様化されている |

古典側をsecp256k1(v4と同じ)ではなく25519系にした点は、**2026-09-17にユーザー判断で確定**。
決め手はX-Wing(§5.2)が「ML-KEM-768 + X25519」専用に仕様化・解析されていることで、
secp256k1に差し替えると自前combinerの設計になってしまう。副次的に公開鍵が
65byte(0x04||X||Y)から32byteに縮み、実測でも全操作でv4より速い(§8.1)。
| AEAD | **AES-256-GCM** | 既存のAES-256-CBC+HMAC-SHA256を置き換え。padding oracleの余地を構造的に無くす |
| ハッシュ | **SHA3-256 / SHA3-512** | ML-DSA/ML-KEMがKeccakを内蔵しており追加コストが実質ゼロ。§5.4 |

Category 3を選んだのは、Bitmessageの暗号文が**恒久的にアーカイブされる**という1.1の性質から。
Category 1(ML-DSA-44 / ML-KEM-512)でも当面の安全性はあるが、「30年後も読まれたくない」
という要求に対しては中央値を取るのが妥当と判断した。ML-DSA-44に落とすと約1.8KB節約できる
(§8に実測)ので、これは**プロファイルとして後から追加可能な選択肢**として残す(§10.3)。

### 3.3 なぜハイブリッド(PQ単独ではない)か

ML-DSA/ML-KEMだけにせず、Ed25519/X25519を併用して**両方の突破を要求する**構成にした。

- **格子暗号の実装バグに対する保険。** ML-KEMの実装は副チャネル・誤り訂正まわりが繊細で、
  実装起因の鍵回復が現実に報告されてきた領域である。古典側を併用しておけば、
  片方の実装が壊れても即座に平文が漏れることはない。
- **新しい数学的仮定に対する保険。** MLWE/MSISは十分に検討されているが、RSA/ECDLPほどの
  歴史は無い。
- **コストが小さい。** 追加は pk 64 byte(署名32+KEM32)・sig 64 byte・ct 32 byte で、
  ML-DSA/ML-KEM本体に対して1%強。時間コストは署名で+10%(1069→1172 us)、検証で+80%
  (253→455 us、§8.1)。検証側の比率が目立つのはML-DSAの検証が元々速いためで、
  しかもこの200 us の大半はEd25519そのものではなく**呼び出しごとに `EVP_PKEY` を
  生成・破棄しているオーバーヘッド**である(鍵オブジェクトをキャッシュすれば縮む。
  プロトタイプでは最適化していない)。それでもv4のECDSA検証(585 us)より速い。

検証は**必ずAND**にする(どちらか通ればOKにしない)。これを取り違えるとハイブリッドの
意味が消えるため、実装(`bm_pqv5_verify`)とテスト(`test_pq_crypto.c` の
「片側だけ改竄した署名を弾く」ケース)の両方で明示している。

### 3.4 なぜ新しいobjectTypeではなくobjectVersionの引き上げか

§2.3の通り、既存ノードがmsg/broadcastを **version判定だけで、復号を試みる前に** 捨ててくれる。
新しいobjectType(例: 0x504b = "PK")を定義すると、PyBitmessageの `checkObjectByType` は
何の検査もせず `objectProcessorQueue` へ流し、処理層で初めて「知らない型」として捨てることになる
(キュー1段分だけ無駄が増える)。また新typeは番号の調整が必要で、objectVersionなら
既存の番号割り当て規則の延長で済む。

---

## 4. アドレス version 5

### 4.1 identifier(v4までの "ripe" に相当)

```
id = SHA3-256( "BitmessagePQ-v5-id" || varint(version) || varint(stream) || pk_sig || pk_kem )
```

- 長さ **32 byte**(v4までは RIPEMD160(SHA512(...)) の20 byte)
- `pk_sig` = ML-DSA-65公開鍵(1952) || Ed25519公開鍵(32) = 1984 byte
- `pk_kem` = ML-KEM-768公開鍵(1184) || X25519公開鍵(32) = 1216 byte

**バイト順は「PQ側が先、古典側が後」で統一している。** KEM側がこの順なのは
X-Wing draftが公開鍵を `pk_M || pk_X`(ML-KEM→X25519)と定めているためで、
署名側もそれに揃えた。逆順(`ed25519 || ml-dsa || x25519 || ml-kem`)も設計としては
成立するが、pk_kemをX-Wingの実装へ渡す前に並べ替えが必要になる。ここは慣習の選択で
あり、変更するならこの節と `bm_pqv5_calc_id` / `pq_hybrid.c` のオフセット定義を
同時に直す(2026-09-17時点ではX-Wing準拠のまま)。

**20byteをやめた理由**: RIPEMD160の衝突計算量は2^80で、Category 3(2^192相当)の署名・KEMと
釣り合わない。アドレス衝突は「同じアドレスに見える別人の鍵」を作れることを意味し、
chan(共有アドレス)やアドレス帳の文脈で実害が出る。せっかくML-DSAを入れても、
identifierが2^80なら攻撃者はそちらを狙う。

**version/streamをハッシュ入力に含める理由**: 同じ鍵を別streamのアドレスとして再利用した
pubkeyオブジェクトを流用する攻撃を構造的に潰すため。v4まではripeがversion/streamに依存せず、
tag側でのみ束縛していた。

実装上の注意: 開発中に `bm_varint_encode` の戻り値(書き込み先ポインタを進めて返さない)を
取り違えて、version/streamがハッシュ入力から丸ごと抜け落ちるバグを出した。
`tests/test_pq_address.c` の `test_id_depends_on_version_and_stream` はその再発検知を兼ねている。

### 4.2 決定性生成(パスフレーズからの再現)

アドレス1本につき **root(64byte)を1つ** 決め、そこから4成分それぞれの鍵材料を
独立に導出する:

```
root          = SHA3-512( "BitmessagePQ-v5-deterministic" || 0x00 || passphrase || varint(nonce) )
sub_seed(c,k) = SHAKE128( root || component_label(c) || 0x00 || varint(k), 必要長 )

  component_label:  "mldsa"(32byte) / "ed25519"(32byte) / "mlkem"(64byte) / "x25519"(32byte)
```

`nonce` がアドレス番号(同じパスフレーズから複数アドレスを作るときに変える値)、
`k` が成分ごとの探索カウンタ(§4.2.1)。identityは `nonce` と4本のカウンタを保持するので、
決定性は完全に保たれる。

**v4との違いは「4成分を独立に導出する」点。** v4は署名鍵と暗号化鍵の2本で、それぞれ
nonceを持っていた。v5でこの構造にしたのは、探索(§4.2.1)で**どの成分だけを引き直すかを
選べるようにする**ため。X-Wingの鍵生成は32byte seed 1本からML-KEMとX25519の両方を
導出する構造なので、そのままではX25519だけを引き直せない。

**v5でもid先頭に0x00を1byte要求する(`null_bytes=1`、v4と同じ)。**

まずv4でなぜ要求していたのかを一次資料で確認した(2026-09-17、ユーザーからの質問による)。
結論は**「アドレス文字列を短くするため」ただ一つ**で、スパム抑止・PoW的な意味は持たされて
いない:

- **実装者本人のコメント**(PyBitmessage `f0666e65`、Jonathan Warren、2013-01-16。
  当時は`bitmessagemain.py`内に直接書かれていた):
  > This next section is a little bit strange. We're going to generate keys over and over
  > until we find one that starts with either \x00 or \x00\x00. Then when we pack them into
  > a Bitmessage address, we won't store the \x00 or \x00\x00 bytes thus making the address
  > shorter.
- **GUIの文言**(`src/bitmessageqt/newaddressdialog.ui`のeighteenByteRipeチェックボックス):
  > Spend several minutes of extra computing time to make the address(es) 1 or 2 characters
  > shorter

  (このチェックボックスは2byte目の話。1byte目はチェック無しでも常に要求される。
  chan生成も`numberOfNullBytesDemandedOnFrontOfRipeHash = 1`のハードコード)
- **プロトコル仕様(wiki "Protocol specification")には先頭ゼロに関する要求が存在しない。**
  仕様側にあるのは `encodeAddress` の「先頭0x00を最大2byteまで削る」という**エンコード規則**
  だけで、「0x00を作りに行く」のはクライアント側の生成方針にすぎない。先頭ゼロの無い
  アドレスも仕様上は完全に正当(DESIGN.md §3.3で扱った「4byte分のゼロを持つ非正規v3
  アドレス」は逆方向の実例)。

32byteのidでは1byte分の短縮が log58(256) ≒ 1.37文字にしかならない(実測54文字→53文字)。
短縮そのものの価値は小さい。

**それでも要求することにしたのは「アドレス長が揃う」ためである**(2026-09-17、ユーザー判断)。
`null_bytes=0` だと255/256のアドレスが54文字・1/256が53文字以下とばらつくのに対し、
`null_bytes=1` なら一律53文字になる。探索コストは実測で数十ms(§8.2)と無視できる。

### 4.2.1 探索でどの成分を引き直すか

v4は署名鍵と暗号化鍵をペアで引き直していた(`class_addressGenerator.py`)。v5では
**成分ごとに鍵生成コストが桁違いに違う**ため、「どれを回すか」が探索コストに直接効く:

| 成分 | 鍵生成の中身 | 実測(§8.1) |
|---|---|---|
| ML-DSA-65 | 行列展開+NTT | 224 us |
| ML-KEM-768 | 行列展開+NTT | 83 us |
| Ed25519 | スカラー倍1回 | (§8.2に実測) |
| X25519 | スカラー倍1回 | (§8.2に実測) |

idは4成分全ての公開鍵のハッシュなので、**どれか1つだけを引き直しても出力は一様に
ばらつき、暗号学的な差は無い**。したがって一番安い成分(X25519)だけを回すのが最適で、
これを既定にした(`BM_PQV5_SEARCH_X25519`)。実測比較は §8.2。

回さなかった成分のカウンタは0のまま残るため、`(パスフレーズ, nonce, カウンタ4本)` で
アドレスは完全に再現できる。

> 実装メモ: 探索モードの列挙値は成分の列挙値と一致させてある。当初は独立した番号に
> していて「X25519を指定するとML-DSAが回る」という取り違えバグを出し、
> `tests/test_pq_address.c` の「回していない成分のカウンタが0のままであること」という
> 検査で捕まえた(2026-09-17)。

### 4.3 アドレス文字列

形は v2〜v4 と**完全に同じ**にした:

```
storedBinaryData = varint(version=5) || varint(stream) || id(先頭の0x00を全て除去)
checksum         = double_sha512(storedBinaryData)[0:4]
address          = "BM-" + base58(storedBinaryData || checksum)
```

`checksum` を SHA3 ではなく既存の `double_sha512` のままにしたのは、**バージョンを知らない
既存ツールでもチェックサム検証だけは通せる**状態を保つため(アドレス帳・コピペミス検出の
ような用途が壊れない)。decode側は v4 と同じ非マレアビリティ検査(先頭0x00が残った
非正規エンコーディングを拒否)を行う。

実測でアドレス長は **53文字**(v4は34〜37文字)。19文字の増加。

### 4.4 tag と「アドレスを知っていれば誰でも作れる鍵」

```
SHA3-512( "BitmessagePQ-v5-tag" || varint(version) || varint(stream) || id )
  → [0:32] = アドレス由来KEM鍵のseed
  → [32:64] = tag(32byte)
```

v4の `SHA512(varint(version)||varint(stream)||ripe)` を前半=秘密鍵・後半=tagに分ける設計と
まったく同じ役割。前半をX-Wingのseedとして使うことで、**アドレス文字列を知っている人なら
誰でも同じKEM鍵ペアを再現でき、pubkey v5とbroadcastを復号できる**という性質を維持する。

---

## 5. 暗号プリミティブ

### 5.1 ハイブリッド署名

```
HybridSigKeyGen(seed32):
    xi || ed_seed = SHAKE128(seed32, 64)
    (pk_m, sk_m)  = ML-DSA-65.KeyGen_internal(xi)
    pk_e          = Ed25519.Public(ed_seed)
    pk = pk_m || pk_e        (1952 + 32 = 1984)
    sk = sk_m || ed_seed     (4032 + 32 = 4064)

HybridSign(label, msg, sk):
    input = label || 0x00 || msg
    return ML-DSA-65.Sign(sk_m, input) || Ed25519.Sign(ed_seed, input)    (3309 + 64 = 3373)

HybridVerify: 両方の検証が成功したときのみ有効
```

ML-DSAのcontext string(FIPS 204 §5.2)は空にし、ドメイン分離は `label || 0x00` の前置で行う。
Ed25519側にcontext stringが無く(OpenSSLはpure Ed25519のみ)、**両者にまったく同じ入力を
与えたい**ため。

### 5.2 ハイブリッドKEM: X-Wing

`draft-connolly-cfrg-xwing-kem` をそのまま実装する。自前のcombinerを設計しないことが目的
(ハイブリッドKEMの合成は「共有秘密を単に連結してハッシュ」でも安全とは限らず、
ct/pkの束縛まで含めて解析されたものを使うべき領域)。

```
combiner(ss_M, ss_X, ct_X, pk_X) = SHA3-256( "\.//^\" || ss_M || ss_X || ct_X || pk_X )

KeyGen(seed32): expanded = SHAKE128(seed32, 96)
                (pk_M, sk_M) = ML-KEM-768.KeyGen_derand(expanded[0:64])
                sk_X = expanded[64:96], pk_X = X25519(sk_X, G)
Encaps(pk):     ek_X ← random;  ct_X = X25519(ek_X, G);  ss_X = X25519(ek_X, pk_X)
                (ct_M, ss_M) = ML-KEM-768.Encaps(pk_M)
                ct = ct_M || ct_X (1088+32=1120),  ss = combiner(...)
```

draftとの差異は2点。どちらも公開鍵・暗号文・共有秘密の計算(=相互運用に関わる部分)は
draftと同一で、鍵の**作り方と保持の仕方**だけが違う:

1. draftが秘密鍵を32byte seedのまま保持するのに対し、この実装は展開後の形
   (ML-KEM sk || X25519 sk = 2432 byte)で保持する。identityの鍵は保存して繰り返し
   使うので、使うたびにML-KEM KeyGenをやり直すのを避けるため。
2. identityのKEM鍵は、draftの `XWingKeyGen(seed32)`(1本のseedからML-KEMとX25519の
   両方を導出)ではなく、§4.2の成分別サブseedから**独立に**生成する。X25519だけを
   引き直す探索(§4.2.1)を可能にするため。なおアドレス由来の鍵(§4.4、pubkey/broadcastの
   復号に使うもの)はdraft通りの `XWingKeyGen(seed32)` を使う — こちらは探索しないので
   分離する必要が無く、seed 1本で済む方が単純なため。

### 5.3 封緘(seal)フォーマット

```
seal(recipient_pk, aad, plaintext):
    (ct, ss) = XWing.Encaps(recipient_pk)
    return ct(1120) || AES-256-GCM(key=ss, nonce=0^12, aad=aad, plaintext) || tag(16)
```

- **nonceは全0固定**。KEMの共有秘密は封緘ごとに新しく作られるのでAES-GCM鍵が1回しか
  使われず、nonce再利用の危険が構造的に無い(HPKEのbase modeでseq=0の1通だけを送るのと
  同じ状況)。12byteをワイヤに載せる必要も無くなる。
- **aadにはオブジェクトの平文部(PoW nonceを除くヘッダ + あればtag)を入れる。**
  これがv4からの実質的な改善で、v4のECIESはヘッダを一切認証しておらず、
  expiresTime等の改竄は署名検証まで進んで初めて分かる。v5では復号の時点で落ちる。
- PoW nonce(先頭8byte)はAADにも署名対象にも**含めない**。PoWは暗号化・署名の後に
  計算され前置されるため。`tests/test_pq_object.c` でこの性質(nonceを書き換えても
  復号・検証が通ること)を明示的にテストしている。

固定増分は **1120 + 16 = 1136 byte**。

### 5.4 ハッシュをSHA-3系に統一した理由

v5で新規に定義するハッシュ(id・tag・seed導出・X-Wing combiner)は全てSHA3/SHAKEにした。

- ML-DSA/ML-KEMがKeccakを内蔵しているので、実装上の追加コストがゼロ
- X-Wingのcombinerが仕様でSHA3-256を要求している
- SHA-2とSHA-3で構造が異なるため、片方に構造的攻撃が出たときの巻き添えが減る

例外は §4.3 のアドレスchecksum(既存ツールとの互換のため double_sha512 のまま)と、
PoW・inventory hash(プロトコル全体で共有される値なので変更しない)。

---

## 6. 実装(プロトタイプ)

```
third_party/pqcrystals/          vendorしたpq-crystals参照実装
  kyber/      (ML-KEM, upstream 3edd5af5, 2026-08-02)
  dilithium/  (ML-DSA, upstream d35ba3fe, 2026-06-03)
  randombytes.{c,h}              両者のrandombytesを1本に差し替え(OpenSSL CSPRNGへ委譲)
  dilithium/keypair_derand.{c,h} ML-DSA.KeyGen_internal(xi) を追加(上流に公開APIが無い)
src/pq/
  pq_crypto.{c,h}    ML-DSA/ML-KEM全パラメータセットの薄いラッパ
  pq_hybrid.{c,h}    ハイブリッド署名・X-Wing・AES-256-GCM封緘
  address_v5.{c,h}   v5アドレス
  pq_object.{c,h}    v5オブジェクトの組み立て/解析
  bm_pq_bench.c      ベンチマークツール(bm-pq-bench)
tests/
  test_pq_crypto.c / test_pq_address.c / test_pq_object.c
```

**なぜ外部ライブラリではなくvendorか。** この環境(Ubuntu 24.04)にはPQを提供する選択肢が無い:
OpenSSLは3.0.13でML-KEM/ML-DSAの実装は3.5以降、liboqs/PQCleanはディストリのアーカイブに
パッケージが存在しない(`apt-cache search`で0件)、Botanも2.19系でML-KEM非対応。つまり
「外部ライブラリを使う」は実質「全員がliboqsをソースからビルドする」を意味し、
ビルドシステムを持たない参照実装20ファイルをvendorする方が依存は軽い。libmicrohttpd/cJSONを
採用した時の方針(ディストロ標準にある枯れたライブラリを使う)とも矛盾しない — 今回は
該当物が存在しないだけである。

ライセンスは両リポジトリともCC0(パブリックドメイン)またはApache-2.0のデュアルで、
MITの本体と衝突しない。

**バックエンド差し替えの余地は残してある。** `src/pq/pq_crypto.c` だけが参照実装のシンボルを
直接呼ぶ(ヘッダも公開しない)ので、OpenSSL 3.5以降が使える環境になったらこの1ファイルを
EVP呼び出しへ書き換えるだけで済む。DESIGN.md §3.5の「公開ヘッダに外部ライブラリの型を
出さない」規律をPQ側でも踏襲した。

vendor時の改変は2点のみで、どちらも上流ファイルを書き換えずに**追加**で実現している:
`randombytes` の差し替え(上流の同名シンボルがkyber/dilithiumで衝突するため、両方を除外して
1本に統一)と、`crypto_sign_keypair_derand` の追加(ML-KEMには `keypair_derand` があるのに
ML-DSAには無いため、`crypto_sign_keypair` の中身を複製して `randombytes()` の1行だけを
引数のseedに置き換えたもの = FIPS 204 Algorithm 6)。

---

## 7. オブジェクトのワイヤーフォーマット

共通ヘッダはDESIGN.md §5.0のまま:
`nonce(8) || expiresTime(8) || objectType(4) || varint(objectVersion) || varint(stream)`

以下、`AAD` は「PoW nonceを除く平文部」、`seal(...)` は §5.3。

### 7.1 getpubkey (type=0, objectVersion=5)

```
<共通ヘッダ> || tag(32)
```

v4と同形。tagの計算式だけが §4.4 に変わる。

### 7.2 pubkey (type=1, objectVersion=5)

```
平文部  = <共通ヘッダ> || tag(32)
封緘対象 = bitfield(4) || pk_sig(1984) || pk_kem(1216)
         || varint(nonceTrialsPerByte) || varint(payloadLengthExtraBytes)
         || varint(sigLen) || signature(3373)
署名対象 = "BitmessagePQ-v5-pubkey" || 0x00 || 平文部 || 封緘対象(signature手前まで)
最終     = 平文部 || seal(アドレス由来KEM公開鍵, AAD=平文部, 封緘対象)
```

bitfieldはv4の意味を引き継ぐ(ack要求ビットのみ実装)。

### 7.3 msg (type=2, objectVersion=2)

```
平文部  = <共通ヘッダ(objectVersion=2, stream=宛先stream)>
封緘対象 = varint(fromAddressVersion=5) || varint(fromStream) || bitfield(4)
         || pk_sig(1984) || pk_kem(1216)
         || varint(nonceTrialsPerByte) || varint(payloadLengthExtraBytes)
         || to_id(32)                      -- なりすまし転送対策、受信側は自分のidと照合必須
         || varint(encoding) || varint(messageLen) || message
         || varint(ackLen) || ackPayload
         || varint(sigLen) || signature(3373)
署名対象 = "BitmessagePQ-v5-msg" || 0x00 || 平文部 || 封緘対象(signature手前まで)
最終     = 平文部 || seal(宛先のpk_kem, AAD=平文部, 封緘対象)
```

### 7.4 broadcast (type=3, objectVersion=6)

```
平文部  = <共通ヘッダ> || tag(32)
封緘対象 = varint(fromAddressVersion) || varint(fromStream) || bitfield(4)
         || pk_sig || pk_kem || varint(ntpb) || varint(ple)
         || varint(encoding) || varint(messageLen) || message
         || varint(sigLen) || signature
最終     = 平文部 || seal(送信元アドレス由来KEM公開鍵, AAD=平文部, 封緘対象)
```

購読側はtagで候補を絞ってから開封する(v4 objectVersion=5 と同じ)。

### 7.5 ack payload

v4の3段階(DESIGN.md §5.5)をそのまま使える。既定のlevel 1(getpubkey偽装)は
**v5ではtag部分を「v5 getpubkeyに見えるランダム32byte」にする**のが自然だが、
v4 getpubkeyとv5 getpubkeyでサイズが同じ(54byte)なので、どちらに偽装しても
区別はつかない。ここは実装時の選択に委ねる(本プロトタイプでは未実装)。

---

## 8. 実測(ベンチマーク)

測定環境と生の出力は §8.4。ツールは `build-Release/src/pq/bm-pq-bench [--pow]`。

### 8.1 暗号プリミティブ

測定は Release ビルド(`-O3`)、Ubuntu 24.04 / OpenSSL 3.0.13 / 16コア。
ML-DSAのsignは棄却サンプリングのため回数によりばらつく。

| アルゴリズム | keygen | sign / encaps | verify / decaps |
|---|---|---|---|
| ML-DSA-44 | 135 us | 627 us | 153 us |
| **ML-DSA-65** | **238 us** | **934 us** | **242 us** |
| ML-DSA-87 | 375 us | 1261 us | 398 us |
| ML-KEM-512 | 48 us | 59 us | 76 us |
| **ML-KEM-768** | **80 us** | **95 us** | **117 us** |
| ML-KEM-1024 | 126 us | 138 us | 167 us |

v5プロファイル(ハイブリッド)と現行v4の比較:

| 操作 | v4 (secp256k1) | v5 (ハイブリッド) | 比 |
|---|---|---|---|
| 署名 | 1241 us | 1196 us | **0.96** |
| 検証 | 563 us | 432 us | **0.77** |
| 暗号化 / 封緘 | 1223 us | 299 us | **0.24** |
| 復号 / 開封 | 610 us | 320 us | **0.52** |

**CPU時間ではv5の方が速い。** OpenSSLのsecp256k1(汎用EC実装で、専用のlibsecp256k1のような
最適化が入っていない)が遅いため、ML-DSA-65+Ed25519の方が署名も検証も速く終わる。
封緘に至っては4倍速い。**PQ化のコストは計算時間ではなく、サイズとそれに比例するPoWに
すべて乗る**というのがこの提案の全体像である。

### 8.2 アドレス生成

`null_bytes=1`(id先頭1byteが0x00)を要求したときの探索コスト。**1候補あたりのコスト**が
安定した指標で、期待所要時間はその256倍(先頭1byteが0になる確率が1/256)。
候補数の実測値は幾何分布なので単発では大きくぶれる。

| 方式 | 引き直す鍵 | ms/候補 | 期待所要 | アドレス長 |
|---|---|---|---|---|
| v4 | secp256k1 ×2 | 1.210 | 310 ms | 37文字 |
| v5 **X25519**(既定) | X25519のみ | **0.091** | **23 ms** | 53文字 |
| v5 Ed25519 | Ed25519のみ | 0.088 | 22 ms | 53文字 |
| v5 ML-KEM | ML-KEM-768のみ | 0.109 | 28 ms | 53文字 |
| v5 ML-DSA | ML-DSA-65のみ | 0.254 | 65 ms | 53文字 |
| v5 全成分 | 4成分とも | 0.485 | 124 ms | 53文字 |
| v5 探索なし | — | 0.566(1回のみ) | 0.6 ms | 54文字 |
| v5 X25519, null_bytes=2 | X25519のみ | 0.085 | 5.6 s | 52文字 |

- **X25519とEd25519はほぼ同じ**(0.09 ms/候補)。この水準まで来ると、コストの大半は
  スカラー倍ではなく**id計算のSHA3-256(入力3200byte)とEVPのオブジェクト生成
  オーバーヘッド**になる。ML-KEM(0.109)との差も小さい。
- 対してML-DSAだけは0.254 ms/候補と明確に高く、v4相当の「全部引き直す」は0.485 ms/候補。
- 既定のX25519方式なら、**v4の13分の1のコスト**で同じ「先頭1byteが0」を達成できる。
- null_bytes=2(52文字)は期待5.6秒。v4の「もっと短いアドレス」オプションが
  "Spend several minutes of extra computing time" と説明していたのに対し、
  v5では数秒で済む。

### 8.3 オブジェクトサイズ

PoW nonceを含む完成オブジェクトのバイト数:

| オブジェクト | v4 | v5 | 比 |
|---|---|---|---|
| getpubkey | 54 | 54 | 1.0 |
| pubkey | 396 | 7776 | 19.6 |
| broadcast(本文5) | 412 | 7785 | 18.9 |
| msg(本文0) | 396 | 7781 | 19.6 |
| msg(本文100) | 492 | 7881 | 16.0 |
| msg(本文1000) | 1404 | 8783 | 6.3 |
| msg(本文10000) | 10396 | 17783 | **1.7** |

**固定オーバーヘッドは +7385 byte**(内訳: pk_sig 1984 + pk_kem 1216 + signature 3373 +
KEM暗号文 1120 + GCMタグ 16 − v4の同等項目)。長文になるほど比率は下がり、
本文10KBでは1.7倍に収まる。

**本文長の上限**: `MAX_OBJECT_PAYLOAD_SIZE = 2^18` に対し、v5 msgの固定オーバーヘッドが
7781 byteなので本文上限は **254363 byte**。現行の `BM_MAX_SUBJECT_PLUS_BODY_LEN`
(2^18 − 500 = 261644)から約7.1KB減るため、v5用の定数を別に定義する必要がある(§9.3)。

### 8.4 オブジェクト発行のPoW(最大の難所)

**ハッシュレートの測り方に注意が要る。** 単一スレッドで測ると 0.59 Mtrial/s だが、
16コア全部を回すと合計 **2.31 Mtrial/s** にしかならない(単純な16倍より**4.1倍低い**)。
全コア負荷時のクロック低下とSMT(論理16コアが物理8コア相当)のため。PoWは常に
全コアを使い切る処理なので、この条件で測った値でないと推定が4倍ずれる
(実際に一度ずらした。§DESIGN-LOG 2026-09-17)。

以下の「期待所要」は 2.31 Mtrial/s 基準。PoWの所要時間は指数分布に従うので、
単発の実測値は期待値の1/5〜3倍程度は普通にぶれる(下表の実測列がまさにそうなっている)。
一方「実効レート」= 見つかったnonce ÷ 所要時間 は試行回数が大きいため安定しており、
いずれも2.1〜2.8 M/sで校正値とよく一致している。

| オブジェクト | byte | 期待試行回数 | **期待所要** | 実測(1回) | 実効レート |
|---|---|---|---|---|---|
| v4 pubkey (TTL 28日) | 396 | 5.29e7 | **22.9 s** | 36.7 s | 2.35 M/s |
| **v5 pubkey (TTL 28日)** | 7776 | 3.33e8 | **144.1 s** | 28.7 s | 2.53 M/s |
| v4 msg 本文1000 (4日) | 1404 | 1.51e7 | **6.5 s** | 2.2 s | 4.71 M/s |
| **v5 msg 本文1000 (4日)** | 8783 | 6.14e7 | **26.6 s** | 15.1 s | 2.79 M/s |
| v5 getpubkey (28日) | 54 | 4.00e7 | **17.3 s** | 4.3 s | 1.86 M/s |
| v5 broadcast 本文1000 (4日) | 8782 | 6.14e7 | **26.6 s** | 34.5 s | 2.13 M/s |

読み取れること:

1. **v4 pubkeyの期待22.9秒は、DESIGN.md §5.1が実運用で観測していた「実測20秒超」と
   一致する。** 校正が正しいことの裏付けになっている。
2. **v5 pubkeyの期待144秒(約2.4分)がPQ化の最大の実務的コスト。** v4の6.3倍。
   アドレスを作るたびに、16コアを2分半使い切ることになる。
3. msgは26.6秒(v4の4.1倍)。送信のたびにこれを払う。TTLを短くすれば比例して下がる
   (TTLの項が支配的なので、4日→1日で約1/4)。
4. **getpubkeyは54byteしかないのに17.3秒かかる。** `payloadLengthExtraBytes=1000` が
   長さに加算されるため、小さいオブジェクトのPoWコストは実質「1054 byte分 × TTL」で
   決まる。これはv4/v5共通の性質で、PQ化とは無関係。

この数字が §9.3 の「PoWを専用ワーカーへ追い出す改修がv5の前提条件」という結論の根拠。
2分半のあいだ`network_epoll_thread`が止まると全ピア接続が落ちる。

### 8.5 生の出力

`build-Release/src/pq/bm-pq-bench --pow` の出力を DESIGN-LOG.md(2026-09-17の節)に
貼ってある。

---

## 9. 移行とロードマップ

### 9.1 段階

1. **プロトタイプ(この文書の時点)** — 暗号・アドレス・オブジェクトのみ。daemon本体からは
   参照していない。テストとベンチマークだけが `src/pq` を使う。
2. **受信側の実装** — `object_sync.c` に objectVersion=5/2/6 の分岐を足し、v5 identityを
   `identity.db` に保存できるようにする。この段階までなら既存ネットワークに何も影響しない。
3. **送信側の実装** — `send_pipeline.c` / API / CLI にv5アドレス対応を足す。
   PoWコストが上がるので、TTL既定値の見直し(§9.3)もここで行う。
4. **相互運用テスト** — testnet上で2ノード間のv5 msg往復と、v4しか知らないノードを
   経由した場合の中継が壊れないことを確認する。
5. **提案の公開** — ここまでの実測値を添えてBitmessageコミュニティへ提案。

### 9.2 既存アドレスとの共存

v4とv5は別アドレスとして共存する。同一ユーザーが両方を持ち、アドレス帳に
「この相手はv5を持っているか」を記録するのが現実的。v4→v5の移行告知を
**v4 broadcastでv5アドレスを流す**形で行えるのがBitmessageの都合の良い点。

### 9.3 未解決事項

- **本文長上限の再設定。** msgオブジェクトの固定オーバーヘッドが増える分、
  `BM_MAX_SUBJECT_PLUS_BODY_LEN`(現在 2^18-500)をv5用に下げる必要がある(§8.3に実測値)。
- **pubkey v5のPoWが重い(v5実装の前提条件)。** 28日TTL×7.8KBで現行の6倍以上の
  試行回数になる(§8.3)。単に待ち時間が伸びるだけでなく、**現在の実装ではPoWが
  呼び出し元スレッドをブロックする**のが問題になる。DESIGN.md §5.1の既知の制限
  「getpubkeyへの自応答PoW中は`network_epoll_thread`(単一スレッド)がブロックされる」
  は、v4では実測20秒超だったものがv5では数分規模になる。この状態では全ピア接続が
  その間停止してしまうため、**v5を実装する前にPoWを専用ワーカーへ追い出す改修が必須**
  (これまでは「許容できるトレードオフ」だったものが、v5では許容できなくなる)。
  合わせてTTLを短くする(例: 7日)+再告知の頻度を上げる運用も検討する。
- **getpubkey応答のスロットリング。** 既存の既知ギャップ(DESIGN.md §5.1)がv5では
  より深刻になる(1回の応答コストが上がるため)。
- **ack payloadのv5対応**(§7.5)。
- **identity.dbのスキーマ。** v5の鍵はv4の32/65byteと桁が違う(sk_sig 4064 + sk_kem 2432)。
  §7.1のvault方式(2段階KDF)との組み合わせ方を決める必要がある。
- **X-Wingのテストベクタによる検証。** 現状は自己往復テストのみで、draftの
  公式テストベクタとの突合せをしていない。ML-KEM/ML-DSA本体についても
  上流のNIST KATを回していない(vendorした参照実装をそのまま使っているので
  上流のCI結果に依存している状態)。

---

## 10. 検討して採らなかった案

### 10.1 新しいobjectTypeを定義する

§3.4の通り。既存ノードがmsg/broadcastを「versionを見て、復号を試みる前に」捨ててくれる
性質を活かせなくなる。

### 10.2 identifierを20byteのまま維持する

アドレス文字列の長さ(34文字 vs 53文字)は魅力だが、2^80の衝突耐性がPQ化の目的と
釣り合わない(§4.1)。

### 10.3 ML-DSA-44 / ML-KEM-512(Category 1)にする

msgオブジェクトを約1.8KB小さくできる(§8.1の鍵・署名長から算出)。恒久アーカイブされる
という性質から既定はCategory 3にしたが、**プロファイル2**として後から追加できる設計に
してある(アドレスversionを1つ増やす形)。

### 10.4 送信者の公開鍵をmsgに載せない(pubkey参照にする)

msgから `pk_sig(1984) + pk_kem(1216) = 3200 byte` を削れるが、
受信側が返信・検証のために別途pubkeyオブジェクトを取りに行く必要が生じ、
「誰が誰と通信しているか」をネットワークに晒すgetpubkeyトラフィックが増える。
Bitmessageの匿名性の考え方と衝突するので採らない。bitfieldのビットで
「省略した」ことを表明できる拡張余地だけ残しておく。

### 10.5 署名をML-DSAだけにする(ハイブリッドをやめる)

3373 → 3309 byte の削減にしかならず、§3.3のメリットを捨てる理由が無い。

### 10.6 PoWのアルゴリズムを変える

§1.3の通り。
