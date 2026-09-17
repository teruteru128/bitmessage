# third_party/pqcrystals — vendorしたML-KEM / ML-DSA参照実装

[DESIGN-PQ.md](../../DESIGN-PQ.md) のプロトタイプが使うポスト量子暗号の実装。

## 出自

| ディレクトリ | 上流 | 取得コミット | 取得日 |
|---|---|---|---|
| `kyber/` | https://github.com/pq-crystals/kyber (`ref/`) | `3edd5af5991927164edd4aacebfcbee00b8064e7` (2026-08-02) | 2026-09-17 |
| `dilithium/` | https://github.com/pq-crystals/dilithium (`ref/`) | `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` (2026-06-03) | 2026-09-17 |

いずれもFIPS 203(ML-KEM)/ FIPS 204(ML-DSA)に対応した版
(kyber側に `keypair_derand`/`enc_derand`、dilithium側に `*_internal` 系と
context string引数があることで確認できる)。

上流の `ref/` 以下から `.c`/`.h` をそのままコピーし、`test/`・`nistkat/`・`Makefile` は
含めていない。`LICENSE` は各ディレクトリにコピーしてある(**CC0 パブリックドメイン、
または Apache-2.0 のデュアルライセンス**。MITである本体と衝突しない)。

## vendor時の改変

**上流からコピーしたファイルは1バイトも書き換えていない**(差分を追えるようにするため)。
必要な変更は「除外」と「追加」だけで実現している。

### 除外したもの

- `kyber/ref/randombytes.{c,h}` と `dilithium/ref/randombytes.{c,h}`
  - 両者が同名の非namespaceシンボル `randombytes()` を定義しており、同時にリンクすると
    重複定義になる
  - 上流実装はLinuxで `getrandom(2)` を直接叩く独自実装で、このプロジェクトが既に
    依存しているOpenSSLのCSPRNGと二重になる

### 追加したもの

- `randombytes.{c,h}`(このディレクトリ直下) — 上記の差し替え。`RAND_bytes()` へ委譲する。
  失敗時は戻り値でエラーを伝える手段が無いため `abort()` する(弱い乱数で鍵を作るより安全)。
- `dilithium/keypair_derand.{c,h}` — `ML-DSA.KeyGen_internal(ξ)`(FIPS 204 Algorithm 6)。
  ML-KEM側には `crypto_kem_keypair_derand` があるのに、ML-DSA側には「seedを外から渡す」
  公開APIが無い。パスフレーズ由来の決定性アドレス生成(DESIGN-PQ.md §4.2)に必須なので、
  `sign.c` の `crypto_sign_keypair` の中身を複製し `randombytes(seedbuf, SEEDBYTES)` の
  1行だけを引数のseedからの `memcpy` に置き換えたファイルを追加した。

## ビルド構成

パラメータセットごとに別ターゲットとしてビルドする(`../CMakeLists.txt`)。参照実装は
コンパイル時マクロ `DILITHIUM_MODE` / `KYBER_K` でパラメータを切り替え、公開シンボルを
`pqcrystals_dilithium{2,3,5}_ref_*` / `pqcrystals_kyber{512,768,1024}_ref_*` へnamespace化
するため、同じ `.c` を別マクロで複数回コンパイルしても衝突しない。

例外が `fips202.c`(SHAKE/SHA3)で、こちらは `pqcrystals_{dilithium,kyber}_fips202_ref_*` と
**ファミリ単位のnamespaceしか持たない**ため、ファミリごとに1回だけビルドする独立ターゲットに
切り出してある。

`kyber/` と `dilithium/` はヘッダ名が完全に衝突する(`api.h`・`params.h`・`poly.h`・
`polyvec.h`・`ntt.h`・`reduce.h`・`symmetric.h`・`fips202.h`)。そのためインクルードパスは
CMakeで `PRIVATE` に閉じてあり、プロジェクト側からは `src/pq/pq_crypto.c` が
namespace済みシンボルを直接宣言して使う(DESIGN-PQ.md §6)。

## 将来の置き換え

OpenSSL 3.5以降は `EVP_PKEY-ML-DSA` / `EVP_PKEY-ML-KEM` を持つ。それが使えるディストリに
なったら `src/pq/pq_crypto.c` をEVP呼び出しへ書き換え、このディレクトリごと削除できる
(プロトコル側のコードは無変更で済むよう、ラッパ1ファイルに閉じ込めてある)。
