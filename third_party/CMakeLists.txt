# §PQ 2026-09-17 ML-DSA(FIPS 204)/ML-KEM(FIPS 203)のvendorビルド定義。
# 詳細な出自・ライセンス・vendor時の改変点はpqcrystals/README.mdを参照。
#
# パラメータセットごとに別ターゲットを作る:参照実装はコンパイル時マクロ
# (DILITHIUM_MODE / KYBER_K)でパラメータを切り替える設計で、公開シンボルは
# その値に応じてpqcrystals_dilithium{2,3,5}_ref_* / pqcrystals_kyber{512,768,1024}_ref_*
# へnamespace化される。したがって同じ.cを別マクロで複数回コンパイルしてもリンク時に
# 衝突しない。DESIGN-PQ.md §8のベンチマークで全パラメータセットを横並びに測るために
# 3種類ずつ全部ビルドしている(本番プロファイルはML-DSA-65 + ML-KEM-768のみ)。
#
# 例外がfips202(SHAKE/SHA3)で、こちらは
#   pqcrystals_dilithium_fips202_ref_* / pqcrystals_kyber_fips202_ref_*
# とファミリ単位のnamespaceしか持たない(パラメータセット名が入らない)。
# パラメータセットごとにコンパイルすると重複定義になるため、ファミリごとに
# 1回だけビルドする独立ターゲットに切り出してある。

set(BM_PQ_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pqcrystals)

# --- 共通: randombytes差し替え(OpenSSLのCSPRNGへ委譲) ---
add_library(bm_pq_randombytes STATIC ${BM_PQ_DIR}/randombytes.c)
target_include_directories(bm_pq_randombytes PRIVATE ${BM_PQ_DIR})
target_link_libraries(bm_pq_randombytes PUBLIC OpenSSL::Crypto)

# --- fips202(ファミリごとに1回だけ) ---
add_library(bm_pq_fips202_dilithium STATIC ${BM_PQ_DIR}/dilithium/fips202.c)
target_include_directories(bm_pq_fips202_dilithium PRIVATE ${BM_PQ_DIR}/dilithium)

add_library(bm_pq_fips202_kyber STATIC ${BM_PQ_DIR}/kyber/fips202.c)
target_include_directories(bm_pq_fips202_kyber PRIVATE ${BM_PQ_DIR}/kyber)

# --- ML-DSA(Dilithium) ---
set(BM_MLDSA_SOURCES
    ${BM_PQ_DIR}/dilithium/sign.c
    ${BM_PQ_DIR}/dilithium/packing.c
    ${BM_PQ_DIR}/dilithium/polyvec.c
    ${BM_PQ_DIR}/dilithium/poly.c
    ${BM_PQ_DIR}/dilithium/ntt.c
    ${BM_PQ_DIR}/dilithium/reduce.c
    ${BM_PQ_DIR}/dilithium/rounding.c
    ${BM_PQ_DIR}/dilithium/symmetric-shake.c
    ${BM_PQ_DIR}/dilithium/keypair_derand.c
)

foreach(mode 2 3 5)
    add_library(bm_pq_mldsa${mode} STATIC ${BM_MLDSA_SOURCES})
    target_compile_definitions(bm_pq_mldsa${mode} PRIVATE DILITHIUM_MODE=${mode})
    target_include_directories(bm_pq_mldsa${mode} PRIVATE ${BM_PQ_DIR}/dilithium ${BM_PQ_DIR})
    target_link_libraries(bm_pq_mldsa${mode} PUBLIC bm_pq_fips202_dilithium bm_pq_randombytes)
endforeach()

# --- ML-KEM(Kyber) ---
set(BM_MLKEM_SOURCES
    ${BM_PQ_DIR}/kyber/kem.c
    ${BM_PQ_DIR}/kyber/indcpa.c
    ${BM_PQ_DIR}/kyber/polyvec.c
    ${BM_PQ_DIR}/kyber/poly.c
    ${BM_PQ_DIR}/kyber/ntt.c
    ${BM_PQ_DIR}/kyber/cbd.c
    ${BM_PQ_DIR}/kyber/reduce.c
    ${BM_PQ_DIR}/kyber/verify.c
    ${BM_PQ_DIR}/kyber/symmetric-shake.c
)

foreach(k 2 3 4)
    add_library(bm_pq_mlkem${k} STATIC ${BM_MLKEM_SOURCES})
    target_compile_definitions(bm_pq_mlkem${k} PRIVATE KYBER_K=${k})
    target_include_directories(bm_pq_mlkem${k} PRIVATE ${BM_PQ_DIR}/kyber ${BM_PQ_DIR})
    target_link_libraries(bm_pq_mlkem${k} PUBLIC bm_pq_fips202_kyber bm_pq_randombytes)
endforeach()

# 全パラメータセットをまとめて引くためのINTERFACEターゲット(src/pq・testsが使う)。
add_library(bm_pq_backend INTERFACE)
target_link_libraries(bm_pq_backend INTERFACE
    bm_pq_mldsa2 bm_pq_mldsa3 bm_pq_mldsa5
    bm_pq_mlkem2 bm_pq_mlkem3 bm_pq_mlkem4
)
