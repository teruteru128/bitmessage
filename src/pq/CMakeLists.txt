# §PQ 2026-09-17 ポスト量子(ML-DSA/ML-KEM)プロトタイプ。DESIGN-PQ.md。
# 当初はdaemon本体から一切参照されず、テストとベンチマークツールからのみ使われる
# 独立したモジュールだった。§11 2026-11-04 項目55(フェーズ2)からbm_coreが依存する
# (src/core/CMakeLists.txt)。bm_pq自身はbm_commonにしか依存しない(bm_coreへ逆向きに
# 依存させると循環するので、v5のアドレス・オブジェクトの処理はbm_pqの中で閉じる)。
add_library(bm_pq STATIC
    pq_crypto.c
    pq_hybrid.c
    address_v5.c
    pq_object.c
)

target_include_directories(bm_pq PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# §PQ 2026-10-01 ML-DSA/ML-KEMのバックエンドはOpenSSL 3.5のEVP(pq_crypto.c)。
# 以前はvendorした参照実装(third_party/pqcrystals、同日削除)をPRIVATEリンクしていた。
target_link_libraries(bm_pq PUBLIC bm_common OpenSSL::Crypto)

# ベンチマークツール(DESIGN-PQ.md §8)。テストではなく手動実行用なのでctestには登録しない。
add_executable(bm-pq-bench bm_pq_bench.c)
target_link_libraries(bm-pq-bench PRIVATE bm_pq bm_core bm_pow bm_common OpenSSL::Crypto)
