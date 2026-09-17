# §PQ 2026-09-17 ポスト量子(ML-DSA/ML-KEM)プロトタイプ。DESIGN-PQ.md。
# 現時点ではdaemon本体(bm_core/bm_infra)からは一切参照されておらず、テストと
# ベンチマークツールからのみ使われる独立したモジュール。v5を実運用へ組み込む
# 段階になったらbm_coreから依存させる(DESIGN-PQ.md §9のロードマップ)。
add_library(bm_pq STATIC
    pq_crypto.c
    pq_hybrid.c
    address_v5.c
    pq_object.c
)

target_include_directories(bm_pq PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_pq PUBLIC bm_common OpenSSL::Crypto)
# vendorした参照実装のシンボルはpq_crypto.cの中だけで使う(ヘッダ名衝突を避けるため
# インクルードパスも公開しない)のでPRIVATEで十分。
target_link_libraries(bm_pq PRIVATE bm_pq_backend)

# ベンチマークツール(DESIGN-PQ.md §8)。テストではなく手動実行用なのでctestには登録しない。
add_executable(bm-pq-bench bm_pq_bench.c)
target_link_libraries(bm-pq-bench PRIVATE bm_pq bm_core bm_pow bm_common OpenSSL::Crypto)
