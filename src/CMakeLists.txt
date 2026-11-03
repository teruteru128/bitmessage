add_subdirectory(common)
add_subdirectory(pow)
# §11 2026-11-04 項目55: bm_coreがbm_pqへ依存するようになったので、coreより前に置く
# (bm_pqはbm_commonにしか依存しないので循環しない)
if(BM_ENABLE_PQ)
    add_subdirectory(pq)
endif()
add_subdirectory(core)
add_subdirectory(infra)
add_subdirectory(cli)

add_executable(bitmessaged main.c)
# P2P version messageのuser agent文字列に埋め込むバージョン。CMakeLists.txt(ルート)の
# project(bitmessage VERSION ...)を単一の情報源とし、main.cへ直接ハードコードしない
# (2026-08-21: ハードコードしていたら1.0.0タグ後の更新を忘れて0.1.0のまま化石化していた)。
target_compile_definitions(bitmessaged PRIVATE BM_PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(bitmessaged PRIVATE
    bm_core
    bm_infra
    bm_pow
    bm_common
    Threads::Threads
    OpenSSL::Crypto
    SQLite::SQLite3
)
