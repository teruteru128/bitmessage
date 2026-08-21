add_subdirectory(common)
add_subdirectory(pow)
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
