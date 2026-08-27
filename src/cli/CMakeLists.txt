add_executable(bitmessage-cli
    main.c
    http_client.c
)

# bitmessaged(src/CMakeLists.txt)と同じ単一の情報源(project()のVERSION)から
# --version表示用に注入する(§11 2026-08-27、bitmessagedへの--version/--help追加とセット)。
target_compile_definitions(bitmessage-cli PRIVATE BM_PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(bitmessage-cli PRIVATE bm_common OpenSSL::Crypto)
