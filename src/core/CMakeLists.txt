add_library(bm_core STATIC
    address.c
    crypto.c
    keyring.c
    identity_store.c
    messages_store.c
    message_builder.c
    pubkey_cache.c
    trial_decrypt.c
    broadcast_decrypt.c
    send_pipeline.c
    config_store.c
    config_file.c
    peer_manager.c
    api_server.c
)

target_include_directories(bm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_core PUBLIC bm_common bm_pow SQLite::SQLite3 OpenSSL::Crypto)
# §11 2026-09-15 api_server.cのみが使う。api_server.hにはstruct MHD_Daemon*もcJSON*も
# 露出させていない(§3.5と同じ「公開ヘッダに外部ライブラリの型を出さない」規律)ので
# PRIVATEで足りる(STATICライブラリなのでリンク行には$<LINK_ONLY:>として伝播する)。
target_link_libraries(bm_core PRIVATE PkgConfig::MICROHTTPD PkgConfig::CJSON)
