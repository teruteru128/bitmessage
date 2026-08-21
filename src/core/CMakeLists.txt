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
