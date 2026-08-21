add_library(bm_infra STATIC
    protocol.c
    network.c
    object.c
    peer_manager.c
    peer_connector.c
    object_store.c
    object_sync.c
    peer_registry.c
)

target_include_directories(bm_infra PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# object_sync.cはcore層(trial_decrypt/pubkey_cache/messages_store)へ配線するためbm_coreに依存する。
# bm_coreはinfra層に依存しない(片方向、循環しない)。
target_link_libraries(bm_infra PUBLIC bm_common bm_core bm_pow)
