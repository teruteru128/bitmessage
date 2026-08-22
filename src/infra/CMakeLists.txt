add_library(bm_infra STATIC
    protocol.c
    network.c
    object.c
    peer_connector.c
    object_store.c
    object_sync.c
    peer_registry.c
    tor_control.c
    dandelion.c
)

target_include_directories(bm_infra PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# object_sync.cはcore層(trial_decrypt/pubkey_cache/messages_store)へ配線するためbm_coreに依存する。
# bm_coreはinfra層に依存しない(片方向、循環しない)。
# dandelion.cのexponential_random()がlog()を使うためlibmをリンクする。
find_library(BM_MATH_LIBRARY m)
target_link_libraries(bm_infra PUBLIC bm_common bm_core bm_pow)
if(BM_MATH_LIBRARY)
    target_link_libraries(bm_infra PUBLIC ${BM_MATH_LIBRARY})
endif()
