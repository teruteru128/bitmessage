add_library(bm_infra STATIC
    protocol.c
    network.c
    object.c
    peer_manager.c
    object_store.c
)

target_include_directories(bm_infra PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_infra PUBLIC bm_common)
