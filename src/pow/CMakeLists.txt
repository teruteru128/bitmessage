add_library(bm_pow STATIC
    pow_engine.c
)

target_include_directories(bm_pow PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_pow PUBLIC bm_common Threads::Threads)
