add_library(bm_common STATIC
    queue.c
    varint.c
    base58.c
    hash.c
    db_common.c
    json.c
    logging.c
)

target_include_directories(bm_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_common PUBLIC Threads::Threads OpenSSL::Crypto SQLite::SQLite3)
