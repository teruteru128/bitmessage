add_subdirectory(common)
add_subdirectory(infra)
add_subdirectory(core)
add_subdirectory(pow)
add_subdirectory(cli)

add_executable(bitmessaged main.c)
target_link_libraries(bitmessaged PRIVATE
    bm_core
    bm_infra
    bm_pow
    bm_common
    Threads::Threads
    OpenSSL::Crypto
    SQLite::SQLite3
)
