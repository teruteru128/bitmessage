add_executable(bitmessage-cli
    main.c
    http_client.c
)

target_link_libraries(bitmessage-cli PRIVATE bm_common OpenSSL::Crypto)
