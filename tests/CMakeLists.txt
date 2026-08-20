# TODO: 他モジュール(varint/base58/PoW target計算)の単体テストも追加していく

add_executable(test_address_vectors test_address_vectors.c)
target_link_libraries(test_address_vectors PRIVATE bm_core)
add_test(NAME address_vectors COMMAND test_address_vectors)

add_executable(test_crypto_roundtrip test_crypto_roundtrip.c)
target_link_libraries(test_crypto_roundtrip PRIVATE bm_core)
add_test(NAME crypto_roundtrip COMMAND test_crypto_roundtrip)

add_executable(test_keyring test_keyring.c)
target_link_libraries(test_keyring PRIVATE bm_core)
add_test(NAME keyring COMMAND test_keyring)

add_executable(test_message_builder test_message_builder.c)
target_link_libraries(test_message_builder PRIVATE bm_core bm_infra)
add_test(NAME message_builder COMMAND test_message_builder)

add_executable(test_trial_decrypt test_trial_decrypt.c)
target_link_libraries(test_trial_decrypt PRIVATE bm_core bm_infra bm_pow)
add_test(NAME trial_decrypt COMMAND test_trial_decrypt)

add_executable(test_send_pipeline test_send_pipeline.c)
target_link_libraries(test_send_pipeline PRIVATE bm_core bm_infra bm_pow)
add_test(NAME send_pipeline COMMAND test_send_pipeline)

add_executable(test_json test_json.c)
target_link_libraries(test_json PRIVATE bm_common)
add_test(NAME json COMMAND test_json)

add_executable(test_api_server test_api_server.c)
target_link_libraries(test_api_server PRIVATE bm_core bm_infra bm_pow Threads::Threads)
add_test(NAME api_server COMMAND test_api_server)

add_test(NAME cli_integration
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_cli_integration.sh
                 $<TARGET_FILE:bitmessaged> $<TARGET_FILE:bitmessage-cli>)

add_executable(test_network_testnet test_network_testnet.c)
target_link_libraries(test_network_testnet PRIVATE bm_infra bm_common)
add_test(NAME network_testnet COMMAND test_network_testnet)
