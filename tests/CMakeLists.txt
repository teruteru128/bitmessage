# TODO: 他モジュール(base58/PoW target計算)の単体テストも追加していく

add_executable(test_varint test_varint.c)
target_link_libraries(test_varint PRIVATE bm_common)
add_test(NAME varint COMMAND test_varint)

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
target_link_libraries(test_network_testnet PRIVATE bm_infra bm_common Threads::Threads)
add_test(NAME network_testnet COMMAND test_network_testnet)

add_executable(test_pubkey_cache test_pubkey_cache.c)
target_link_libraries(test_pubkey_cache PRIVATE bm_core bm_infra)
add_test(NAME pubkey_cache COMMAND test_pubkey_cache)

add_executable(test_object_sync test_object_sync.c)
target_link_libraries(test_object_sync PRIVATE bm_core bm_infra bm_pow)
add_test(NAME object_sync COMMAND test_object_sync)

add_executable(test_pow_engine test_pow_engine.c)
target_link_libraries(test_pow_engine PRIVATE bm_pow bm_common OpenSSL::Crypto)
add_test(NAME pow_engine COMMAND test_pow_engine)

add_executable(test_getpubkey_automation test_getpubkey_automation.c)
target_link_libraries(test_getpubkey_automation PRIVATE bm_core bm_infra bm_pow Threads::Threads)
add_test(NAME getpubkey_automation COMMAND test_getpubkey_automation)

add_executable(test_resend test_resend.c)
target_link_libraries(test_resend PRIVATE bm_core bm_infra bm_pow)
add_test(NAME resend COMMAND test_resend)

add_executable(test_broadcast test_broadcast.c)
target_link_libraries(test_broadcast PRIVATE bm_core bm_infra bm_pow Threads::Threads)
add_test(NAME broadcast COMMAND test_broadcast)

add_executable(test_config_store test_config_store.c)
target_link_libraries(test_config_store PRIVATE bm_core bm_infra Threads::Threads)
add_test(NAME config_store COMMAND test_config_store)

add_executable(test_chan test_chan.c)
target_link_libraries(test_chan PRIVATE bm_core bm_infra bm_pow)
add_test(NAME chan COMMAND test_chan)

add_executable(test_inbound test_inbound.c)
target_link_libraries(test_inbound PRIVATE bm_core bm_infra)
add_test(NAME inbound COMMAND test_inbound)

add_executable(test_tor_control test_tor_control.c)
target_link_libraries(test_tor_control PRIVATE bm_core bm_infra)
add_test(NAME tor_control COMMAND test_tor_control)

add_executable(test_config_file test_config_file.c)
target_link_libraries(test_config_file PRIVATE bm_core)
add_test(NAME config_file COMMAND test_config_file)

add_executable(test_peer_rating_on_disconnect test_peer_rating_on_disconnect.c)
target_link_libraries(test_peer_rating_on_disconnect PRIVATE bm_core bm_infra Threads::Threads)
add_test(NAME peer_rating_on_disconnect COMMAND test_peer_rating_on_disconnect)

add_executable(test_peer_registry_proxy test_peer_registry_proxy.c)
target_link_libraries(test_peer_registry_proxy PRIVATE bm_core bm_infra)
add_test(NAME peer_registry_proxy COMMAND test_peer_registry_proxy)

add_executable(test_peer_manager_self test_peer_manager_self.c)
target_link_libraries(test_peer_manager_self PRIVATE bm_core)
add_test(NAME peer_manager_self COMMAND test_peer_manager_self)

add_executable(test_dandelion_stage1 test_dandelion_stage1.c)
target_link_libraries(test_dandelion_stage1 PRIVATE bm_core bm_infra)
add_test(NAME dandelion_stage1 COMMAND test_dandelion_stage1)

add_executable(test_dandelion_stage2 test_dandelion_stage2.c)
target_link_libraries(test_dandelion_stage2 PRIVATE bm_core bm_infra)
add_test(NAME dandelion_stage2 COMMAND test_dandelion_stage2)

add_executable(test_dandelion_stage3 test_dandelion_stage3.c)
target_link_libraries(test_dandelion_stage3 PRIVATE bm_core bm_infra)
add_test(NAME dandelion_stage3 COMMAND test_dandelion_stage3)

add_executable(test_peer_connector_shutdown test_peer_connector_shutdown.c)
target_link_libraries(test_peer_connector_shutdown PRIVATE bm_core bm_infra)
add_test(NAME peer_connector_shutdown COMMAND test_peer_connector_shutdown)

add_executable(test_peer_connector_choose test_peer_connector_choose.c)
target_link_libraries(test_peer_connector_choose PRIVATE bm_core bm_infra)
add_test(NAME peer_connector_choose COMMAND test_peer_connector_choose)

add_executable(test_network_format_host_port test_network_format_host_port.c)
target_link_libraries(test_network_format_host_port PRIVATE bm_infra)
add_test(NAME network_format_host_port COMMAND test_network_format_host_port)

add_executable(test_logging test_logging.c)
target_link_libraries(test_logging PRIVATE bm_common Threads::Threads)
add_test(NAME logging COMMAND test_logging)
