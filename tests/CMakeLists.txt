# TODO: 他モジュール(varint/base58/PoW target計算)の単体テストも追加していく

add_executable(test_address_vectors test_address_vectors.c)
target_link_libraries(test_address_vectors PRIVATE bm_core)
add_test(NAME address_vectors COMMAND test_address_vectors)
