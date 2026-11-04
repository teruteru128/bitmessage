add_library(bm_core STATIC
    address.c
    crypto.c
    keyring.c
    identity_store.c
    messages_store.c
    message_builder.c
    pubkey_cache.c
    trial_decrypt.c
    broadcast_decrypt.c
    send_pipeline.c
    config_store.c
    config_file.c
    peer_manager.c
    api_server.c
)

target_include_directories(bm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bm_core PUBLIC bm_common bm_pow SQLite::SQLite3 OpenSSL::Crypto)
# §11 2026-11-04 項目55(ポスト量子拡張のフェーズ2、DESIGN-PQ.md §9.1): OpenSSL 3.5以降で
# ビルドしたときだけbm_pqへ依存し、BM_HAVE_PQを定義する。PUBLICにしたのは、bm_infra・
# bitmessaged・テストも同じ条件で#ifdefするため。OpenSSL 3.0環境(CIのubuntu-latest等)では
# 従来通りbm_pq無しでビルドされ、v5の分岐はコンパイルされない。実際にv5を扱うかどうかは
# さらに実行時フラグ([pq] enabled、既定0)で決める。
if(BM_ENABLE_PQ)
    target_link_libraries(bm_core PUBLIC bm_pq)
    target_compile_definitions(bm_core PUBLIC BM_HAVE_PQ=1)
    # §11 2026-11-04 項目55の段3: v5 identityの保存とkeyring
    target_sources(bm_core PRIVATE pq_identity_store.c pq_keyring.c pq_pubkey_cache.c)
endif()
# §11 2026-09-15 api_server.cのみが使う。api_server.hにはstruct MHD_Daemon*もcJSON*も
# 露出させていない(§3.5と同じ「公開ヘッダに外部ライブラリの型を出さない」規律)ので
# PRIVATEで足りる(STATICライブラリなのでリンク行には$<LINK_ONLY:>として伝播する)。
target_link_libraries(bm_core PRIVATE PkgConfig::MICROHTTPD PkgConfig::CJSON)
