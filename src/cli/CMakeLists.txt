add_executable(bitmessage-cli
    main.c
    http_client.c
    i18n.c
)

# bitmessaged(src/CMakeLists.txt)と同じ単一の情報源(project()のVERSION)から
# --version表示用に注入する(§11 2026-08-27、bitmessagedへの--version/--help追加とセット)。
target_compile_definitions(bitmessage-cli PRIVATE BM_PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(bitmessage-cli PRIVATE bm_common OpenSSL::Crypto)

# §11 2026-11-03 項目54(国際化): 訳(po/<lang>.po)を.moへ変換する。ビルドツリーでは
# 実行ファイルの隣のlocale/<lang>/LC_MESSAGES/に置き、i18n.cが/proc/self/exe基準で見つける
# (インストールしていないbuild-*のCLIやテストからも訳が出るように)。インストール時は
# ${CMAKE_INSTALL_LOCALEDIR}(既定share/locale)へ置き、i18n.cはコンパイル時に埋め込んだ
# BM_INSTALL_LOCALEDIRを使う。言語を増やすときはpo/<lang>.poを追加してBM_LINGUASへ足す。
if(BM_ENABLE_NLS)
    target_compile_definitions(bitmessage-cli PRIVATE
        BM_ENABLE_NLS
        BM_INSTALL_LOCALEDIR="${CMAKE_INSTALL_FULL_LOCALEDIR}")
    target_link_libraries(bitmessage-cli PRIVATE Intl::Intl)

    set(BM_LINGUAS ja)
    set(BM_MO_FILES "")
    foreach(lang IN LISTS BM_LINGUAS)
        set(po_file ${PROJECT_SOURCE_DIR}/po/${lang}.po)
        set(mo_dir ${CMAKE_CURRENT_BINARY_DIR}/locale/${lang}/LC_MESSAGES)
        set(mo_file ${mo_dir}/bitmessage.mo)
        # --checkでprintf書式の不一致(msgidの%dに対しmsgstrが%sになっている等)をビルド時に
        # 弾く。訳の書式が食い違うと実行時に未定義動作になるため
        add_custom_command(
            OUTPUT ${mo_file}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${mo_dir}
            COMMAND ${GETTEXT_MSGFMT_EXECUTABLE} --check -o ${mo_file} ${po_file}
            DEPENDS ${po_file}
            COMMENT "Compiling ${lang}.po"
            VERBATIM)
        list(APPEND BM_MO_FILES ${mo_file})
        install(FILES ${mo_file} DESTINATION ${CMAKE_INSTALL_LOCALEDIR}/${lang}/LC_MESSAGES)
    endforeach()
    add_custom_target(bitmessage-cli-translations ALL DEPENDS ${BM_MO_FILES})
    add_dependencies(bitmessage-cli bitmessage-cli-translations)
endif()

# `cmake --build <dir> --target update-po`: ソースから訳対象の文字列を抜き出して
# po/bitmessage.potを作り直し、po/<lang>.poへ反映する(新しい文字列は未訳、消えた文字列は
# obsoleteとして残る)。その後po/<lang>.poを手で訳し、tests/test_po_up_to_date.shが
# 通ることを確かめる。--add-location=fileにしているのは、行番号まで書くと無関係な変更の
# たびに.po/.potの差分が出るため。
find_program(BM_XGETTEXT_EXECUTABLE xgettext)
if(BM_XGETTEXT_EXECUTABLE AND GETTEXT_MSGMERGE_EXECUTABLE)
    set(BM_UPDATE_PO_COMMANDS
        COMMAND ${BM_XGETTEXT_EXECUTABLE} --language=C --from-code=UTF-8 --keyword=_ --keyword=N_
                --add-comments=TRANSLATORS: --add-location=file --sort-by-file
                --package-name=bitmessage --package-version=${PROJECT_VERSION}
                --msgid-bugs-address=https://github.com/teruteru128/bitmessage/issues
                -o po/bitmessage.pot src/cli/main.c src/cli/i18n.c)
    foreach(lang ja)
        list(APPEND BM_UPDATE_PO_COMMANDS
            COMMAND ${GETTEXT_MSGMERGE_EXECUTABLE} --quiet --update --backup=none --add-location=file
                    po/${lang}.po po/bitmessage.pot)
    endforeach()
    add_custom_target(update-po ${BM_UPDATE_PO_COMMANDS}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        VERBATIM)
endif()
