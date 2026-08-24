cmake_minimum_required(VERSION 3.25.0)
project(bitmessage VERSION 1.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

# §11 2026-08-24 backlog項目9: メモリリーク・バッファオーバーフロー・メモリ管理ミスの
# 検査体制。既定はOFF(通常のbuild-Debugでのビルド速度・実行速度に影響させないため)。
# 有効化する場合は専用ディレクトリ(例: build-Sanitize)を使い、build-Debugとは分離する
# 運用を想定(CLAUDE.md「Build」参照)。ASan/UBSanは同一プロセスで併用可能だが、
# ThreadSanitizerはinstrumentationが競合し同時併用できないため別オプションにしてある
# (BM_ENABLE_ASAN/BM_ENABLE_UBSANとBM_ENABLE_TSANを同時にONにするとFATAL_ERROR)。
option(BM_ENABLE_ASAN "Enable AddressSanitizer (+LeakSanitizer)" OFF)
option(BM_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(BM_ENABLE_TSAN "Enable ThreadSanitizer (data race detection)" OFF)

if(BM_ENABLE_TSAN AND (BM_ENABLE_ASAN OR BM_ENABLE_UBSAN))
    message(FATAL_ERROR "BM_ENABLE_TSAN cannot be combined with BM_ENABLE_ASAN/BM_ENABLE_UBSAN "
                         "(their instrumentation conflicts); use separate build directories.")
endif()

set(BM_SANITIZE_FLAGS "")
if(BM_ENABLE_ASAN)
    list(APPEND BM_SANITIZE_FLAGS "address")
endif()
if(BM_ENABLE_UBSAN)
    list(APPEND BM_SANITIZE_FLAGS "undefined")
endif()
if(BM_ENABLE_TSAN)
    list(APPEND BM_SANITIZE_FLAGS "thread")
endif()
if(BM_SANITIZE_FLAGS)
    list(JOIN BM_SANITIZE_FLAGS "," BM_SANITIZE_FLAGS_JOINED)
    add_compile_options(-fno-omit-frame-pointer -g "-fsanitize=${BM_SANITIZE_FLAGS_JOINED}")
    add_link_options("-fsanitize=${BM_SANITIZE_FLAGS_JOINED}")
endif()

add_subdirectory(src)

# §11 2026-08-24 backlog項目10の3/5: cmake --install用のinstall()定義。GNUInstallDirsで
# ${CMAKE_INSTALL_BINDIR}(既定"bin")・${CMAKE_INSTALL_DATADIR}(既定"share")等の
# ディストリ標準的な相対パスを得る(ハードコードしない)。DBファイル・設定ファイルの
# 置き場所(BM_DATA_DIR/BM_CONFIG_FILE)はユーザー状態データのためインストール対象に
# 含めない(backlog項目10の2/5、main.c参照。既定はCWDのまま、systemdユニット
# ファイル(backlog項目10の4/5、下記)側でEnvironment=として明示指定する)。
include(GNUInstallDirs)

install(TARGETS bitmessaged bitmessage-cli
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# seeds/observed_nodes.txtは読み取り専用でソースツリーに同梱されるbootstrapシード
# (ユーザー状態データではない)なので、FHS的にはshareへインストールするのが適切。
# インストール後のパスはBM_SEEDS_FILE環境変数(main.c、既定"seeds/observed_nodes.txt")で
# 明示的に指定する(未設定時はCWD相対のままなので、インストール後に使う場合は
# systemdユニットファイル側でEnvironment=BM_SEEDS_FILE=<この行の実際のインストール先>
# を設定する必要がある)。
install(FILES seeds/observed_nodes.txt
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bitmessage)

# §11 2026-08-24 backlog項目10の4/5: systemdユニットファイル。pkg-config経由で
# systemdsystemunitdirを問い合わせる方式(pkg_check_modules(systemd))は、ビルド環境に
# systemdの開発用pkg-configファイルが無い場合に失敗しうるため、多くのCMakeプロジェクトで
# 使われている${CMAKE_INSTALL_LIBDIR}/systemd/systemへの直接インストールに倣った
# (prefix=/usr/localなら/usr/local/lib/systemd/system、prefix=/usrなら
# /usr/lib/systemd/system)。systemdユニットファイル自体(systemd/bitmessaged.service)は
# ExecStart等のパスをCMAKE_INSTALL_PREFIX既定値(/usr/local)決め打ちで書いてあるため、
# 別prefixでインストールする場合はユニットファイル側も合わせて書き換える必要がある
# (ユニットファイル冒頭のコメント参照)。
install(FILES systemd/bitmessaged.service
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)

enable_testing()
add_subdirectory(tests)
