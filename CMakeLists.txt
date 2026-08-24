cmake_minimum_required(VERSION 3.25.0)
project(bitmessage VERSION 1.1.0 LANGUAGES C)

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

enable_testing()
add_subdirectory(tests)
