cmake_minimum_required(VERSION 3.23)
project(prism LANGUAGES C CXX)

# CMake 4.0+ 将 CMP0167 行为改为 NEW（FindBoost 弃用），此处显式设置避免警告
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Release 模式优化：-O3 最大优化，-ffunction-sections/-fdata-sections 配合链接器 --gc-sections 裁剪未使用符号
# 仅对 C/CXX 生效，避免传给 NASM 汇编器导致编译失败
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        $<$<COMPILE_LANGUAGE:C,CXX>:-O3>
        $<$<COMPILE_LANGUAGE:C,CXX>:-ffunction-sections>
        $<$<COMPILE_LANGUAGE:C,CXX>:-fdata-sections>
    )
    add_link_options(-Wl,--gc-sections)
endif()

# === 所有依赖均通过 FetchContent 或本地查找自动解决 ===
include(FetchContent)

# --- spdlog v1.17.0 ---
# 日志库。含少量编译组件（rotating_file_sink、async_logger 等），
# 但源码量很小，FetchContent 拉取编译只需十几秒。
# SPDLOG_BUILD_EXAMPLE=OFF: 不编译 spdlog 自带示例
# SPDLOG_BUILD_TESTS=OFF: 不编译 spdlog 自带测试
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    spdlog
    URL https://github.com/gabime/spdlog/archive/refs/tags/v1.17.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(spdlog)

# --- Boost 1.89.0 ---
# 项目仅使用 Boost.Asio（协程/异步 I/O）和 Boost.System（error_code），均为 header-only。
# 从 Boost 官方归档下载完整源码包（~147MB），CMake 缓存到 _deps/ 目录，首次下载后复用。
# 不使用 GitHub 是因为 boostorg/boost 超级仓库依赖 160+ git submodule，国内网络拉取不可靠。
FetchContent_Declare(
    boost_src
    URL https://archives.boost.io/release/1.89.0/source/boost_1_89_0.tar.bz2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE  # 解压文件使用下载时间戳，确保 URL 变更时触发重新构建
)
FetchContent_MakeAvailable(boost_src)

# 创建 INTERFACE 库：仅传递头文件路径和编译宏，不产生编译产物
set(boost_include_dir "${boost_src_SOURCE_DIR}")
add_library(boost_system_header_only INTERFACE)
target_include_directories(boost_system_header_only INTERFACE ${boost_include_dir})
# BOOST_ERROR_CODE_HEADER_ONLY: boost::system::error_code 纯头文件实现，不链接 boost_system 库
# BOOST_SYSTEM_NO_LIB: 禁止 CMake 自动链接 Boost.System 共享库
target_compile_definitions(boost_system_header_only INTERFACE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
add_library(Boost::system ALIAS boost_system_header_only)

# --- glaze v6.5.1 ---
# 高性能 JSON 序列化库，纯 header-only。
# GLAZE_INSTALL=OFF: 不生成 glaze 的 install 目标，避免污染项目的 install 步骤
set(GLAZE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    glaze
    URL https://github.com/stephenberry/glaze/archive/refs/tags/v6.5.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(glaze)

# --- BoringSSL ---
# Google 维护的 TLS 库，API 兼容 OpenSSL。项目通过 <openssl/*.h> 头文件和 OpenSSL 风格的
# CMake 目标（OpenSSL::SSL / OpenSSL::Crypto）使用，代码无需修改。
# BoringSSL 的 CMake 导出 ssl 和 crypto 目标，此处创建 OpenSSL 兼容别名。
# MinGW + Windows 下 fiat_p256_adx 的 .S 文件不支持 PE/COFF 格式，需要 patch 移除。
# AES-NI 等使用编译器内建汇编（<immintrin.h>）的部分可以正常工作。
set(OPENSSL_NO_ASM OFF CACHE BOOL "" FORCE)
# 禁用 BoringSSL 内部的 testing/benchmark，避免与项目自身的 Google Benchmark 目标名冲突
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
# 不编译 BoringSSL 自带的 bssl/decrepit 等工具（项目只需要 ssl/crypto/pki 库）
set(BORINGSSL_BUILD_TOOL OFF CACHE BOOL "" FORCE)
find_package(Threads REQUIRED)
FetchContent_Declare(
    boringssl
    URL https://github.com/google/boringssl/archive/beafe3db15e3213bbce1711f85f704b6c00413d1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_Populate(boringssl)

# MinGW patch: 从 BCM_SOURCES_ASM 中移除 fiat_p256_adx 文件
# 这两个 .S 文件只支持 Apple 和 ELF 格式，不支持 Windows PE/COFF
# 同时修改 p256_64.h 中的条件编译，避免调用这些未实现的函数
if(MINGW)
    # 1. 从 sources.cmake 中移除 fiat_p256_adx 文件
    set(SOURCES_CMAKE "${boringssl_SOURCE_DIR}/gen/sources.cmake")
    file(READ ${SOURCES_CMAKE} SOURCES_CONTENT)
    string(REPLACE "  third_party/fiat/asm/fiat_p256_adx_mul.S\n" "" SOURCES_CONTENT "${SOURCES_CONTENT}")
    string(REPLACE "  third_party/fiat/asm/fiat_p256_adx_sqr.S\n" "" SOURCES_CONTENT "${SOURCES_CONTENT}")
    file(WRITE ${SOURCES_CMAKE} "${SOURCES_CONTENT}")

    # 2. 修改 p256_64.h 中的条件编译，添加 !defined(OPENSSL_WINDOWS)
    set(P256_64_H "${boringssl_SOURCE_DIR}/third_party/fiat/p256_64.h")
    file(READ ${P256_64_H} P256_CONTENT)
    string(REPLACE
        "#if !defined(OPENSSL_NO_ASM) && defined(__GNUC__) && defined(__x86_64__)"
        "#if !defined(OPENSSL_NO_ASM) && defined(__GNUC__) && defined(__x86_64__) && !defined(OPENSSL_WINDOWS)"
        P256_CONTENT "${P256_CONTENT}")
    file(WRITE ${P256_64_H} "${P256_CONTENT}")
endif()

add_subdirectory(${boringssl_SOURCE_DIR} ${boringssl_BINARY_DIR})

# 创建 OpenSSL 兼容别名
if(NOT TARGET OpenSSL::SSL AND TARGET ssl)
    add_library(OpenSSL::SSL ALIAS ssl)
endif()
if(NOT TARGET OpenSSL::Crypto AND TARGET crypto)
    add_library(OpenSSL::Crypto ALIAS crypto)
endif()

# --- BLAKE3 ---
# BLAKE3 哈希和密钥派生函数，用于 SS2022 (SIP022) 密钥派生。
# BLAKE3 是 Rust crate，C API 在 c/ 子目录中，需要手动集成。
FetchContent_Declare(
    blake3
    URL https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.8.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(blake3)

# BLAKE3 C 库（手动构建，不使用 Rust/Cargo）
set(BLAKE3_C_DIR "${blake3_SOURCE_DIR}/c")
add_library(blake3_c STATIC
    ${BLAKE3_C_DIR}/blake3.c
    ${BLAKE3_C_DIR}/blake3_dispatch.c
    ${BLAKE3_C_DIR}/blake3_portable.c
    ${BLAKE3_C_DIR}/blake3_sse2.c
    ${BLAKE3_C_DIR}/blake3_sse41.c
    ${BLAKE3_C_DIR}/blake3_avx2.c
    ${BLAKE3_C_DIR}/blake3_avx512.c
)
target_include_directories(blake3_c PUBLIC ${BLAKE3_C_DIR})
# BLAKE3 各 SIMD 源文件需要对应的指令集编译选项（per-file）
set_source_files_properties(${BLAKE3_C_DIR}/blake3_sse2.c PROPERTIES COMPILE_FLAGS "-msse2")
set_source_files_properties(${BLAKE3_C_DIR}/blake3_sse41.c PROPERTIES COMPILE_FLAGS "-msse4.1")
set_source_files_properties(${BLAKE3_C_DIR}/blake3_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
set_source_files_properties(${BLAKE3_C_DIR}/blake3_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")

# BoringSSL 的 bssl/decrepit 等目标无条件编译，排除出默认构建避免 MinGW 编译错误
set_target_properties(bssl PROPERTIES EXCLUDE_FROM_ALL TRUE)
if(TARGET decrepit)
    set_target_properties(decrepit PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

if(NOT TARGET OpenSSL::SSL AND TARGET ssl)
    add_library(OpenSSL::SSL ALIAS ssl)
endif()
if(NOT TARGET OpenSSL::Crypto AND TARGET crypto)
    add_library(OpenSSL::Crypto ALIAS crypto)
endif()

enable_testing()

# 可选的基准测试和压力测试工具开关
option(PRISM_ENABLE_BENCHMARK "Enable forward benchmarks" ON)
message(STATUS "PRISM_ENABLE_BENCHMARK=${PRISM_ENABLE_BENCHMARK}")

option(PRISM_ENABLE_STRESS "Enable forward stress tools" ON)
message(STATUS "PRISM_ENABLE_STRESS=${PRISM_ENABLE_STRESS}")

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(benchmarks)
add_subdirectory(stresses)
