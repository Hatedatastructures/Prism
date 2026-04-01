# =============================================================
# BoringSSL setup
# =============================================================
set(BORINGSSL_ROOT "C:/bin/BoringSSL")

if(NOT EXISTS "${BORINGSSL_ROOT}/include")
    message(FATAL_ERROR "BoringSSL include directory not found at ${BORINGSSL_ROOT}/include")
endif()

find_library(LIB_SSL
    NAMES ssl libssl
    PATHS "${BORINGSSL_ROOT}/lib" "${BORINGSSL_ROOT}/lib64"
    NO_DEFAULT_PATH
)

find_library(LIB_CRYPTO
    NAMES crypto libcrypto
    PATHS "${BORINGSSL_ROOT}/lib" "${BORINGSSL_ROOT}/lib64"
    NO_DEFAULT_PATH
)

if(NOT LIB_SSL OR NOT LIB_CRYPTO)
    message(FATAL_ERROR "Could not find ssl.lib or crypto.lib in ${BORINGSSL_ROOT}/lib")
endif()

message(STATUS "Found BoringSSL SSL: ${LIB_SSL}")
message(STATUS "Found BoringSSL Crypto: ${LIB_CRYPTO}")

add_library(${PROJECT_NAME}_static_library STATIC)

target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/prism
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
        ${BORINGSSL_ROOT}/include
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}_static_library
        PUBLIC
        spdlog::spdlog
        glaze::glaze
        Boost::system
        ${LIB_SSL}
        ${LIB_CRYPTO}
        ws2_32
        mswsock
        crypt32
)

target_compile_definitions(${PROJECT_NAME}_static_library
        PUBLIC
        BOOST_ASIO_HEADER_ONLY
        BOOST_ASIO_USE_OPENSSL
        BOOST_ASIO_CONCURRENCY_HINT_UNSAFE  # : 禁用 io_context 内部所有互斥锁
        BOOST_ASIO_DISABLE_VISIBILITY       # : 解决 use_awaitable 重复符号问题
#        BOOST_ASIO_ENABLE_HANDLER_TRACKING  # : 启用处理程序跟踪
        WIN32_LEAN_AND_MEAN
)

add_subdirectory(prism)

add_executable(${PROJECT_NAME}
        main.cpp
)

target_compile_options(${PROJECT_NAME} PRIVATE
        -g1
        -O1
        -fno-keep-inline-dllexport
)

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)
