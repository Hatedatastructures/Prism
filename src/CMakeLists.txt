# 收集库源文件
set(FORWARD_LIB_SOURCES
        forward-engine/protocol/http/header.cpp
        ../include/forward-engine/protocol/http/header.hpp
        forward-engine/protocol/http/request.cpp
        ../include/forward-engine/protocol/http/request.hpp
        forward-engine/trace/monitor.cpp
        ../include/forward-engine/trace/monitor.hpp
        forward-engine/protocol/http/response.cpp
        ../include/forward-engine/protocol/http/response.hpp
        forward-engine/protocol/http/serialization.cpp
        ../include/forward-engine/protocol/http/serialization.hpp
        forward-engine/protocol/http/deserialization.cpp
        ../include/forward-engine/protocol/http/deserialization.hpp
        forward-engine/transport/positive.cpp
        ../include/forward-engine/transport/positive.hpp
        forward-engine/transport/reverse.cpp
        ../include/forward-engine/transport/reverse.hpp
        forward-engine/agent/frame.cpp
        ../include/forward-engine/protocol/frame.hpp
        forward-engine/agent/distributor.cpp
        ../include/forward-engine/agent/distributor.hpp
        forward-engine/transport/source.cpp
        ../include/forward-engine/transport/source.hpp
        ../include/forward-engine/transport/obscura.hpp
        ../include/forward-engine/agent/session.hpp
        ../include/forward-engine/rule/blacklist.hpp
        ../include/forward-engine/protocol/http.hpp
        ../include/forward-engine/protocol/http/constants.hpp
        ../include/forward-engine/core/broker.hpp
        ../include/forward-engine/agent.hpp
        ../include/forward-engine/agent/worker.hpp
        forward-engine/rule/blacklist.cpp
        ../include/forward-engine/memory/pointer.hpp
        ../include/forward-engine/transport/adaptation.hpp
        ../include/forward-engine/protocol/analysis.hpp
        forward-engine/protocol/analysis.cpp
        ../include/forward-engine/memory/container.hpp
        ../include/forward-engine/abnormal/deviant.hpp
        ../include/forward-engine/abnormal/security.hpp
        ../include/forward-engine/abnormal/network.hpp
        ../include/forward-engine/abnormal/protocol.hpp
        ../include/forward-engine/abnormal.hpp
        ../include/forward-engine/core/configuration.hpp
        ../include/forward-engine/trace/spdlog.hpp
        forward-engine/trace/spdlog.cpp
        ../include/forward-engine/trace.hpp
        ../include/forward-engine/rule.hpp
        ../include/forward-engine/transformer.hpp
        ../include/forward-engine/transformer/json.hpp
        ../include/forward-engine/agent/config.hpp
        ../include/forward-engine/trace/config.hpp
        ../include/forward-engine/rule/config.hpp
        ../include/forward-engine/memory/pool.hpp
        ../include/forward-engine/memory.hpp
        ../include/forward-engine/transport/transfer.hpp
        ../include/forward-engine/protocol/trojan.hpp
        ../include/forward-engine/protocol/socks5.hpp
        ../include/forward-engine/protocol.hpp
        ../include/forward-engine/agent/handler.hpp
)

# =============================================================
# BoringSSL 引用配置 (引用已安装的库)
# =============================================================

# [重要] 这里填你安装 BoringSSL 的根目录！
# 假设你的目录结构是:
# C:/Program Files/BoringSSL/include/openssl/...
# C:/Program Files/BoringSSL/lib/ssl.lib
# C:/Program Files/BoringSSL/lib/crypto.lib
# 注意：Windows 路径分隔符要用 "/" (反斜杠)
set(BORINGSSL_ROOT "C:/bin/BoringSSL") 

# 检查路径是否存在
if(NOT EXISTS "${BORINGSSL_ROOT}/include")
    message(FATAL_ERROR "BoringSSL include directory not found at ${BORINGSSL_ROOT}/include")
endif()

# 查找静态库文件 (ssl.lib 和 crypto.lib)
# 注意：BoringSSL 编译出来的名字可能是 ssl.lib/crypto.lib 或者 libssl.lib/libcrypto.lib
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

# =============================================================
# (配置结束)
# =============================================================

add_library(${PROJECT_NAME}_static_library STATIC
        ${FORWARD_LIB_SOURCES}
)

target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/forward-engine
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
        # [关键] 将 BoringSSL 头文件路径放在最前面，防止冲突
        ${BORINGSSL_ROOT}/include
)

find_package(spdlog CONFIG REQUIRED)

target_link_libraries(${PROJECT_NAME}_static_library
        PUBLIC
        async_simple::async_simple
        spdlog::spdlog
        glaze::glaze
        Boost::system
        # [关键] 链接你找到的 lib 文件
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
        WIN32_LEAN_AND_MEAN
)

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
