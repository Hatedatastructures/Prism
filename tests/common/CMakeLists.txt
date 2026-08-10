# 协议测试公共库（header-only）
# 纯逻辑协议编解码（客户端 + 服务端），无锁无 I/O，全部 .hpp 实现。
# 被 tests/ 下各测试模块引用（prism_test_common）。
add_library(prism_test_common INTERFACE)

target_include_directories(prism_test_common INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/..)

# 协议模块头文件（供 IDE/打包感知；INTERFACE 库不编译）
target_sources(prism_test_common INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/common.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/socks5/socks5.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/http/http.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/trojan/trojan.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vless/vless.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vmess/kdf.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vmess/client.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vmess/server.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shadowsocks2022/codec.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shadowsocks2022/client.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shadowsocks2022/server.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/hysteria2/hysteria2.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/tuic/tuic.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shadowtls/shadowtls.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/trusttunnel/trusttunnel.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/reality/reality.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/anytls/anytls.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/restls/restls.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/mux/smux.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/mux/yamux.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/mux/h2mux.hpp
)

target_link_libraries(prism_test_common INTERFACE
        ${PROJECT_NAME}_static_library
        OpenSSL::Crypto
)
