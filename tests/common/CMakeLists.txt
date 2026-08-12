# 协议组件库（纯 header-only，命名空间 psmtest）
# 每个协议：types/codec/kdf/chunk/handshake/client/server（扁平结构，无子目录）
# 用法：#include <common/<proto>/<proto>.hpp>，链接 vmtest_common（INTERFACE）

# --- 兼容库壳（保留链接结构） ---
add_library(prism_test_common INTERFACE)

target_include_directories(prism_test_common INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_sources(prism_test_common INTERFACE
        core/error.hpp
        core/flat_buffer.hpp
        core/parser.hpp
        core/protocol_base.hpp
        core/session_base.hpp
        core/transport/algorithm.hpp
        core/transport/bench.hpp
        core/transport/memory_stream.hpp
        core/transport/socket_stream.hpp
        core/transport/stream.hpp
        core/transport/transport_base.hpp
        mux/codec.hpp
        mux/session.hpp
        mux/types.hpp
        mux/smux/smux.hpp
        mux/yamux/yamux.hpp
        mux/h2mux/h2mux.hpp
        vmess/vmess.hpp
        vless/vless.hpp
        trojan/trojan.hpp
        shadowsocks2022/shadowsocks2022.hpp
        socks5/socks5.hpp
        hysteria2/hysteria2.hpp
        tuic/tuic.hpp
        reality/reality.hpp
        shadowtls/shadowtls.hpp
        restls/restls.hpp
        anytls/anytls.hpp
        trusttunnel/trusttunnel.hpp
        ws/ws.hpp
        gun/gun.hpp
)

target_link_libraries(prism_test_common INTERFACE
        ${PROJECT_NAME}_static_library
        OpenSSL::Crypto
        blake3_c
)

# --- 生产级协议库（header-only，命名空间 psmtest） ---
# 扁平结构：types/codec/kdf/chunk/session/client/server 直接位于协议目录
add_library(vmtest_common INTERFACE)

target_include_directories(vmtest_common INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_sources(vmtest_common INTERFACE
        core/error.hpp
        core/flat_buffer.hpp
        core/parser.hpp
        core/protocol_base.hpp
        core/session_base.hpp
        core/transport/algorithm.hpp
        core/transport/bench.hpp
        core/transport/memory_stream.hpp
        core/transport/socket_stream.hpp
        core/transport/stream.hpp
        core/transport/transport_base.hpp
        mux/codec.hpp
        mux/session.hpp
        mux/types.hpp
        mux/smux/types.hpp
        mux/smux/codec.hpp
        mux/smux/session.hpp
        mux/smux/client.hpp
        mux/smux/server.hpp
        mux/smux/smux.hpp
        mux/yamux/types.hpp
        mux/yamux/codec.hpp
        mux/yamux/session.hpp
        mux/yamux/client.hpp
        mux/yamux/server.hpp
        mux/yamux/yamux.hpp
        mux/h2mux/types.hpp
        mux/h2mux/codec.hpp
        mux/h2mux/session.hpp
        mux/h2mux/client.hpp
        mux/h2mux/server.hpp
        mux/h2mux/h2mux.hpp
        vmess/types.hpp
        vmess/codec.hpp
        vmess/conn.hpp
        vmess/dgram.hpp
        vmess/vmess.hpp
        vless/types.hpp
        vless/codec.hpp
        vless/conn.hpp
        vless/dgram.hpp
        vless/vless.hpp
        trojan/types.hpp
        trojan/codec.hpp
        trojan/conn.hpp
        trojan/dgram.hpp
        trojan/trojan.hpp
        shadowsocks2022/types.hpp
        shadowsocks2022/codec.hpp
        shadowsocks2022/conn.hpp
        shadowsocks2022/dgram.hpp
        shadowsocks2022/shadowsocks2022.hpp
        socks5/types.hpp
        socks5/codec.hpp
        socks5/conn.hpp
        socks5/dgram.hpp
        socks5/socks5.hpp
        hysteria2/types.hpp
        hysteria2/codec.hpp
        hysteria2/conn.hpp
        hysteria2/dgram.hpp
        hysteria2/hysteria2.hpp
        tuic/types.hpp
        tuic/codec.hpp
        tuic/conn.hpp
        tuic/dgram.hpp
        tuic/tuic.hpp
        reality/types.hpp
        reality/codec.hpp
        reality/conn.hpp
        reality/reality.hpp
        shadowtls/types.hpp
        shadowtls/codec.hpp
        shadowtls/conn.hpp
        shadowtls/shadowtls.hpp
        restls/types.hpp
        restls/codec.hpp
        restls/conn.hpp
        restls/restls.hpp
        anytls/types.hpp
        anytls/codec.hpp
        anytls/conn.hpp
        anytls/anytls.hpp
        trusttunnel/types.hpp
        trusttunnel/codec.hpp
        trusttunnel/conn.hpp
        trusttunnel/dgram.hpp
        trusttunnel/trusttunnel.hpp
        ws/types.hpp
        ws/codec.hpp
        ws/conn.hpp
        ws/ws.hpp
        gun/types.hpp
        gun/codec.hpp
        gun/conn.hpp
        gun/gun.hpp
)

target_link_libraries(vmtest_common INTERFACE
        ${PROJECT_NAME}_static_library
        OpenSSL::Crypto
        blake3_c
        boost_system_header_only
)
