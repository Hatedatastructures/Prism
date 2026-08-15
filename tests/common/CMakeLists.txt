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
        core/codec_traits.hpp
        core/transport/algorithm.hpp
        core/transport/bench.hpp
        core/transport/memory_stream.hpp
        core/transport/socket_stream.hpp
        core/transport/stream.hpp
        core/transport/transport_base.hpp
        # ── 主库底层工具（header-only 拷贝，命名空间 psm::） ──
        core/fault/code.hpp
        core/fault/compatible.hpp
        core/fault/handling.hpp
        core/exception/deviant.hpp
        core/exception/network.hpp
        core/exception/protocol.hpp
        core/exception/security.hpp
        core/foundation.hpp
        core/memory/container.hpp
        core/memory/pointer.hpp
        core/memory/pool.hpp
        core/crypto/aead.hpp
        core/crypto/base64.hpp
        core/crypto/blake3.hpp
        core/crypto/block.hpp
        core/crypto/crypto.hpp
        core/crypto/hkdf.hpp
        core/crypto/sha224.hpp
        core/crypto/x25519.hpp
        core/coroutine/registry.hpp
        core/rate/counter.hpp
        core/diagnose/context.hpp
        core/diagnose/log.hpp
        core/transport/transmission.hpp
        core/transport/reliable.hpp
        core/transport/unreliable.hpp
        core/transport/preview.hpp
        core/transport/pad.hpp
        core/transport/snapshot.hpp
        core/transport/encrypted.hpp
        core/transport/connector.hpp
        core/protocol/address.hpp
        core/protocol/form.hpp
        core/protocol/framing.hpp
        core/protocol/read.hpp
        core/protocol/mux.hpp
        core/protocol/target.hpp
        # ── HTTP/2、HTTP/3、QUIC 工具层 ──
        core/http2/session.hpp
        core/http2/stream.hpp
        core/http3/auth.hpp
        core/http3/qpack.hpp
        core/http3/session.hpp
        core/http3/server.hpp
        core/quic/stream_adapter.hpp
        core/quic/gateway_common.hpp
        # ── 中间件管线 ──
        core/middleware/context.hpp
        core/middleware/pipeline.hpp
        core/middleware/builtin/dial.hpp
        core/middleware/builtin/mux.hpp
        core/middleware/builtin/pad.hpp
        core/middleware/builtin/relay.hpp
        mux/codec.hpp
        mux/session.hpp
        mux/types.hpp
        mux/smux/smux.hpp
        mux/yamux/yamux.hpp
        mux/h2mux/h2mux.hpp
        proxy/vmess/vmess.hpp
        proxy/vless/vless.hpp
        proxy/trojan/trojan.hpp
        proxy/shadowsocks2022/shadowsocks2022.hpp
        proxy/socks5/socks5.hpp
        proxy/hysteria2/hysteria2.hpp
        proxy/tuic/tuic.hpp
        stealth/reality/reality.hpp
        stealth/shadowtls/shadowtls.hpp
        stealth/restls/restls.hpp
        stealth/anytls/anytls.hpp
        stealth/trusttunnel/trusttunnel.hpp
        stealth/ws/ws.hpp
        stealth/gun/gun.hpp
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
        proxy/vmess/types.hpp
        proxy/vmess/codec.hpp
        proxy/vmess/conn.hpp
        proxy/vmess/dgram.hpp
        proxy/vmess/vmess.hpp
        proxy/vless/types.hpp
        proxy/vless/codec.hpp
        proxy/vless/conn.hpp
        proxy/vless/dgram.hpp
        proxy/vless/vless.hpp
        proxy/trojan/types.hpp
        proxy/trojan/codec.hpp
        proxy/trojan/conn.hpp
        proxy/trojan/dgram.hpp
        proxy/trojan/trojan.hpp
        proxy/shadowsocks2022/types.hpp
        proxy/shadowsocks2022/codec.hpp
        proxy/shadowsocks2022/conn.hpp
        proxy/shadowsocks2022/dgram.hpp
        proxy/shadowsocks2022/shadowsocks2022.hpp
        proxy/socks5/types.hpp
        proxy/socks5/codec.hpp
        proxy/socks5/conn.hpp
        proxy/socks5/dgram.hpp
        proxy/socks5/socks5.hpp
        proxy/hysteria2/types.hpp
        proxy/hysteria2/codec.hpp
        proxy/hysteria2/conn.hpp
        proxy/hysteria2/dgram.hpp
        proxy/hysteria2/hysteria2.hpp
        proxy/tuic/types.hpp
        proxy/tuic/codec.hpp
        proxy/tuic/conn.hpp
        proxy/tuic/dgram.hpp
        proxy/tuic/tuic.hpp
        stealth/reality/types.hpp
        stealth/reality/codec.hpp
        stealth/reality/conn.hpp
        stealth/reality/reality.hpp
        stealth/shadowtls/types.hpp
        stealth/shadowtls/codec.hpp
        stealth/shadowtls/conn.hpp
        stealth/shadowtls/shadowtls.hpp
        stealth/restls/types.hpp
        stealth/restls/codec.hpp
        stealth/restls/conn.hpp
        stealth/restls/restls.hpp
        stealth/anytls/types.hpp
        stealth/anytls/codec.hpp
        stealth/anytls/conn.hpp
        stealth/anytls/anytls.hpp
        stealth/trusttunnel/types.hpp
        stealth/trusttunnel/codec.hpp
        stealth/trusttunnel/conn.hpp
        stealth/trusttunnel/dgram.hpp
        stealth/trusttunnel/trusttunnel.hpp
        stealth/ws/types.hpp
        stealth/ws/codec.hpp
        stealth/ws/conn.hpp
        stealth/ws/ws.hpp
        stealth/gun/types.hpp
        stealth/gun/codec.hpp
        stealth/gun/conn.hpp
        stealth/gun/gun.hpp
)

target_link_libraries(vmtest_common INTERFACE
        ${PROJECT_NAME}_static_library
        OpenSSL::Crypto
        blake3_c
        boost_system_header_only
)
