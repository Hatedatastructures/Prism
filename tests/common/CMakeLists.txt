# 协议组件库（纯 header-only，命名空间 preview）
# 单一 prism_ngx INTERFACE 库：core 基础设施 + 7 协议 + 7 伪装 + 3 mux
add_library(prism_ngx INTERFACE)

target_include_directories(prism_ngx INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_sources(prism_ngx INTERFACE
        # ── core ──
        core/codec_traits.hpp
        core/error.hpp
        core/authenticator.hpp
        core/byte_span.hpp
        core/role.hpp
        core/transmission.hpp
        core/flat_buffer.hpp
        core/foundation.hpp
        core/parser.hpp
        core/session_base.hpp
        # ── core/coroutine ──
        core/coroutine/registry.hpp
        # ── core/crypto ──
        core/crypto/aead.hpp
        # ── core/account ──
        core/memory/cow_map.hpp
        core/account/directory.hpp
        core/account/authenticator.hpp
        core/crypto/base64.hpp
        core/crypto/blake3.hpp
        core/crypto/block.hpp
        core/crypto/crypto.hpp
        core/crypto/hkdf.hpp
        core/crypto/sha224.hpp
        core/crypto/x25519.hpp
        # ── core/diagnose ──
        core/diagnose/context.hpp
        core/diagnose/observability.hpp
        core/diagnose/log.hpp
        # ── core/exception ──
        core/exception/deviant.hpp
        core/exception/network.hpp
        core/exception/protocol.hpp
        core/exception/security.hpp
        # ── core/fault ──
        core/fault/code.hpp
        core/fault/compatible.hpp
        core/fault/handling.hpp
        # ── core/http2 ──
        protocols/http2/session.hpp
        protocols/http2/stream.hpp
        protocols/http2/frame.hpp
        protocols/http2/codec.hpp
        protocols/http2/impl.hpp
        # ── core/http ──
        protocols/http1/parser.hpp
        protocols/http1/conn.hpp
        # ── core/http3 ──
        protocols/http3/auth.hpp
        protocols/http3/qpack.hpp
        protocols/http3/server.hpp
        protocols/http3/session.hpp
        # ── core/memory ──
        core/memory/container.hpp
        core/memory/pointer.hpp
        core/memory/pool.hpp
        # ── core/middleware ──
        core/middleware/builtin/dial.hpp
        core/middleware/builtin/mux.hpp
        core/middleware/builtin/pad.hpp
        core/middleware/builtin/relay.hpp
        core/middleware/builtin/throttle.hpp
        core/middleware/builtin/auth.hpp
        # ── core/recognition ──
        # ── core/runtime ──
        core/runtime/session.hpp
        core/runtime/listener.hpp
        core/runtime/statistics.hpp
        core/runtime/statistics.hpp
        core/api/api_manager.hpp
        # ── core/settings ──
        core/settings/json.hpp
        core/settings/loader.hpp
        core/runtime/session_registry.hpp
        core/recognition/protocol.hpp
        core/recognition/probe.hpp
        core/recognition/route.hpp
        core/recognition/recognition.hpp
        core/middleware/context.hpp
        core/middleware/pipeline.hpp
        # ── core/protocol ──
        core/protocol/address.hpp
        core/protocol/form.hpp
        core/protocol/framing.hpp
        core/protocol/mux.hpp
        core/protocol/read.hpp
        core/net/target.hpp
        # ── core/quic ──
        protocols/quic/gateway_common.hpp
        # ── core/net ──
        core/net/dialer/dialer.hpp
        core/net/route/route.hpp
        core/net/outbound/outbound.hpp
        # ── core/net/dns ──
        core/net/dns/resolver.hpp
        core/net/udp_relay.hpp
        protocols/quic/stream_adapter.hpp
        # ── core/rate ──
        core/rate/token_bucket.hpp
        core/recognition/probe_defense.hpp
        # ── core/transport ──
        core/transport/algorithm.hpp
        bench/bench.hpp
        core/transport/connector.hpp
        core/transport/encrypted.hpp
        core/transport/memory_stream.hpp
        core/transport/pad.hpp
        core/transport/preview.hpp
        core/transport/reliable.hpp
        core/transport/snapshot.hpp
        core/transport/reliable.hpp
        core/transport/stream.hpp
        core/transport/unreliable.hpp
        core/transport/unreliable.hpp
        # ── mux ──
        protocols/mux/client.hpp
        protocols/mux/codec.hpp
        protocols/mux/server.hpp
        protocols/mux/session.hpp
        protocols/mux/stream.hpp
        protocols/mux/types.hpp
        # ── mux/h2mux ──
        protocols/mux/h2mux/client.hpp
        protocols/mux/h2mux/codec.hpp
        protocols/mux/h2mux/h2mux.hpp
        protocols/mux/h2mux/server.hpp
        protocols/mux/h2mux/session.hpp
        protocols/mux/h2mux/types.hpp
        # ── mux/smux ──
        protocols/mux/smux/client.hpp
        protocols/mux/smux/codec.hpp
        protocols/mux/smux/server.hpp
        protocols/mux/smux/session.hpp
        protocols/mux/smux/smux.hpp
        protocols/mux/smux/types.hpp
        # ── mux/yamux ──
        protocols/mux/yamux/client.hpp
        protocols/mux/yamux/codec.hpp
        protocols/mux/yamux/server.hpp
        protocols/mux/yamux/session.hpp
        protocols/mux/yamux/types.hpp
        protocols/mux/yamux/yamux.hpp
        # ── proxy/hysteria2 ──
        protocols/hysteria2/codec.hpp
        protocols/hysteria2/conn.hpp
        protocols/hysteria2/dgram.hpp
        protocols/hysteria2/hysteria2.hpp
        protocols/hysteria2/types.hpp
        # ── proxy/shadowsocks2022 ──
        protocols/shadowsocks2022/codec.hpp
        protocols/shadowsocks2022/conn.hpp
        protocols/shadowsocks2022/dgram.hpp
        protocols/shadowsocks2022/shadowsocks2022.hpp
        protocols/shadowsocks2022/types.hpp
        # ── proxy/socks5 ──
        protocols/socks5/codec.hpp
        protocols/socks5/conn.hpp
        protocols/socks5/dgram.hpp
        protocols/socks5/socks5.hpp
        protocols/socks5/types.hpp
        # ── proxy/trojan ──
        protocols/trojan/codec.hpp
        protocols/trojan/conn.hpp
        protocols/trojan/dgram.hpp
        protocols/trojan/trojan.hpp
        protocols/trojan/types.hpp
        # ── proxy/tuic ──
        protocols/tuic/codec.hpp
        protocols/tuic/conn.hpp
        protocols/tuic/dgram.hpp
        protocols/tuic/tuic.hpp
        protocols/tuic/types.hpp
        # ── proxy/vless ──
        protocols/vless/codec.hpp
        protocols/vless/conn.hpp
        protocols/vless/dgram.hpp
        protocols/vless/types.hpp
        protocols/vless/vless.hpp
        # ── proxy/vmess ──
        protocols/vmess/codec.hpp
        protocols/vmess/conn.hpp
        protocols/vmess/dgram.hpp
        protocols/vmess/types.hpp
        protocols/vmess/vmess.hpp
        # ── stealth/anytls ──
        protocols/anytls/anytls.hpp
        protocols/anytls/codec.hpp
        protocols/anytls/conn.hpp
        protocols/anytls/types.hpp
        # ── stealth/gun ──
        protocols/gun/codec.hpp
        protocols/gun/conn.hpp
        protocols/gun/gun.hpp
        protocols/gun/types.hpp
        # ── stealth/native ──
        protocols/native/types.hpp
        protocols/native/conn.hpp
        protocols/native/native.hpp
        # ── stealth/reality ──
        protocols/reality/codec.hpp
        protocols/reality/conn.hpp
        protocols/reality/reality.hpp
        protocols/reality/types.hpp
        # ── stealth/restls ──
        protocols/restls/codec.hpp
        protocols/restls/conn.hpp
        protocols/restls/restls.hpp
        protocols/restls/types.hpp
        # ── stealth/shadowtls ──
        protocols/shadowtls/codec.hpp
        protocols/shadowtls/conn.hpp
        protocols/shadowtls/shadowtls.hpp
        protocols/shadowtls/types.hpp
        # ── stealth/trusttunnel ──
        protocols/trusttunnel/codec.hpp
        protocols/trusttunnel/conn.hpp
        protocols/trusttunnel/dgram.hpp
        protocols/trusttunnel/trusttunnel.hpp
        protocols/trusttunnel/types.hpp
        # ── stealth/ws ──
        protocols/ws/codec.hpp
        protocols/ws/conn.hpp
        protocols/ws/types.hpp
        protocols/ws/ws.hpp
        # ── stealth/xhttp ──
        protocols/xhttp/types.hpp
        protocols/xhttp/conn.hpp
        protocols/xhttp/xhttp.hpp
        # ── stealth/ech ──
        protocols/ech/types.hpp
        protocols/ech/keygen.hpp
        protocols/ech/scan.hpp
        protocols/ech/ech.hpp
        # ── top ──
        TestRunner.hpp
        MockTransport.hpp
        MockTlsServer.hpp
        programmable_transport.hpp
        # ── stress ──
        stress/stress_helper.hpp
)

target_link_libraries(prism_ngx INTERFACE
        ${PROJECT_NAME}_static_library
        OpenSSL::Crypto
        blake3_c
        boost_system_header_only
)

# 兼容别名（旧链接结构保留，均指向 prism_ngx）
add_library(prism_test_common INTERFACE)
target_link_libraries(prism_test_common INTERFACE prism_ngx)

add_library(vmtest_common INTERFACE)
target_link_libraries(vmtest_common INTERFACE prism_ngx)
