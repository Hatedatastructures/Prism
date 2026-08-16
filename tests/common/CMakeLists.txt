# 协议组件库（纯 header-only，命名空间 psmtest）
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
        core/account/cow_map.hpp
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
        core/http2/session.hpp
        core/http2/stream.hpp
        core/http2/frame.hpp
        core/http2/codec.hpp
        core/http2/impl.hpp
        # ── core/http ──
        core/http/parser.hpp
        core/http/conn.hpp
        # ── core/http3 ──
        core/http3/auth.hpp
        core/http3/qpack.hpp
        core/http3/server.hpp
        core/http3/session.hpp
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
        core/runtime/per_worker_traffic.hpp
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
        core/protocol/target.hpp
        # ── core/quic ──
        core/quic/gateway_common.hpp
        # ── core/net ──
        core/net/dialer/dialer.hpp
        core/net/route/route.hpp
        core/net/outbound/outbound.hpp
        # ── core/net/dns ──
        core/net/dns/resolver.hpp
        core/net/udp_relay.hpp
        core/quic/stream_adapter.hpp
        # ── core/rate ──
        core/rate/token_bucket.hpp
        core/rate/counter.hpp
        # ── core/transport ──
        core/transport/algorithm.hpp
        core/transport/bench.hpp
        core/transport/connector.hpp
        core/transport/encrypted.hpp
        core/transport/memory_stream.hpp
        core/transport/pad.hpp
        core/transport/preview.hpp
        core/transport/reliable.hpp
        core/transport/snapshot.hpp
        core/transport/socket_stream.hpp
        core/transport/stream.hpp
        core/transport/unreliable.hpp
        core/transport/udp_transmission.hpp
        # ── mux ──
        mux/codec.hpp
        mux/session.hpp
        mux/types.hpp
        # ── mux/h2mux ──
        mux/h2mux/client.hpp
        mux/h2mux/codec.hpp
        mux/h2mux/h2mux.hpp
        mux/h2mux/server.hpp
        mux/h2mux/session.hpp
        mux/h2mux/types.hpp
        # ── mux/smux ──
        mux/smux/client.hpp
        mux/smux/codec.hpp
        mux/smux/server.hpp
        mux/smux/session.hpp
        mux/smux/smux.hpp
        mux/smux/types.hpp
        # ── mux/yamux ──
        mux/yamux/client.hpp
        mux/yamux/codec.hpp
        mux/yamux/server.hpp
        mux/yamux/session.hpp
        mux/yamux/types.hpp
        mux/yamux/yamux.hpp
        # ── proxy/hysteria2 ──
        proxy/hysteria2/codec.hpp
        proxy/hysteria2/conn.hpp
        proxy/hysteria2/dgram.hpp
        proxy/hysteria2/hysteria2.hpp
        proxy/hysteria2/types.hpp
        # ── proxy/shadowsocks2022 ──
        proxy/shadowsocks2022/codec.hpp
        proxy/shadowsocks2022/conn.hpp
        proxy/shadowsocks2022/dgram.hpp
        proxy/shadowsocks2022/shadowsocks2022.hpp
        proxy/shadowsocks2022/types.hpp
        # ── proxy/socks5 ──
        proxy/socks5/codec.hpp
        proxy/socks5/conn.hpp
        proxy/socks5/dgram.hpp
        proxy/socks5/socks5.hpp
        proxy/socks5/types.hpp
        # ── proxy/trojan ──
        proxy/trojan/codec.hpp
        proxy/trojan/conn.hpp
        proxy/trojan/dgram.hpp
        proxy/trojan/trojan.hpp
        proxy/trojan/types.hpp
        # ── proxy/tuic ──
        proxy/tuic/codec.hpp
        proxy/tuic/conn.hpp
        proxy/tuic/dgram.hpp
        proxy/tuic/tuic.hpp
        proxy/tuic/types.hpp
        # ── proxy/vless ──
        proxy/vless/codec.hpp
        proxy/vless/conn.hpp
        proxy/vless/dgram.hpp
        proxy/vless/types.hpp
        proxy/vless/vless.hpp
        # ── proxy/vmess ──
        proxy/vmess/codec.hpp
        proxy/vmess/conn.hpp
        proxy/vmess/dgram.hpp
        proxy/vmess/types.hpp
        proxy/vmess/vmess.hpp
        # ── stealth/anytls ──
        stealth/anytls/anytls.hpp
        stealth/anytls/codec.hpp
        stealth/anytls/conn.hpp
        stealth/anytls/types.hpp
        # ── stealth/gun ──
        stealth/gun/codec.hpp
        stealth/gun/conn.hpp
        stealth/gun/gun.hpp
        stealth/gun/types.hpp
        # ── stealth/native ──
        stealth/native/types.hpp
        stealth/native/conn.hpp
        stealth/native/native.hpp
        # ── stealth/reality ──
        stealth/reality/codec.hpp
        stealth/reality/conn.hpp
        stealth/reality/reality.hpp
        stealth/reality/types.hpp
        # ── stealth/restls ──
        stealth/restls/codec.hpp
        stealth/restls/conn.hpp
        stealth/restls/restls.hpp
        stealth/restls/types.hpp
        # ── stealth/shadowtls ──
        stealth/shadowtls/codec.hpp
        stealth/shadowtls/conn.hpp
        stealth/shadowtls/shadowtls.hpp
        stealth/shadowtls/types.hpp
        # ── stealth/trusttunnel ──
        stealth/trusttunnel/codec.hpp
        stealth/trusttunnel/conn.hpp
        stealth/trusttunnel/dgram.hpp
        stealth/trusttunnel/trusttunnel.hpp
        stealth/trusttunnel/types.hpp
        # ── stealth/ws ──
        stealth/ws/codec.hpp
        stealth/ws/conn.hpp
        stealth/ws/types.hpp
        stealth/ws/ws.hpp
        # ── stealth/xhttp ──
        stealth/xhttp/types.hpp
        stealth/xhttp/conn.hpp
        stealth/xhttp/xhttp.hpp
        # ── stealth/ech ──
        stealth/ech/types.hpp
        stealth/ech/keygen.hpp
        stealth/ech/scan.hpp
        stealth/ech/ech.hpp
        # ── top ──
        programmable_transport.hpp
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
