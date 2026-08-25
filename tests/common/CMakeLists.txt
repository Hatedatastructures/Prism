# 协议组件库（纯 header-only，命名空间 preview）
# 单一 prism_ngx INTERFACE 库：core 基础设施 + 7 协议 + 7 伪装 + 3 mux
add_library(prism_ngx INTERFACE)

target_include_directories(prism_ngx INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_sources(prism_ngx INTERFACE
        # ── core ──
        Core/CodecTraits.hpp
        Core/Error.hpp
        Core/Authenticator.hpp
        Core/ByteSpan.hpp
        Core/Role.hpp
        Core/Transmission.hpp
        Core/FlatBuffer.hpp
        Core/Foundation.hpp
        Core/Parser.hpp
        Core/SessionBase.hpp
        # ── core/coroutine ──
        Core/Coroutine/Registry.hpp
        # ── core/crypto ──
        Core/Crypto/Aead.hpp
        # ── core/account ──
        Core/Memory/CowMap.hpp
        Core/Account/Directory.hpp
        Core/Account/Authenticator.hpp
        Core/Crypto/Base64.hpp
        Core/Crypto/Blake3.hpp
        Core/Crypto/Block.hpp
        Core/Crypto/Crypto.hpp
        Core/Crypto/Hkdf.hpp
        Core/Crypto/Sha224.hpp
        Core/Crypto/X25519.hpp
        # ── core/diagnose ──
        Core/Diagnose/Context.hpp
        Core/Diagnose/Observability.hpp
        Core/Diagnose/Log.hpp
        # ── core/exception ──
        Core/Exception/Deviant.hpp
        Core/Exception/Network.hpp
        Core/Exception/Protocol.hpp
        Core/Exception/Security.hpp
        # ── core/fault ──
        Core/Fault/Code.hpp
        Core/Fault/Compatible.hpp
        Core/Fault/Handling.hpp
        # ── protocols/http2 ──
        Protocols/Http2/Session.hpp
        Protocols/Http2/Stream.hpp
        Protocols/Http2/Frame.hpp
        Protocols/Http2/Codec.hpp
        Protocols/Http2/Impl.hpp
        # ── protocols/http1 ──
        Protocols/Http1/Parser.hpp
        Protocols/Http1/Conn.hpp
        # ── protocols/http3 ──
        Protocols/Http3/Auth.hpp
        Protocols/Http3/Qpack.hpp
        Protocols/Http3/Server.hpp
        Protocols/Http3/Session.hpp
        # ── core/memory ──
        Core/Memory/Container.hpp
        Core/Memory/Pointer.hpp
        Core/Memory/Pool.hpp
        # ── core/middleware ──
        Core/Middleware/Builtin/Dial.hpp
        Core/Middleware/Builtin/Mux.hpp
        Core/Middleware/Builtin/Pad.hpp
        Core/Middleware/Builtin/Relay.hpp
        Core/Middleware/Builtin/Throttle.hpp
        Core/Middleware/Builtin/Auth.hpp
        # ── core/recognition ──
        # ── core/runtime ──
        Core/Runtime/Session.hpp
        Core/Runtime/Listener.hpp
        Core/Runtime/Statistics.hpp
        # ── core/runtime/adapter ──
        Core/Runtime/Adapter/Common.hpp
        Core/Runtime/Adapter/Handler.hpp
        Core/Runtime/Adapter/ProtocolAdapter.hpp
        Core/Runtime/Adapter/Socks5.hpp
        Core/Runtime/Adapter/Ss2022.hpp
        Core/Runtime/Adapter/Trojan.hpp
        Core/Runtime/Adapter/Vless.hpp
        Core/Runtime/Adapter/Vmess.hpp
        Core/Api/ApiManager.hpp
        # ── core/settings ──
        Core/Settings/Json.hpp
        Core/Settings/Loader.hpp
        Core/Runtime/SessionRegistry.hpp
        Core/Recognition/Protocol.hpp
        Core/Recognition/Probe.hpp
        Core/Recognition/Route.hpp
        Core/Recognition/Recognition.hpp
        Core/Recognition/SchemeExecutor.hpp
        Core/Recognition/ProbeDefense.hpp
        Core/Middleware/Context.hpp
        Core/Middleware/Pipeline.hpp
        # ── core/protocol ──
        Core/Protocol/Address.hpp
        Core/Protocol/Form.hpp
        Core/Protocol/Framing.hpp
        Core/Protocol/Mux.hpp
        Core/Protocol/Read.hpp
        Core/Net/Target.hpp
        # ── protocols/quic ──
        Protocols/Quic/GatewayCommon.hpp
        # ── core/net ──
        Core/Net/Dialer/Dialer.hpp
        Core/Net/Route/Route.hpp
        Core/Net/Outbound/Outbound.hpp
        # ── core/net/dns ──
        Core/Net/Dns/Resolver.hpp
        Core/Net/UdpRelay.hpp
        Protocols/Quic/StreamAdapter.hpp
        # ── core/rate ──
        Core/Rate/TokenBucket.hpp
        # ── core/transport ──
        Core/Transport/Algorithm.hpp
        Bench/Bench.hpp
        Core/Transport/Connector.hpp
        Core/Transport/Encrypted.hpp
        Core/Transport/MemoryStream.hpp
        Core/Transport/Pad.hpp
        Core/Transport/Preview.hpp
        Core/Transport/Reliable.hpp
        Core/Transport/Snapshot.hpp
        Core/Transport/Stream.hpp
        Core/Transport/Unreliable.hpp
        # ── protocols/mux ──
        Protocols/Mux/Client.hpp
        Protocols/Mux/Codec.hpp
        Protocols/Mux/Server.hpp
        Protocols/Mux/Session.hpp
        Protocols/Mux/Stream.hpp
        Protocols/Mux/Types.hpp
        # ── protocols/mux/h2mux ──
        Protocols/Mux/H2Mux/Client.hpp
        Protocols/Mux/H2Mux/Codec.hpp
        Protocols/Mux/H2Mux/H2Mux.hpp
        Protocols/Mux/H2Mux/Server.hpp
        Protocols/Mux/H2Mux/Session.hpp
        Protocols/Mux/H2Mux/Types.hpp
        # ── protocols/mux/smux ──
        Protocols/Mux/Smux/Client.hpp
        Protocols/Mux/Smux/Codec.hpp
        Protocols/Mux/Smux/Server.hpp
        Protocols/Mux/Smux/Session.hpp
        Protocols/Mux/Smux/Smux.hpp
        Protocols/Mux/Smux/Types.hpp
        # ── protocols/mux/yamux ──
        Protocols/Mux/Yamux/Client.hpp
        Protocols/Mux/Yamux/Codec.hpp
        Protocols/Mux/Yamux/Server.hpp
        Protocols/Mux/Yamux/Session.hpp
        Protocols/Mux/Yamux/Types.hpp
        Protocols/Mux/Yamux/Yamux.hpp
        # ── protocols/hysteria2 ──
        Protocols/Hysteria2/Codec.hpp
        Protocols/Hysteria2/Conn.hpp
        Protocols/Hysteria2/Dgram.hpp
        Protocols/Hysteria2/Hysteria2.hpp
        Protocols/Hysteria2/Types.hpp
        # ── protocols/shadowsocks2022 ──
        Protocols/Shadowsocks2022/Codec.hpp
        Protocols/Shadowsocks2022/Conn.hpp
        Protocols/Shadowsocks2022/Dgram.hpp
        Protocols/Shadowsocks2022/Shadowsocks2022.hpp
        Protocols/Shadowsocks2022/Types.hpp
        # ── protocols/socks5 ──
        Protocols/Socks5/Codec.hpp
        Protocols/Socks5/Conn.hpp
        Protocols/Socks5/Dgram.hpp
        Protocols/Socks5/Socks5.hpp
        Protocols/Socks5/Types.hpp
        Protocols/Socks5/UdpAssoc.hpp
        # ── protocols/trojan ──
        Protocols/Trojan/Codec.hpp
        Protocols/Trojan/Conn.hpp
        Protocols/Trojan/Dgram.hpp
        Protocols/Trojan/Trojan.hpp
        Protocols/Trojan/Types.hpp
        # ── protocols/tuic ──
        Protocols/Tuic/Codec.hpp
        Protocols/Tuic/Conn.hpp
        Protocols/Tuic/Dgram.hpp
        Protocols/Tuic/Tuic.hpp
        Protocols/Tuic/Types.hpp
        # ── protocols/vless ──
        Protocols/Vless/Codec.hpp
        Protocols/Vless/Conn.hpp
        Protocols/Vless/Dgram.hpp
        Protocols/Vless/Types.hpp
        Protocols/Vless/Vless.hpp
        Protocols/Vless/UdpTunnel.hpp
        # ── protocols/vmess ──
        Protocols/Vmess/Codec.hpp
        Protocols/Vmess/Conn.hpp
        Protocols/Vmess/Dgram.hpp
        Protocols/Vmess/Types.hpp
        Protocols/Vmess/Vmess.hpp
        # ── protocols/anytls ──
        Protocols/Anytls/Anytls.hpp
        Protocols/Anytls/Codec.hpp
        Protocols/Anytls/Conn.hpp
        Protocols/Anytls/Types.hpp
        # ── protocols/gun ──
        Protocols/Gun/Codec.hpp
        Protocols/Gun/Conn.hpp
        Protocols/Gun/Gun.hpp
        Protocols/Gun/Types.hpp
        # ── protocols/native ──
        Protocols/Native/Types.hpp
        Protocols/Native/Conn.hpp
        Protocols/Native/Native.hpp
        # ── protocols/reality ──
        Protocols/Reality/Codec.hpp
        Protocols/Reality/Conn.hpp
        Protocols/Reality/Reality.hpp
        Protocols/Reality/Types.hpp
        # ── protocols/restls ──
        Protocols/Restls/Codec.hpp
        Protocols/Restls/Conn.hpp
        Protocols/Restls/Restls.hpp
        Protocols/Restls/Types.hpp
        # ── protocols/shadowtls ──
        Protocols/Shadowtls/Codec.hpp
        Protocols/Shadowtls/Conn.hpp
        Protocols/Shadowtls/Shadowtls.hpp
        Protocols/Shadowtls/Types.hpp
        # ── protocols/trusttunnel ──
        Protocols/Trusttunnel/Codec.hpp
        Protocols/Trusttunnel/Conn.hpp
        Protocols/Trusttunnel/Dgram.hpp
        Protocols/Trusttunnel/Trusttunnel.hpp
        Protocols/Trusttunnel/Types.hpp
        # ── protocols/ws ──
        Protocols/Ws/Codec.hpp
        Protocols/Ws/Conn.hpp
        Protocols/Ws/Types.hpp
        Protocols/Ws/Ws.hpp
        # ── protocols/xhttp ──
        Protocols/Xhttp/Types.hpp
        Protocols/Xhttp/Conn.hpp
        Protocols/Xhttp/Xhttp.hpp
        # ── protocols/ech ──
        Protocols/Ech/Types.hpp
        Protocols/Ech/Keygen.hpp
        Protocols/Ech/Scan.hpp
        Protocols/Ech/Ech.hpp
        # ── top ──
        TestRunner.hpp
        MockTransport.hpp
        MockTlsServer.hpp
        ProgrammableTransport.hpp
        RuntimeTestHelpers.hpp
        # ── stress ──
        Stress/StressHelper.hpp
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
