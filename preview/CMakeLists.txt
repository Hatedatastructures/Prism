# Preview Foundation（根级候选生产模块，纯 header-only）
#
# tests/common 中其余过渡 target 复用本文件定义的依赖检查函数。
# Foundation 自身只依赖外部库，不依赖任何其他 Preview target。

function(ConfigurePreviewTarget Target)
    if(NOT "${Target}" MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Preview/TestSupport target 必须使用 PascalCase：${Target}")
    endif()
    target_include_directories(${Target} INTERFACE ${CMAKE_SOURCE_DIR})
endfunction()

# Production tests must see only the production source/include trees and the
# dedicated tests root.  Keeping this separate from ConfigurePreviewTarget
# prevents a production test from resolving preview/... by accident.
function(ConfigureProductionTestSupportTarget Target)
    if(NOT "${Target}" MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Production test support target must use PascalCase: ${Target}")
    endif()
    target_include_directories(${Target} INTERFACE
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${boost_include_dir}
        ${Boost_INCLUDE_DIRS}
    )
endfunction()

function(AssertPreviewDependency Consumer Dependency)
    if("${Consumer}" MATCHES "^Preview" AND
       "${Dependency}" MATCHES "^(TestSupport|ProductionTestSupport)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：${Consumer} 不得依赖 ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewFoundation" AND
       "${Dependency}" MATCHES "^Preview")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewFoundation 不得依赖 ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewTransport" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewTransport -> ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewNet" AND
       NOT "${Dependency}" MATCHES "^Preview(Foundation|Transport)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewNet -> ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewRuntime" AND
       NOT "${Dependency}" MATCHES "^Preview(Net|Transport|Foundation)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewRuntime -> ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewProtocolsCommon" AND
       NOT "${Dependency}" MATCHES "^Preview(Net|Transport|Foundation)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewProtocolsCommon -> ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewComposition" AND
       NOT "${Dependency}" MATCHES "^Preview(Runtime|ProtocolsCommon|Protocol[A-Za-z0-9]+)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：PreviewComposition -> ${Dependency}")
    endif()

    if("${Consumer}" MATCHES "^PreviewProtocol" AND
       NOT "${Dependency}" MATCHES "^Preview(Net|Transport|Foundation|ProtocolsCommon|ProtocolHttp3Core|ProtocolHttp2|ProtocolQuic)$")
        message(FATAL_ERROR
            "非法 Preview 依赖：${Consumer} -> ${Dependency}")
    endif()
endfunction()

function(LinkPreviewTargets Consumer)
    foreach(Dependency IN LISTS ARGN)
        AssertPreviewDependency(${Consumer} ${Dependency})
    endforeach()
    target_link_libraries(${Consumer} INTERFACE ${ARGN})
endfunction()

add_library(PreviewFoundation INTERFACE)
ConfigurePreviewTarget(PreviewFoundation)
target_sources(PreviewFoundation INTERFACE
        Foundation/CodecTraits.hpp
        Foundation/Error.hpp
        Foundation/Authenticator.hpp
        Foundation/ByteSpan.hpp
        Foundation/FlatBuffer.hpp
        Foundation/Foundation.hpp
        Foundation/Parser.hpp
        Foundation/Role.hpp
        Foundation/SessionBase.hpp
        Foundation/Utility/TrafficSink.hpp
        Foundation/Utility/Account/Authenticator.hpp
        Foundation/Utility/Account/Directory.hpp
        Foundation/Utility/Coroutine/Registry.hpp
        Foundation/Utility/Crypto/Aead.hpp
        Foundation/Utility/Crypto/Base64.hpp
        Foundation/Utility/Crypto/Blake3.hpp
        Foundation/Utility/Crypto/Block.hpp
        Foundation/Utility/Crypto/Crypto.hpp
        Foundation/Utility/Crypto/Hkdf.hpp
        Foundation/Utility/Crypto/Sha224.hpp
        Foundation/Utility/Crypto/X25519.hpp
        Foundation/Utility/Diagnose/Context.hpp
        Foundation/Utility/Diagnose/Observability.hpp
        Foundation/Utility/Diagnose/Log.hpp
        Foundation/Exception/Deviant.hpp
        Foundation/Exception/Network.hpp
        Foundation/Exception/Protocol.hpp
        Foundation/Exception/Security.hpp
        Foundation/Fault/Code.hpp
        Foundation/Fault/Compatible.hpp
        Foundation/Fault/Handling.hpp
        Foundation/Memory/Container.hpp
        Foundation/Memory/CowMap.hpp
        Foundation/Memory/Pointer.hpp
        Foundation/Memory/Pool.hpp
        Foundation/Utility/Rate/TokenBucket.hpp
)
target_link_libraries(PreviewFoundation INTERFACE
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly
)

add_library(PreviewTransport INTERFACE)
ConfigurePreviewTarget(PreviewTransport)
target_sources(PreviewTransport INTERFACE
        Transport/Transmission.hpp
        Transport/Algorithm.hpp
        Transport/Connector.hpp
        Transport/Encrypted.hpp
        Transport/MemoryStream.hpp
        Transport/Pad.hpp
        Transport/Preview.hpp
        Transport/Reliable.hpp
        Transport/Snapshot.hpp
        Transport/Stream.hpp
        Transport/Unreliable.hpp
)
LinkPreviewTargets(PreviewTransport PreviewFoundation)
if(WIN32)
    target_link_libraries(PreviewTransport INTERFACE ws2_32 mswsock crypt32)
endif()

add_library(PreviewNet INTERFACE)
ConfigurePreviewTarget(PreviewNet)
target_sources(PreviewNet INTERFACE
        Net/Target.hpp
        Net/Dialer/Dialer.hpp
        Net/Route/Route.hpp
        Net/Outbound/Outbound.hpp
        Net/Dns/Config.hpp
        Net/Dns/Format.hpp
        Net/Dns/Types.hpp
        Net/Dns/Answer.hpp
        Net/Dns/Transport.hpp
        Net/Dns/ConnPool.hpp
        Net/Dns/Doh.hpp
        Net/Dns/Cache.hpp
        Net/Dns/Coalescer.hpp
        Net/Dns/Rules.hpp
        Net/Dns/Upstream.hpp
        Net/Dns/Resolver.hpp
        Net/Dns/Detail/ConfigOptions.hpp
        Net/Dns/Detail/Exchange.hpp
        Net/Dns/Detail/Maintenance.hpp
        Net/Dns/Detail/Fallback.hpp
        Net/UdpRelay.hpp
)
LinkPreviewTargets(PreviewNet PreviewTransport PreviewFoundation)

add_library(PreviewRuntime INTERFACE)
ConfigurePreviewTarget(PreviewRuntime)
target_sources(PreviewRuntime INTERFACE
        # Runtime middleware
        Runtime/Middleware/Context.hpp
        Runtime/Middleware/Pipeline.hpp
        Runtime/Middleware/Builtin/Auth.hpp
        Runtime/Middleware/Builtin/Dial.hpp
        Runtime/Middleware/Builtin/Mux.hpp
        Runtime/Middleware/Builtin/Pad.hpp
        Runtime/Middleware/Builtin/Relay.hpp
        Runtime/Middleware/Builtin/Throttle.hpp
        # Runtime recognition
        Runtime/Recognition/Protocol.hpp
        Runtime/Recognition/Probe.hpp
        Runtime/Recognition/ProbeDefense.hpp
        Runtime/Recognition/Recognition.hpp
        Runtime/Recognition/Route.hpp
        Runtime/Recognition/SchemeExecutor.hpp
        # Runtime session/front/resource and stable protocol contract
        Runtime/Session.hpp
        Runtime/Listener.hpp
        Runtime/SessionRegistry.hpp
        Runtime/Statistics.hpp
        Runtime/Contract/Handler.hpp
)
LinkPreviewTargets(PreviewRuntime PreviewNet PreviewTransport PreviewFoundation)

add_library(PreviewComposition INTERFACE)
ConfigurePreviewTarget(PreviewComposition)
target_sources(PreviewComposition INTERFACE
        # Composition adapters; protocol binding remains outside Runtime
        Composition/Adapters/Common.hpp
        Composition/Adapters/ProtocolAdapter.hpp
        Composition/Adapters/Socks5.hpp
        Composition/Adapters/Ss2022.hpp
        Composition/Adapters/Trojan.hpp
        Composition/Adapters/Vless.hpp
        Composition/Adapters/Vmess.hpp
        Composition/Api/ApiManager.hpp
        Composition/Settings/Json.hpp
        Composition/Settings/Loader.hpp
)
LinkPreviewTargets(PreviewComposition
        PreviewRuntime
)

add_library(PreviewProtocolsCommon INTERFACE)
ConfigurePreviewTarget(PreviewProtocolsCommon)
target_sources(PreviewProtocolsCommon INTERFACE
        Protocols/Common/Address.hpp
        Protocols/Common/Form.hpp
        Protocols/Common/Framing.hpp
        Protocols/Common/Mux.hpp
        Protocols/Common/Read.hpp
)

add_library(PreviewProtocolHttp2 INTERFACE)
ConfigurePreviewTarget(PreviewProtocolHttp2)
target_sources(PreviewProtocolHttp2 INTERFACE
        Protocols/Http2/Session.hpp
        Protocols/Http2/Stream.hpp
        Protocols/Http2/Frame.hpp
        Protocols/Http2/Codec.hpp
        Protocols/Http2/Impl.hpp
)

# HTTP/2 and Hysteria2 reuse the header-only QPACK/Huffman/authentication
# primitives without requiring the full nghttp3/ngtcp2 HTTP/3 stack.
add_library(PreviewProtocolHttp3Core INTERFACE)
ConfigurePreviewTarget(PreviewProtocolHttp3Core)
target_sources(PreviewProtocolHttp3Core INTERFACE
        Protocols/Http3/Auth.hpp
        Protocols/Http3/Detail/Varint.hpp
        Protocols/Http3/Huffman.hpp
        Protocols/Http3/StaticTable.hpp
        Protocols/Http3/DynamicTable.hpp
        Protocols/Http3/Decoder.hpp
        Protocols/Http3/Encoder.hpp
        Protocols/Http3/Qpack.hpp
)
LinkPreviewTargets(PreviewProtocolHttp3Core PreviewProtocolsCommon)

add_library(PreviewProtocolQuic INTERFACE)
ConfigurePreviewTarget(PreviewProtocolQuic)
target_sources(PreviewProtocolQuic INTERFACE
        Protocols/Quic/GatewayCommon.hpp
        Protocols/Quic/StreamAdapter.hpp
)

add_library(PreviewProtocolHttp INTERFACE)
ConfigurePreviewTarget(PreviewProtocolHttp)
target_sources(PreviewProtocolHttp INTERFACE
        Protocols/Http1/Parser.hpp
        Protocols/Http1/Conn.hpp
)

add_library(PreviewProtocolHttp3 INTERFACE)
ConfigurePreviewTarget(PreviewProtocolHttp3)
target_sources(PreviewProtocolHttp3 INTERFACE
        Protocols/Http3/Server.hpp
        Protocols/Http3/Session.hpp
)
LinkPreviewTargets(PreviewProtocolHttp3 PreviewProtocolHttp3Core)
target_include_directories(PreviewProtocolHttp3 INTERFACE
        ${nghttp3_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/crypto/includes
)
target_link_libraries(PreviewProtocolHttp3 INTERFACE
        OpenSSL::SSL
        OpenSSL::Crypto
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
        nghttp3_static
)

add_library(PreviewProtocolHysteria2 INTERFACE)
ConfigurePreviewTarget(PreviewProtocolHysteria2)
target_sources(PreviewProtocolHysteria2 INTERFACE
        Protocols/Hysteria2/Types.hpp
        Protocols/Hysteria2/Codec.hpp
        Protocols/Hysteria2/Conn.hpp
        Protocols/Hysteria2/Dgram.hpp
        Protocols/Hysteria2/Hysteria2.hpp
)

add_library(PreviewProtocolShadowsocks2022 INTERFACE)
ConfigurePreviewTarget(PreviewProtocolShadowsocks2022)
target_sources(PreviewProtocolShadowsocks2022 INTERFACE
        Protocols/Shadowsocks2022/Types.hpp
        Protocols/Shadowsocks2022/ChunkCodec.hpp
        Protocols/Shadowsocks2022/KeyDerivation.hpp
        Protocols/Shadowsocks2022/RequestCodec.hpp
        Protocols/Shadowsocks2022/ResponseCodec.hpp
        Protocols/Shadowsocks2022/Codec.hpp
        Protocols/Shadowsocks2022/Conn.hpp
        Protocols/Shadowsocks2022/Dgram.hpp
        Protocols/Shadowsocks2022/Shadowsocks2022.hpp
)

add_library(PreviewProtocolSocks5 INTERFACE)
ConfigurePreviewTarget(PreviewProtocolSocks5)
target_sources(PreviewProtocolSocks5 INTERFACE
        Protocols/Socks5/Types.hpp
        Protocols/Socks5/Codec.hpp
        Protocols/Socks5/Conn.hpp
        Protocols/Socks5/Dgram.hpp
        Protocols/Socks5/UdpAssoc.hpp
        Protocols/Socks5/Socks5.hpp
)

add_library(PreviewProtocolTrojan INTERFACE)
ConfigurePreviewTarget(PreviewProtocolTrojan)
target_sources(PreviewProtocolTrojan INTERFACE
        Protocols/Trojan/Types.hpp
        Protocols/Trojan/Codec.hpp
        Protocols/Trojan/Conn.hpp
        Protocols/Trojan/Dgram.hpp
        Protocols/Trojan/Trojan.hpp
)

add_library(PreviewProtocolTuic INTERFACE)
ConfigurePreviewTarget(PreviewProtocolTuic)
target_sources(PreviewProtocolTuic INTERFACE
        Protocols/Tuic/Types.hpp
        Protocols/Tuic/Codec.hpp
        Protocols/Tuic/Conn.hpp
        Protocols/Tuic/Dgram.hpp
        Protocols/Tuic/Tuic.hpp
)

add_library(PreviewProtocolVless INTERFACE)
ConfigurePreviewTarget(PreviewProtocolVless)
target_sources(PreviewProtocolVless INTERFACE
        Protocols/Vless/Types.hpp
        Protocols/Vless/Codec.hpp
        Protocols/Vless/Conn.hpp
        Protocols/Vless/Dgram.hpp
        Protocols/Vless/UdpTunnel.hpp
        Protocols/Vless/Vless.hpp
)

add_library(PreviewProtocolVmess INTERFACE)
ConfigurePreviewTarget(PreviewProtocolVmess)
target_sources(PreviewProtocolVmess INTERFACE
        Protocols/Vmess/Types.hpp
        Protocols/Vmess/Auth.hpp
        Protocols/Vmess/ChunkCodec.hpp
        Protocols/Vmess/RequestCodec.hpp
        Protocols/Vmess/ResponseCodec.hpp
        Protocols/Vmess/Codec.hpp
        Protocols/Vmess/Conn.hpp
        Protocols/Vmess/Dgram.hpp
        Protocols/Vmess/Vmess.hpp
)

add_library(PreviewProtocolMux INTERFACE)
ConfigurePreviewTarget(PreviewProtocolMux)
target_sources(PreviewProtocolMux INTERFACE
        Protocols/Mux/Types.hpp
        Protocols/Mux/Codec.hpp
        Protocols/Mux/StreamState.hpp
        Protocols/Mux/SessionReadLoop.hpp
        Protocols/Mux/SessionWriteLoop.hpp
        Protocols/Mux/Stream.hpp
        Protocols/Mux/Session.hpp
        Protocols/Mux/Client.hpp
        Protocols/Mux/Server.hpp
        Protocols/Mux/Smux/Types.hpp
        Protocols/Mux/Smux/Codec.hpp
        Protocols/Mux/Smux/Session.hpp
        Protocols/Mux/Smux/Client.hpp
        Protocols/Mux/Smux/Server.hpp
        Protocols/Mux/Smux/Smux.hpp
        Protocols/Mux/Yamux/Types.hpp
        Protocols/Mux/Yamux/Codec.hpp
        Protocols/Mux/Yamux/Session.hpp
        Protocols/Mux/Yamux/Client.hpp
        Protocols/Mux/Yamux/Server.hpp
        Protocols/Mux/Yamux/Yamux.hpp
        Protocols/Mux/H2Mux/Types.hpp
        Protocols/Mux/H2Mux/Codec.hpp
        Protocols/Mux/H2Mux/Session.hpp
        Protocols/Mux/H2Mux/Client.hpp
        Protocols/Mux/H2Mux/Server.hpp
        Protocols/Mux/H2Mux/H2Mux.hpp
)

add_library(PreviewProtocolAnytls INTERFACE)
ConfigurePreviewTarget(PreviewProtocolAnytls)
target_sources(PreviewProtocolAnytls INTERFACE
        Protocols/Anytls/Types.hpp
        Protocols/Anytls/Codec.hpp
        Protocols/Anytls/Conn.hpp
        Protocols/Anytls/Anytls.hpp
)

add_library(PreviewProtocolEch INTERFACE)
ConfigurePreviewTarget(PreviewProtocolEch)
target_sources(PreviewProtocolEch INTERFACE
        Protocols/Ech/Types.hpp
        Protocols/Ech/Keygen.hpp
        Protocols/Ech/Scan.hpp
        Protocols/Ech/Ech.hpp
)

add_library(PreviewProtocolGun INTERFACE)
ConfigurePreviewTarget(PreviewProtocolGun)
target_sources(PreviewProtocolGun INTERFACE
        Protocols/Gun/Types.hpp
        Protocols/Gun/Codec.hpp
        Protocols/Gun/Conn.hpp
        Protocols/Gun/Gun.hpp
)

add_library(PreviewProtocolNative INTERFACE)
ConfigurePreviewTarget(PreviewProtocolNative)
target_sources(PreviewProtocolNative INTERFACE
        Protocols/Native/Types.hpp
        Protocols/Native/Conn.hpp
        Protocols/Native/Native.hpp
)

add_library(PreviewProtocolReality INTERFACE)
ConfigurePreviewTarget(PreviewProtocolReality)
target_sources(PreviewProtocolReality INTERFACE
        Protocols/Reality/Types.hpp
        Protocols/Reality/Codec.hpp
        Protocols/Reality/Conn.hpp
        Protocols/Reality/Reality.hpp
)

add_library(PreviewProtocolRestls INTERFACE)
ConfigurePreviewTarget(PreviewProtocolRestls)
target_sources(PreviewProtocolRestls INTERFACE
        Protocols/Restls/Types.hpp
        Protocols/Restls/Codec.hpp
        Protocols/Restls/Conn.hpp
        Protocols/Restls/Restls.hpp
)

add_library(PreviewProtocolShadowtls INTERFACE)
ConfigurePreviewTarget(PreviewProtocolShadowtls)
target_sources(PreviewProtocolShadowtls INTERFACE
        Protocols/Shadowtls/Types.hpp
        Protocols/Shadowtls/Codec.hpp
        Protocols/Shadowtls/Conn.hpp
        Protocols/Shadowtls/Shadowtls.hpp
)

add_library(PreviewProtocolTrusttunnel INTERFACE)
ConfigurePreviewTarget(PreviewProtocolTrusttunnel)
target_sources(PreviewProtocolTrusttunnel INTERFACE
        Protocols/Trusttunnel/Types.hpp
        Protocols/Trusttunnel/Codec.hpp
        Protocols/Trusttunnel/Conn.hpp
        Protocols/Trusttunnel/Dgram.hpp
        Protocols/Trusttunnel/Trusttunnel.hpp
)

add_library(PreviewProtocolWs INTERFACE)
ConfigurePreviewTarget(PreviewProtocolWs)
target_sources(PreviewProtocolWs INTERFACE
        Protocols/Ws/Types.hpp
        Protocols/Ws/Codec.hpp
        Protocols/Ws/Conn.hpp
        Protocols/Ws/Ws.hpp
)

add_library(PreviewProtocolXhttp INTERFACE)
ConfigurePreviewTarget(PreviewProtocolXhttp)
target_sources(PreviewProtocolXhttp INTERFACE
        Protocols/Xhttp/Types.hpp
        Protocols/Xhttp/Conn.hpp
        Protocols/Xhttp/Xhttp.hpp
)

# Protocol dependencies are declared beside the Preview targets they compose.
# tests/common no longer owns Preview production headers; its CMake file is
# retained only as a compatibility subdirectory for downstream test layouts.
LinkPreviewTargets(PreviewProtocolsCommon PreviewTransport PreviewFoundation)

foreach(ProtocolTarget IN ITEMS
        PreviewProtocolHttp
        PreviewProtocolHttp3
        PreviewProtocolHttp2
        PreviewProtocolQuic
        PreviewProtocolHysteria2
        PreviewProtocolShadowsocks2022
        PreviewProtocolSocks5
        PreviewProtocolTrojan
        PreviewProtocolTuic
        PreviewProtocolVless
        PreviewProtocolVmess
        PreviewProtocolMux
        PreviewProtocolAnytls
        PreviewProtocolEch
        PreviewProtocolGun
        PreviewProtocolNative
        PreviewProtocolReality
        PreviewProtocolRestls
        PreviewProtocolShadowtls
        PreviewProtocolTrusttunnel
        PreviewProtocolWs
        PreviewProtocolXhttp)
    LinkPreviewTargets(${ProtocolTarget} PreviewProtocolsCommon)
endforeach()

LinkPreviewTargets(PreviewProtocolHttp2 PreviewProtocolsCommon PreviewProtocolHttp3Core)
LinkPreviewTargets(PreviewProtocolQuic PreviewProtocolsCommon)
LinkPreviewTargets(PreviewProtocolHysteria2 PreviewProtocolsCommon PreviewProtocolHttp3Core)
LinkPreviewTargets(PreviewProtocolXhttp PreviewProtocolHttp2)

LinkPreviewTargets(PreviewComposition
        PreviewProtocolsCommon
        PreviewProtocolSocks5
        PreviewProtocolVmess
        PreviewProtocolVless
        PreviewProtocolTrojan
        PreviewProtocolShadowsocks2022
)
