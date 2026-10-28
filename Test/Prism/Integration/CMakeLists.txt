# Integration 子模块：真实互操作（独立可执行，非 gtest，成对运行）
add_subdirectory(Go)

# Mihomo 矩阵用的本地 HTTP 目标服务器，不依赖旧版生产库。
add_executable(PrismMatrixFileServer Matrix/MatrixServer.cpp)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(PrismMatrixFileServer PRIVATE -g1 -Os)
endif()
target_link_libraries(PrismMatrixFileServer PRIVATE BoostSystemHeaderOnly)
if(WIN32)
    target_link_libraries(PrismMatrixFileServer PRIVATE ws2_32 mswsock)
endif()
set_target_properties(PrismMatrixFileServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Test/Prism/Integration")

AddPrismTest(Hysteria2/TcpEchoFramingTest.cpp)
target_sources(TcpEchoFramingTest PRIVATE Hysteria2/TcpEcho.hpp)
target_link_libraries(TcpEchoFramingTest PRIVATE PrismFoundation)
AddPrismTest(Application/FrontIntegration.cpp Task9FrontIntegration)
target_sources(Task9FrontIntegration PRIVATE ../../TestSupport/Prism/QuicFactory.hpp)
target_link_libraries(Task9FrontIntegration PRIVATE PrismRuntime PrismComposition PrismProtocolQuic PrismProtocolQuicNative
    PrismProtocolSocks5 PrismBoundary PrismFoundation PrismIngressContract PrismTestSupport)
AddPrismTest(Interop/TuicEchoTerminalTest.cpp)
target_sources(TuicEchoTerminalTest PRIVATE
    Interop/TuicLifecycle.hpp Interop/TuicTerminalIo.hpp)
target_link_libraries(TuicEchoTerminalTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolTuic PrismTestSupport
    BoostSystemHeaderOnly)

add_executable(InteropSs2022Client Interop/Ss2022Client.cpp)
target_compile_options(InteropSs2022Client PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Client PRIVATE PrismProtocolShadowsocks2022 PrismFoundation PrismTestSupport BoostSystemHeaderOnly)
add_executable(InteropProviderDatagrams Interop/ProviderDatagrams.cpp)
target_compile_options(InteropProviderDatagrams PRIVATE -g1 -Os)
target_link_libraries(InteropProviderDatagrams PRIVATE PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismFoundation BoostSystemHeaderOnly)
add_executable(InteropSs2022Server Interop/Ss2022Server.cpp)
target_compile_options(InteropSs2022Server PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Server PRIVATE PrismProtocolShadowsocks2022 PrismTestSupport BoostSystemHeaderOnly)

# L4 生产对拍：Prism 客户端 → 生产 Prism 服务端（独立可执行，非 gtest）
add_executable(InteropPrismL4 Interop/Layer4.cpp)
target_compile_options(InteropPrismL4 PRIVATE -g1 -Os)
target_link_libraries(InteropPrismL4 PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolsCommon PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport BoostSystemHeaderOnly)

# Trojan 外部互操作：client（普通 TCP/application-mux）与 server 分离。
add_executable(InteropTrojanClient Interop/TrojanClient.cpp)
target_compile_options(InteropTrojanClient PRIVATE -g1 -Os)
target_link_libraries(InteropTrojanClient PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolTrojan BoostSystemHeaderOnly)
add_executable(InteropTrojanMux Interop/TrojanMux.cpp)
target_compile_options(InteropTrojanMux PRIVATE -g1 -Os)
target_link_libraries(InteropTrojanMux PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolTrojan
        PrismProtocolHttp2 PrismProtocolMux BoostSystemHeaderOnly)
add_executable(InteropTrojanServer Interop/TrojanServer.cpp)
target_compile_options(InteropTrojanServer PRIVATE -g1 -Os)
target_link_libraries(InteropTrojanServer PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolTrojan BoostSystemHeaderOnly)

# VMess 外部互操作：普通 client、application-mux 与 server 分离。
add_executable(InteropVmessClient Interop/VmessClient.cpp)
target_compile_options(InteropVmessClient PRIVATE -g1 -Os)
target_link_libraries(InteropVmessClient PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolVmess BoostSystemHeaderOnly)
add_executable(InteropVmessMux Interop/VmessMux.cpp)
target_compile_options(InteropVmessMux PRIVATE -g1 -Os)
target_link_libraries(InteropVmessMux PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolVmess
        PrismProtocolHttp2 PrismProtocolMux BoostSystemHeaderOnly)
add_executable(InteropVmessServer Interop/VmessServer.cpp)
target_compile_options(InteropVmessServer PRIVATE -g1 -Os)
target_link_libraries(InteropVmessServer PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolVmess BoostSystemHeaderOnly)

# VLESS 外部互操作：client（TCP/UDP/XUDP）与 server 分离。
add_executable(InteropVlessClient Interop/VlessClient.cpp)
target_compile_options(InteropVlessClient PRIVATE -g1 -Os)
target_link_libraries(InteropVlessClient PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolVless BoostSystemHeaderOnly)
add_executable(InteropVlessServer Interop/VlessServer.cpp)
target_compile_options(InteropVlessServer PRIVATE -g1 -Os)
target_link_libraries(InteropVlessServer PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolVless BoostSystemHeaderOnly)

# SOCKS5 外部互操作：Prism client/server 与独立 Go reference 双向 TCP。
add_executable(InteropSocks5 Interop/Socks5.cpp)
target_compile_options(InteropSocks5 PRIVATE -g1 -Os)
target_link_libraries(InteropSocks5 PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolSocks5 BoostSystemHeaderOnly)

# HTTP/1.1 CONNECT 外部互操作：Prism client/server 与独立 Go reference 双向 TCP。
add_executable(InteropHttp Interop/Http.cpp)
target_compile_options(InteropHttp PRIVATE -g1 -Os)
target_link_libraries(InteropHttp PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolHttp BoostSystemHeaderOnly)

# 双模式真实单端口识别：外部 Go client -> Profile -> TcpListener -> handler -> echo。
add_executable(InteropRecognition Interop/Recognition.cpp)
target_compile_options(InteropRecognition PRIVATE -g1 -Os)
target_link_libraries(InteropRecognition PRIVATE PrismFoundation PrismTransport PrismNet PrismNetworkModel PrismRuntime
        PrismComposition PrismProtocolHttp PrismProtocolSocks5 PrismProtocolVless PrismProtocolVmess PrismTestSupport
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# Native TLS 外部互操作：Prism carrier 与标准 Go TLS 双向 TCP。
add_executable(InteropNativeTls Interop/NativeTls.cpp)
target_compile_options(InteropNativeTls PRIVATE -g1 -Os)
target_link_libraries(InteropNativeTls PRIVATE PrismFoundation PrismTransport PrismProtocolNative PrismNet
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# ShadowTLS v3 外部互操作：Prism relay server 与独立 Go/mihomo client。
add_executable(InteropShadowtls Interop/Shadowtls.cpp)
target_compile_options(InteropShadowtls PRIVATE -g1 -Os)
target_link_libraries(InteropShadowtls PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime
        PrismComposition PrismProtocolShadowtls BoostSystemHeaderOnly)

# WebSocket RFC 6455 外部互操作：Prism 帧连接与独立 Go reference 双向 TCP。
add_executable(InteropWs Interop/Ws.cpp)
target_sources(InteropWs PRIVATE ../Protocols/Ws/Admission/FactorySupport.hpp)
target_compile_options(InteropWs PRIVATE -g1 -Os)
target_link_libraries(InteropWs PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolWs
        BoostSystemHeaderOnly)

# AnyTLS 互操作：独立认证帧端点与正式 Application 的 Native TLS 多流客户端。
add_executable(InteropAnytls Interop/Anytls.cpp)
target_compile_options(InteropAnytls PRIVATE -g1 -Os)
target_link_libraries(InteropAnytls PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolAnytls
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# gun-lite 外部互操作：Prism 连接与独立 Go wire reference 双向 TCP。
add_executable(InteropGun Interop/Gun.cpp)
target_compile_options(InteropGun PRIVATE -g1 -Os)
target_link_libraries(InteropGun PRIVATE PrismFoundation PrismTransport PrismNet PrismProtocolGun
        BoostSystemHeaderOnly)

# Standard gRPC/HTTP2 Gun endpoint external interop (h2c reference).
add_executable(InteropGunGrpc Interop/GunGrpc.cpp)
target_include_directories(InteropGunGrpc PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_compile_options(InteropGunGrpc PRIVATE -g1 -Os)
target_link_libraries(InteropGunGrpc PRIVATE PrismFoundation PrismTransport PrismNet
        PrismProtocolGun PrismProtocolHttp2 BoostSystemHeaderOnly)

# XHTTP Stream-one 外部互操作：Go x/net/http2 client → Prism TLS/h2 server。
add_executable(InteropXhttp Interop/Xhttp.cpp)
target_compile_options(InteropXhttp PRIVATE -g1 -Os)
target_link_libraries(InteropXhttp PRIVATE PrismFoundation PrismTransport PrismNet PrismIoContracts PrismProtocolXhttp
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# TrustTunnel 标准 TLS/HTTP2 CONNECT 外部互操作：Go x/net/http2 双向。
add_executable(InteropTrusttunnel Interop/Trusttunnel.cpp)
target_compile_options(InteropTrusttunnel PRIVATE -g1 -Os)
target_link_libraries(InteropTrusttunnel PRIVATE PrismFoundation PrismTransport PrismProtocolTrusttunnel
        PrismProtocolHttp2 OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# TUIC v5 外部互操作：Prism 原生 QUIC 服务端与独立 quic-go 客户端。
# 此目标只验证 Native standalone harness，不覆盖 Prism Application ingress。
add_executable(InteropTuic Interop/Tuic.cpp Interop/TuicServer.cpp)
target_sources(InteropTuic PRIVATE Interop/TuicLifecycle.hpp Interop/TuicOptions.hpp
    Interop/TuicTerminalIo.hpp
    ../../TestSupport/Prism/QuicFactory.hpp)
target_compile_options(InteropTuic PRIVATE -g1 -Os)
target_link_libraries(InteropTuic PRIVATE PrismFoundation PrismTransport PrismNet PrismIngressContract
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic BoostSystemHeaderOnly)

if(PRISM_ENABLE_INTEROP AND WIN32)
    find_program(PrismTuicInteropPowerShell NAMES pwsh powershell REQUIRED)
    find_program(PrismTuicInteropGo NAMES go REQUIRED)
    set(PrismTuicGoClientBinary
        "${CMAKE_BINARY_DIR}/Test/Prism/Integration/Go/PrismTuicGoClient${CMAKE_EXECUTABLE_SUFFIX}")
    add_custom_command(
        OUTPUT "${PrismTuicGoClientBinary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/Test/Prism/Integration/Go"
        COMMAND "${PrismTuicInteropGo}" build -o "${PrismTuicGoClientBinary}" ./tuic
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/Go/tuic/main.go
            ${CMAKE_CURRENT_SOURCE_DIR}/Go/go.mod
            ${CMAKE_CURRENT_SOURCE_DIR}/Go/go.sum
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Go
        VERBATIM)
    add_custom_target(PrismTuicGoClient DEPENDS "${PrismTuicGoClientBinary}")
    add_dependencies(Prism PrismTuicGoClient)
    add_test(NAME PrismTuicApplicationIngress
        COMMAND ${PrismTuicInteropPowerShell} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/TuicApplication.ps1
                -RepoRoot ${CMAKE_SOURCE_DIR}
                -PrismExe $<TARGET_FILE:Prism>
                -TuicClient ${PrismTuicGoClientBinary}
                -Rounds 20
                -OutputDirectory ${CMAKE_BINARY_DIR}/interop-results/tuic-application)
    set_tests_properties(PrismTuicApplicationIngress PROPERTIES
        LABELS "interop;quic;tuic"
        RUN_SERIAL TRUE
        TIMEOUT 900)

    add_test(NAME PrismHysteria2ApplicationIngress
        COMMAND ${PrismTuicInteropPowerShell} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/Hysteria2Application.ps1
                -RepoRoot ${CMAKE_SOURCE_DIR}
                -PrismExe $<TARGET_FILE:Prism>
                -Go ${PrismTuicInteropGo}
                -RepeatCount 3
                -OutputDirectory ${CMAKE_BINARY_DIR}/interop-results/hysteria2-application)
    set_tests_properties(PrismHysteria2ApplicationIngress PROPERTIES
        LABELS "interop;application;quic;hysteria2"
        RUN_SERIAL TRUE
        TIMEOUT 900)
endif()

# Hysteria2 外部互操作：Prism 原生 QUIC/HTTP3 与独立 sing-quic 客户端。
add_executable(InteropHysteria2
    Interop/Hysteria2.cpp
    Interop/Hysteria2TcpServer.cpp
    Interop/Hysteria2UdpServer.cpp
    Interop/Hysteria2Support.cpp)
target_sources(InteropHysteria2 PRIVATE Interop/Hysteria2Support.hpp)
target_sources(InteropHysteria2 PRIVATE ../../TestSupport/Prism/QuicFactory.hpp)
target_sources(InteropHysteria2 PRIVATE Hysteria2/TcpEcho.hpp)
target_compile_options(InteropHysteria2 PRIVATE -g1 -Os)
target_link_libraries(InteropHysteria2 PRIVATE PrismFoundation PrismAccount PrismIngressContract PrismRuntime PrismProtocolHysteria2
    PrismProtocolHttp3 PrismProtocolQuic PrismProtocolQuicNative PrismTestSupport BoostSystemHeaderOnly)
add_executable(InteropHysteria2Client Interop/Hysteria2Client.cpp)
target_compile_options(InteropHysteria2Client PRIVATE -g1 -Os)
target_link_libraries(InteropHysteria2Client PRIVATE PrismFoundation PrismProtocolHysteria2 PrismProtocolHttp3
    PrismProtocolQuic PrismProtocolQuicNative OpenSSL::SSL BoostSystemHeaderOnly)

# Hysteria2 HTTP/3 初始化失败路径回归；真实外部互操作由 InteropHysteria2 执行。
add_executable(Hysteria2InteropBlocker Hysteria2/InteropBlocker.cpp)
target_compile_options(Hysteria2InteropBlocker PRIVATE -g1 -Os)
target_link_libraries(Hysteria2InteropBlocker PRIVATE PrismProtocolHttp3 PrismProtocolQuic)
add_test(NAME Hysteria2InteropBlocker COMMAND $<TARGET_FILE:Hysteria2InteropBlocker>)
set_tests_properties(Hysteria2InteropBlocker PROPERTIES
    LABELS "protocol;http3;quic;regression"
    TIMEOUT 30)
