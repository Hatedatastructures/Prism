# integration 子模块：SS2022 互操作（独立可执行，非 gtest，成对运行）
AddPreviewTest(Task9FrontIntegration.cpp)
target_link_libraries(Task9FrontIntegration PRIVATE PreviewRuntime PreviewComposition PreviewProtocolQuic)

add_executable(InteropSs2022Client InteropSs2022Client.cpp)
target_compile_options(InteropSs2022Client PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Client PRIVATE PreviewProtocolShadowsocks2022 PreviewTestSupport BoostSystemHeaderOnly)
add_executable(InteropSs2022Server InteropSs2022Server.cpp)
target_compile_options(InteropSs2022Server PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Server PRIVATE PreviewProtocolShadowsocks2022 PreviewTestSupport BoostSystemHeaderOnly)

# L4 生产对拍：preview 客户端 → 生产 Prism 服务端（独立可执行，非 gtest）
add_executable(InteropPrismL4 InteropPrismL4.cpp)
target_compile_options(InteropPrismL4 PRIVATE -g1 -Os)
target_link_libraries(InteropPrismL4 PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolShadowsocks2022 PreviewProtocolSocks5 PreviewProtocolTrojan PreviewProtocolVless PreviewProtocolVmess PreviewTestSupport BoostSystemHeaderOnly)

# Trojan 外部互操作：Preview client/server 与独立 Go reference 双向运行。
add_executable(InteropTrojan InteropTrojan.cpp)
target_compile_options(InteropTrojan PRIVATE -g1 -Os)
target_link_libraries(InteropTrojan PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolTrojan BoostSystemHeaderOnly)

# VMess 外部互操作：独立 sing-vmess client 的 TCP/UDP → Preview server。
add_executable(InteropVmess InteropVmess.cpp)
target_compile_options(InteropVmess PRIVATE -g1 -Os)
target_link_libraries(InteropVmess PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolVmess BoostSystemHeaderOnly)

# VLESS 外部互操作：Preview client/server 与独立 Go reference 双向 TCP。
add_executable(InteropVless InteropVless.cpp)
target_compile_options(InteropVless PRIVATE -g1 -Os)
target_link_libraries(InteropVless PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolVless BoostSystemHeaderOnly)

# SOCKS5 外部互操作：Preview client/server 与独立 Go reference 双向 TCP。
add_executable(InteropSocks5 InteropSocks5.cpp)
target_compile_options(InteropSocks5 PRIVATE -g1 -Os)
target_link_libraries(InteropSocks5 PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolSocks5 BoostSystemHeaderOnly)

# HTTP/1.1 CONNECT 外部互操作：Preview client/server 与独立 Go reference 双向 TCP。
add_executable(InteropHttp InteropHttp.cpp)
target_compile_options(InteropHttp PRIVATE -g1 -Os)
target_link_libraries(InteropHttp PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolHttp BoostSystemHeaderOnly)

# 双模式真实单端口识别：外部 Go client -> Profile -> TcpListener -> handler -> echo。
add_executable(InteropRecognition InteropRecognition.cpp)
target_compile_options(InteropRecognition PRIVATE -g1 -Os)
target_link_libraries(InteropRecognition PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewRuntime
        PreviewComposition PreviewProtocolHttp PreviewProtocolSocks5 PreviewProtocolVless PreviewProtocolVmess
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# Native TLS 外部互操作：Preview carrier 与标准 Go TLS 双向 TCP。
add_executable(InteropNativeTls InteropNativeTls.cpp)
target_compile_options(InteropNativeTls PRIVATE -g1 -Os)
target_link_libraries(InteropNativeTls PRIVATE PreviewFoundation PreviewTransport PreviewProtocolNative PreviewNet
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# ShadowTLS v3 外部互操作：Preview relay server 与独立 Go/mihomo client。
add_executable(InteropShadowtls InteropShadowtls.cpp)
target_compile_options(InteropShadowtls PRIVATE -g1 -Os)
target_link_libraries(InteropShadowtls PRIVATE PreviewFoundation PreviewTransport PreviewNet
        PreviewProtocolShadowtls BoostSystemHeaderOnly)

# WebSocket RFC 6455 外部互操作：Preview 帧连接与独立 Go reference 双向 TCP。
add_executable(InteropWs InteropWs.cpp)
target_compile_options(InteropWs PRIVATE -g1 -Os)
target_link_libraries(InteropWs PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolWs
        BoostSystemHeaderOnly)

# AnyTLS 外部互操作：Preview 认证帧连接与独立 Go reference 双向 TCP。
add_executable(InteropAnytls InteropAnytls.cpp)
target_compile_options(InteropAnytls PRIVATE -g1 -Os)
target_link_libraries(InteropAnytls PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolAnytls
        BoostSystemHeaderOnly)

# gun-lite 外部互操作：Preview 连接与独立 Go wire reference 双向 TCP。
add_executable(InteropGun InteropGun.cpp)
target_compile_options(InteropGun PRIVATE -g1 -Os)
target_link_libraries(InteropGun PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolGun
        BoostSystemHeaderOnly)

# Standard gRPC/HTTP2 Gun endpoint external interop (h2c reference).
add_executable(InteropGunGrpc InteropGunGrpc.cpp)
target_compile_options(InteropGunGrpc PRIVATE -g1 -Os)
target_link_libraries(InteropGunGrpc PRIVATE PreviewFoundation PreviewTransport PreviewNet
        PreviewProtocolGun PreviewProtocolHttp2 BoostSystemHeaderOnly)

# XHTTP Stream-one 外部互操作：Go x/net/http2 client → Preview TLS/h2 server。
add_executable(InteropXhttp InteropXhttp.cpp)
target_compile_options(InteropXhttp PRIVATE -g1 -Os)
target_link_libraries(InteropXhttp PRIVATE PreviewFoundation PreviewTransport PreviewNet PreviewProtocolXhttp
        OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# TrustTunnel 标准 TLS/HTTP2 CONNECT 外部互操作：Go x/net/http2 双向。
add_executable(InteropTrusttunnel InteropTrusttunnel.cpp)
target_compile_options(InteropTrusttunnel PRIVATE -g1 -Os)
target_link_libraries(InteropTrusttunnel PRIVATE PreviewFoundation PreviewTransport PreviewProtocolTrusttunnel
        PreviewProtocolHttp2 OpenSSL::SSL OpenSSL::Crypto BoostSystemHeaderOnly)

# TUIC v5 外部互操作：Preview 原生 QUIC 服务端与独立 quic-go 客户端。
add_executable(InteropTuic InteropTuic.cpp)
target_compile_options(InteropTuic PRIVATE -g1 -Os)
target_link_libraries(InteropTuic PRIVATE PreviewFoundation PreviewTransport PreviewProtocolQuicNative PreviewProtocolTuic BoostSystemHeaderOnly)

# Hysteria2 外部互操作：Preview 原生 QUIC/HTTP3 与独立 sing-quic 客户端。
add_executable(InteropHysteria2 InteropHysteria2.cpp)
target_compile_options(InteropHysteria2 PRIVATE -g1 -Os)
target_link_libraries(InteropHysteria2 PRIVATE PreviewFoundation PreviewProtocolHttp3 PreviewProtocolQuicNative BoostSystemHeaderOnly)
add_executable(InteropHysteria2Client InteropHysteria2Client.cpp)
target_compile_options(InteropHysteria2Client PRIVATE -g1 -Os)
target_link_libraries(InteropHysteria2Client PRIVATE PreviewFoundation PreviewProtocolHttp3 PreviewProtocolQuicNative BoostSystemHeaderOnly)

# Hysteria2 HTTP/3 初始化失败路径回归；真实外部互操作由 InteropHysteria2 执行。
add_executable(Hysteria2InteropBlocker Hysteria2InteropBlocker.cpp)
target_compile_options(Hysteria2InteropBlocker PRIVATE -g1 -Os)
target_link_libraries(Hysteria2InteropBlocker PRIVATE PreviewProtocolHttp3 PreviewProtocolQuic)
