# 多协议套接分别验证内存数据一致性、真实 TCP 完整性与吞吐对照。
if(PRISM_ENABLE_BENCHMARK)
    foreach(_case IN ITEMS CarrierMemoryBenchmark CarrierTcpIntegrityBenchmark CarrierTcpThroughputBenchmark)
        AddPreviewTest(${_case}.cpp)
        target_sources(${_case} PRIVATE CarrierBenchmarkWsFactory.cpp
            CarrierBenchmarkWsFactory.hpp CarrierBenchmarkTransportResult.hpp
            ../../protocols/Ws/WsFactorySupport.hpp)
        target_link_libraries(${_case} PRIVATE PreviewTransport PreviewProtocolAnytls
            PreviewProtocolGun PreviewProtocolReality PreviewProtocolRestls PreviewProtocolShadowtls
            PreviewProtocolSocks5 PreviewProtocolTrojan PreviewProtocolTrusttunnel PreviewProtocolVless
            PreviewProtocolWs)
        set_property(TARGET ${_case} PROPERTY PRISM_TEST_PURPOSE "CrossProtocolPerformance")
    endforeach()
endif()

# 同一 owner 的正式职责头与行为场景，复用既有 target。
if(TARGET CarrierMemoryBenchmark)
target_sources(CarrierMemoryBenchmark PRIVATE
    ../../integration/Layering/CarrierMemoryTrustTunnelHandshake.cpp
)
endif()
