# hysteria2 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Hysteria2ClientServerPerf.cpp)
    target_link_libraries(Hysteria2ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
endif()
AddPrismTest(Hysteria2ConnErrorMatrix.cpp)
target_link_libraries(Hysteria2ConnErrorMatrix PRIVATE
    PrismFoundation
    PrismTransport
    PrismProtocolHysteria2
    PrismTestSupport)
AddPrismTest(Hysteria2ConnTerminalReadTest.cpp)
target_link_libraries(Hysteria2ConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolHysteria2)
AddPrismTest(Hysteria2ConnSession.cpp)
target_link_libraries(Hysteria2ConnSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Hysteria2DgramSession.cpp)
target_link_libraries(Hysteria2DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Hysteria2DatagramFragmentTest.cpp)
target_link_libraries(Hysteria2DatagramFragmentTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Hysteria2DatagramErrorTest.cpp)
target_link_libraries(Hysteria2DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Hysteria2CodecFuzzTest.cpp)
target_link_libraries(Hysteria2CodecFuzzTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Hysteria2CodecDeepTest.cpp)
target_link_libraries(Hysteria2CodecDeepTest PRIVATE PrismFoundation PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Hysteria2CodecRoundtripTest.cpp)
target_link_libraries(Hysteria2CodecRoundtripTest PRIVATE PrismFoundation PrismProtocolHysteria2)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Hysteria2StressTest.cpp)
 target_link_libraries(Hysteria2StressTest PRIVATE PrismTransport PrismProtocolHysteria2 PrismTestSupport)
endif()
# Hysteria2 HTTP/3 auth owner contract.
AddPrismTest(Hysteria2Http3AuthTest.cpp)
target_link_libraries(Hysteria2Http3AuthTest PRIVATE
    PrismAccount PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolShadowsocks2022
    PrismProtocolSocks5 PrismRuntime PrismTestSupport)
AddPrismTest(Hysteria2AdmissionTest.cpp)
target_link_libraries(Hysteria2AdmissionTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts PrismLifecycle PrismProtocolHttp PrismProtocolHysteria2
    PrismProtocolQuic PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTestSupport PrismTransport)
AddPrismTest(Hysteria2DatagramSessionTerminalTest.cpp)
target_link_libraries(Hysteria2DatagramSessionTerminalTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts
    PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolHttp3Core PrismProtocolQuic
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime PrismTransport)
AddPrismTest(Hysteria2StreamRequestTerminalTest.cpp)
target_link_libraries(Hysteria2StreamRequestTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismLifecycle
    PrismNet
    PrismProtocolHttp
    PrismProtocolHysteria2
    PrismProtocolQuic
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismRuntime
    PrismTestSupport
    PrismTransport
)
