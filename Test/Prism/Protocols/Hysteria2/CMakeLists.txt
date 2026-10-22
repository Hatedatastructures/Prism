# hysteria2 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/Hysteria2ClientServerPerf.cpp)
    target_link_libraries(Hysteria2ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
endif()
AddPrismTest(Connection/Hysteria2ConnErrorMatrix.cpp)
target_link_libraries(Hysteria2ConnErrorMatrix PRIVATE
    PrismFoundation
    PrismTransport
    PrismProtocolHysteria2
    PrismTestSupport)
AddPrismTest(Connection/Hysteria2ConnEndTest.cpp)
target_link_libraries(Hysteria2ConnEndTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolHysteria2)
AddPrismTest(Connection/Hysteria2ConnSession.cpp)
target_link_libraries(Hysteria2ConnSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Datagram/Hysteria2DgramSession.cpp)
target_link_libraries(Hysteria2DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Datagram/Hysteria2FragmentTest.cpp)
target_link_libraries(Hysteria2FragmentTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Datagram/Hysteria2DatagramErrorTest.cpp)
target_link_libraries(Hysteria2DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/Hysteria2CodecFuzzTest.cpp)
target_link_libraries(Hysteria2CodecFuzzTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Codec/Hysteria2CodecDeepTest.cpp)
target_link_libraries(Hysteria2CodecDeepTest PRIVATE PrismFoundation PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/Hysteria2RoundtripTest.cpp)
target_link_libraries(Hysteria2RoundtripTest PRIVATE PrismFoundation PrismProtocolHysteria2)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/Hysteria2StressTest.cpp)
 target_link_libraries(Hysteria2StressTest PRIVATE PrismTransport PrismProtocolHysteria2 PrismTestSupport)
endif()
# Hysteria2 HTTP/3 auth owner contract.
AddPrismTest(Admission/Hysteria2Http3AuthTest.cpp)
target_link_libraries(Hysteria2Http3AuthTest PRIVATE
    PrismAccount PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolShadowsocks2022
    PrismProtocolSocks5 PrismRuntime PrismTestSupport)
AddPrismTest(Admission/Hysteria2AdmissionTest.cpp)
target_link_libraries(Hysteria2AdmissionTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts PrismLifecycle PrismProtocolHttp PrismProtocolHysteria2
    PrismProtocolQuic PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTestSupport PrismTransport)
AddPrismTest(Datagram/Hysteria2DgramEndTest.cpp)
target_link_libraries(Hysteria2DgramEndTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts
    PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolHttp3Core PrismProtocolQuic
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime PrismTransport)
AddPrismTest(Connection/Hysteria2RequestEndTest.cpp)
target_link_libraries(Hysteria2RequestEndTest PRIVATE
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
