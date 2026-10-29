# hysteria2 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp Hysteria2ClientServerPerf)
    target_link_libraries(Hysteria2ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
endif()
AddPrismTest(Connection/ErrorMatrix.cpp Hysteria2ConnErrorMatrix)
target_link_libraries(Hysteria2ConnErrorMatrix PRIVATE
    PrismFoundation
    PrismTransport
    PrismProtocolHysteria2
    PrismTestSupport)
AddPrismTest(Connection/EndTest.cpp Hysteria2ConnEndTest)
target_link_libraries(Hysteria2ConnEndTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolHysteria2)
AddPrismTest(Connection/Session.cpp Hysteria2ConnSession)
target_link_libraries(Hysteria2ConnSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Datagram/Session.cpp Hysteria2DgramSession)
target_link_libraries(Hysteria2DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismProtocolQuic PrismTestSupport)
AddPrismTest(Datagram/FragmentTest.cpp Hysteria2FragmentTest)
target_link_libraries(Hysteria2FragmentTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Datagram/ErrorTest.cpp Hysteria2DatagramErrorTest)
target_link_libraries(Hysteria2DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/CodecFuzzTest.cpp Hysteria2CodecFuzzTest)
target_link_libraries(Hysteria2CodecFuzzTest PRIVATE PrismProtocolHysteria2 PrismTestSupport)
AddPrismTest(Codec/DeepTest.cpp Hysteria2CodecDeepTest)
target_link_libraries(Hysteria2CodecDeepTest PRIVATE PrismFoundation PrismProtocolHysteria2 PrismTestSupport)
target_compile_options(Hysteria2CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/RoundtripTest.cpp Hysteria2RoundtripTest)
target_link_libraries(Hysteria2RoundtripTest PRIVATE PrismFoundation PrismProtocolHysteria2)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/StressTest.cpp Hysteria2StressTest)
 target_link_libraries(Hysteria2StressTest PRIVATE PrismTransport PrismProtocolHysteria2 PrismTestSupport)
endif()
# Hysteria2 HTTP/3 auth owner contract.
AddPrismTest(Admission/Http3AuthTest.cpp Hysteria2Http3AuthTest)
target_link_libraries(Hysteria2Http3AuthTest PRIVATE
    PrismAccount PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolShadowsocks2022
    PrismProtocolSocks5 PrismRuntime PrismTestSupport)
AddPrismTest(Admission/AdmissionTest.cpp Hysteria2AdmissionTest)
target_link_libraries(Hysteria2AdmissionTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts PrismLifecycle PrismProtocolHttp PrismProtocolHysteria2
    PrismProtocolQuic PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTestSupport PrismTransport)
AddPrismTest(Datagram/EndTest.cpp Hysteria2DgramEndTest)
target_link_libraries(Hysteria2DgramEndTest PRIVATE PrismAccount PrismFoundation
    PrismIoContracts
    PrismProtocolHysteria2 PrismProtocolHttp PrismProtocolHttp3Core PrismProtocolQuic
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime PrismTransport)
AddPrismTest(Connection/RequestEndTest.cpp Hysteria2RequestEndTest)
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
