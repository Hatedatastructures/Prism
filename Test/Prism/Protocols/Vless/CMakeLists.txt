# vless 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp VlessClientServerPerf)
    target_link_libraries(VlessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
endif()
AddPrismTest(Connection/ErrorMatrix.cpp VlessConnErrorMatrix)
target_link_libraries(VlessConnErrorMatrix PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
AddPrismTest(Connection/TerminalReadTest.cpp VlessConnTerminalReadTest)
target_link_libraries(VlessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(Datagram/UdpTunnelTerminalTest.cpp VlessUdpTunnelTerminalTest)
target_link_libraries(VlessUdpTunnelTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(Connection/HandshakeTimeoutTest.cpp VlessHandshakeTimeoutTest)
target_link_libraries(VlessHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessHandshakeTimeoutTest PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Connection/Session.cpp VlessConnSession)
target_link_libraries(VlessConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismDatagramContract
    PrismTransport
    PrismComposition
    PrismIngressContract
    PrismStreamContract
    PrismRuntime
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolTrojan
    PrismProtocolVmess
    PrismProtocolVless)
target_sources(VlessConnSession PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Datagram/Session.cpp VlessDgramSession)
target_link_libraries(VlessDgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessDgramSession PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Datagram/ErrorTest.cpp VlessDatagramErrorTest)
target_link_libraries(VlessDatagramErrorTest PRIVATE
    PrismFoundation
    PrismNet
    PrismDatagramContract
    PrismTransport
    PrismProtocolVless
    PrismIngressContract)
target_compile_options(VlessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/CodecFuzzTest.cpp VlessCodecFuzzTest)
target_link_libraries(VlessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(Codec/DeepTest.cpp VlessCodecDeepTest)
target_link_libraries(VlessCodecDeepTest PRIVATE PrismFoundation PrismProtocolVless)
target_compile_options(VlessCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/GoldenVectorTest.cpp VlessGoldenVectorTest)
target_link_libraries(VlessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(Codec/BeastTest.cpp VlessBeastTest)
target_link_libraries(VlessBeastTest PRIVATE PrismFoundation PrismProtocolVless)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/StressTest.cpp VlessStressTest)
    target_link_libraries(VlessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless)
endif()

AddPrismTest(Datagram/XudpTest.cpp VlessXudpTest)
target_include_directories(VlessXudpTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(VlessXudpTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime
    PrismLifecycle PrismNetworkModel PrismProtocolVless)
AddPrismTest(Datagram/XudpSessionOwnerTest.cpp)
target_include_directories(XudpSessionOwnerTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(XudpSessionOwnerTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismLifecycle
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismStreamContract
    PrismComposition
    PrismRuntime
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolTrojan
    PrismProtocolVmess
    PrismProtocolVless)
AddPrismTest(Datagram/CanonicalAccountTest.cpp)
target_include_directories(CanonicalAccountTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(CanonicalAccountTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismDatagramContract
    PrismIngressModel
    PrismIngressContract
    PrismTransport
    PrismNet
    PrismStreamContract
    PrismComposition
    PrismDiagnoseBackend
    PrismRuntime
    PrismApplication
    PrismNetworkModel
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolTrojan
    PrismProtocolVmess
    PrismProtocolVless
    spdlog::spdlog)
