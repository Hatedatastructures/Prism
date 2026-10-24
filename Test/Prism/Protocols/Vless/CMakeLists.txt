# vless 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/VlessClientServerPerf.cpp)
    target_link_libraries(VlessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
endif()
AddPrismTest(Connection/VlessConnErrorMatrix.cpp)
target_link_libraries(VlessConnErrorMatrix PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
AddPrismTest(Connection/VlessConnTerminalReadTest.cpp)
target_link_libraries(VlessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(Datagram/VlessUdpTunnelTerminalTest.cpp)
target_link_libraries(VlessUdpTunnelTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(Connection/VlessHandshakeTimeoutTest.cpp)
target_link_libraries(VlessHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessHandshakeTimeoutTest PRIVATE Connection/VlessConnSessionSupport.hpp)
AddPrismTest(Connection/VlessConnSession.cpp)
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
target_sources(VlessConnSession PRIVATE Connection/VlessConnSessionSupport.hpp)
AddPrismTest(Datagram/VlessDgramSession.cpp)
target_link_libraries(VlessDgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessDgramSession PRIVATE Connection/VlessConnSessionSupport.hpp)
AddPrismTest(Datagram/VlessDatagramErrorTest.cpp)
target_link_libraries(VlessDatagramErrorTest PRIVATE
    PrismFoundation
    PrismNet
    PrismDatagramContract
    PrismTransport
    PrismProtocolVless
    PrismIngressContract)
target_compile_options(VlessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/VlessCodecFuzzTest.cpp)
target_link_libraries(VlessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(Codec/VlessCodecDeepTest.cpp)
target_link_libraries(VlessCodecDeepTest PRIVATE PrismFoundation PrismProtocolVless)
target_compile_options(VlessCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/VlessGoldenVectorTest.cpp)
target_link_libraries(VlessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(Codec/VlessBeastTest.cpp)
target_link_libraries(VlessBeastTest PRIVATE PrismFoundation PrismProtocolVless)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/VlessStressTest.cpp)
    target_link_libraries(VlessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless)
endif()

AddPrismTest(Datagram/VlessXudpTest.cpp)
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
