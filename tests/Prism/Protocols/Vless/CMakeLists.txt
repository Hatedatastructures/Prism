# vless 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(VlessClientServerPerf.cpp)
    target_link_libraries(VlessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
endif()
AddPrismTest(VlessConnErrorMatrix.cpp)
target_link_libraries(VlessConnErrorMatrix PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVless)
AddPrismTest(VlessConnTerminalReadTest.cpp)
target_link_libraries(VlessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(VlessUdpTunnelTerminalTest.cpp)
target_link_libraries(VlessUdpTunnelTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVless)
AddPrismTest(VlessHandshakeTimeoutTest.cpp)
target_link_libraries(VlessHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessHandshakeTimeoutTest PRIVATE VlessConnSessionSupport.hpp)
AddPrismTest(VlessConnSession.cpp)
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
target_sources(VlessConnSession PRIVATE VlessConnSessionSupport.hpp)
AddPrismTest(VlessDgramSession.cpp)
target_link_libraries(VlessDgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolVless PrismIngressContract)
target_sources(VlessDgramSession PRIVATE VlessConnSessionSupport.hpp)
AddPrismTest(VlessDatagramErrorTest.cpp)
target_link_libraries(VlessDatagramErrorTest PRIVATE
    PrismFoundation
    PrismNet
    PrismDatagramContract
    PrismTransport
    PrismProtocolVless
    PrismIngressContract)
target_compile_options(VlessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(VlessCodecFuzzTest.cpp)
target_link_libraries(VlessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(VlessCodecDeepTest.cpp)
target_link_libraries(VlessCodecDeepTest PRIVATE PrismFoundation PrismProtocolVless)
target_compile_options(VlessCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(VlessGoldenVectorTest.cpp)
target_link_libraries(VlessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVless)
AddPrismTest(VlessBeastTest.cpp)
target_link_libraries(VlessBeastTest PRIVATE PrismFoundation PrismProtocolVless)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(VlessStressTest.cpp)
    target_link_libraries(VlessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVless)
endif()

AddPrismTest(VlessXudpTest.cpp)
target_include_directories(VlessXudpTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(VlessXudpTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime
    PrismLifecycle PrismNetworkModel PrismProtocolVless)
AddPrismTest(XudpSessionOwnerTest.cpp)
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
AddPrismTest(CanonicalAccountDatagramTest.cpp)
target_include_directories(CanonicalAccountDatagramTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(CanonicalAccountDatagramTest PRIVATE
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
