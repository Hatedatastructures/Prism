# socks5 子模块测试
AddPrismTest(Socks5BeastTest.cpp)
target_link_libraries(Socks5BeastTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Socks5CodecOwnerTest.cpp)
target_link_libraries(Socks5CodecOwnerTest PRIVATE PrismFoundation PrismProtocolSocks5)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Socks5ClientServerPerf.cpp)
    target_link_libraries(Socks5ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
endif()
AddPrismTest(Socks5ConnErrorMatrix.cpp)
target_link_libraries(Socks5ConnErrorMatrix PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnErrorMatrix PRIVATE Socks5ConnSessionSupport.hpp)
AddPrismTest(Socks5ConnTerminalReadTest.cpp)
target_link_libraries(Socks5ConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Socks5ConnSession.cpp)
target_link_libraries(Socks5ConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnSession PRIVATE Socks5ConnSessionSupport.hpp)
AddPrismTest(Socks5DgramSession.cpp)
target_link_libraries(Socks5DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
AddPrismTest(Socks5UdpAssocRetirementTest.cpp)
target_link_libraries(Socks5UdpAssocRetirementTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Socks5UdpAssocRetirementDispatchFailureTest.cpp)
target_link_libraries(Socks5UdpAssocRetirementDispatchFailureTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Socks5DatagramErrorTest.cpp)
target_link_libraries(Socks5DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Socks5CodecFuzzTest.cpp)
target_link_libraries(Socks5CodecFuzzTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Socks5CodecDeepTest.cpp)
target_link_libraries(Socks5CodecDeepTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Socks5GoldenVectorTest.cpp)
target_link_libraries(Socks5GoldenVectorTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Socks5DeferredReplyTest.cpp)
target_link_libraries(Socks5DeferredReplyTest PRIVATE
    PrismDiagnoseBackend
    PrismFoundation
    PrismTransport
    PrismProtocolSocks5)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Socks5StressTest.cpp)
    target_link_libraries(Socks5StressTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
endif()
