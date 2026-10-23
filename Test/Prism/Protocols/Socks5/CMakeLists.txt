# socks5 子模块测试
AddPrismTest(Codec/Socks5BeastTest.cpp)
target_link_libraries(Socks5BeastTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Codec/Socks5CodecOwnerTest.cpp)
target_link_libraries(Socks5CodecOwnerTest PRIVATE PrismFoundation PrismProtocolSocks5)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/Socks5ClientServerPerf.cpp)
    target_link_libraries(Socks5ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
endif()
AddPrismTest(Connection/Socks5ConnErrorMatrix.cpp)
target_link_libraries(Socks5ConnErrorMatrix PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnErrorMatrix PRIVATE Connection/Socks5ConnSessionSupport.hpp)
AddPrismTest(Connection/Socks5ConnTerminalReadTest.cpp)
target_link_libraries(Socks5ConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Connection/Socks5ConnSession.cpp)
target_link_libraries(Socks5ConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnSession PRIVATE Connection/Socks5ConnSessionSupport.hpp)
AddPrismTest(Datagram/Socks5DgramSession.cpp)
target_link_libraries(Socks5DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
AddPrismTest(Datagram/Socks5UdpRetireTest.cpp)
target_link_libraries(Socks5UdpRetireTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5UdpRetireTest PRIVATE Datagram/TcpPair.hpp)
AddPrismTest(Datagram/Socks5UdpExceptionTest.cpp)
target_link_libraries(Socks5UdpExceptionTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5UdpExceptionTest PRIVATE Datagram/TcpPair.hpp)
AddPrismTest(Datagram/UdpRetireDispatchTest.cpp)
target_link_libraries(UdpRetireDispatchTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Datagram/Socks5DatagramErrorTest.cpp)
target_link_libraries(Socks5DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/Socks5CodecFuzzTest.cpp)
target_link_libraries(Socks5CodecFuzzTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Codec/Socks5CodecDeepTest.cpp)
target_link_libraries(Socks5CodecDeepTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/Socks5GoldenVectorTest.cpp)
target_link_libraries(Socks5GoldenVectorTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Core/Socks5DeferredReplyTest.cpp)
target_link_libraries(Socks5DeferredReplyTest PRIVATE
    PrismDiagnoseBackend
    PrismFoundation
    PrismTransport
    PrismProtocolSocks5)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/Socks5StressTest.cpp)
    target_link_libraries(Socks5StressTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
endif()
