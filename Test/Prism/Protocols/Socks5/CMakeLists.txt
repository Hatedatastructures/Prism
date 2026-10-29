# socks5 子模块测试
AddPrismTest(Codec/BeastTest.cpp Socks5BeastTest)
target_link_libraries(Socks5BeastTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Codec/OwnerTest.cpp Socks5CodecOwnerTest)
target_link_libraries(Socks5CodecOwnerTest PRIVATE PrismFoundation PrismProtocolSocks5)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp Socks5ClientServerPerf)
    target_link_libraries(Socks5ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
endif()
AddPrismTest(Connection/ErrorMatrix.cpp Socks5ConnErrorMatrix)
target_link_libraries(Socks5ConnErrorMatrix PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnErrorMatrix PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Connection/TerminalReadTest.cpp Socks5ConnTerminalReadTest)
target_link_libraries(Socks5ConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
AddPrismTest(Connection/Session.cpp Socks5ConnSession)
target_link_libraries(Socks5ConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismRuntime
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5ConnSession PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Datagram/Session.cpp Socks5DgramSession)
target_link_libraries(Socks5DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
AddPrismTest(Datagram/UdpRetireTest.cpp Socks5UdpRetireTest)
target_link_libraries(Socks5UdpRetireTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolSocks5)
target_sources(Socks5UdpRetireTest PRIVATE Datagram/TcpPair.hpp)
AddPrismTest(Datagram/UdpExceptionTest.cpp Socks5UdpExceptionTest)
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
AddPrismTest(Datagram/ErrorTest.cpp Socks5DatagramErrorTest)
target_link_libraries(Socks5DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/CodecFuzzTest.cpp Socks5CodecFuzzTest)
target_link_libraries(Socks5CodecFuzzTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Codec/DeepTest.cpp Socks5CodecDeepTest)
target_link_libraries(Socks5CodecDeepTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolSocks5)
target_compile_options(Socks5CodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/GoldenVectorTest.cpp Socks5GoldenVectorTest)
target_link_libraries(Socks5GoldenVectorTest PRIVATE PrismFoundation PrismProtocolSocks5)
AddPrismTest(Core/DeferredReplyTest.cpp Socks5DeferredReplyTest)
target_link_libraries(Socks5DeferredReplyTest PRIVATE
    PrismDiagnoseBackend
    PrismFoundation
    PrismTransport
    PrismProtocolSocks5)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/StressTest.cpp Socks5StressTest)
    target_link_libraries(Socks5StressTest PRIVATE PrismFoundation PrismTransport PrismProtocolSocks5)
endif()
