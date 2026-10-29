# SOCKS5 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(TcpE2ETest.cpp Socks5TcpE2ETest)
target_link_libraries(Socks5TcpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(LongitudinalCoverage.cpp Socks5LongitudinalCoverage)
target_link_libraries(Socks5LongitudinalCoverage PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(TypedHandoffTest.cpp Socks5TypedHandoffTest)
target_sources(Socks5TypedHandoffTest PRIVATE PlaneTransferTest.cpp)
target_link_libraries(Socks5TypedHandoffTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismAccount PrismIngressContract
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismTestSupport)
AddPrismTest(UdpE2ETest.cpp Socks5UdpE2ETest)
target_link_libraries(Socks5UdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismTestSupport)
