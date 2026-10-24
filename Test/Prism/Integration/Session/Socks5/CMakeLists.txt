# SOCKS5 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(Socks5TcpE2ETest.cpp)
target_link_libraries(Socks5TcpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(Socks5LongitudinalCoverage.cpp)
target_link_libraries(Socks5LongitudinalCoverage PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(Socks5TypedHandoffTest.cpp)
target_sources(Socks5TypedHandoffTest PRIVATE Socks5PlaneTransferTest.cpp)
target_link_libraries(Socks5TypedHandoffTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismAccount PrismIngressContract
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismTestSupport)
AddPrismTest(Socks5UdpE2ETest.cpp)
target_link_libraries(Socks5UdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismTestSupport)
