# SOCKS5 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(Socks5TcpE2ETest.cpp)
target_link_libraries(Socks5TcpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismTestSupport)
AddPrismTest(Socks5LongitudinalCoverage.cpp)
target_link_libraries(Socks5LongitudinalCoverage PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismTestSupport)
AddPrismTest(Socks5TypedHandoffTest.cpp)
target_link_libraries(Socks5TypedHandoffTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismProtocolSocks5 PrismTestSupport)
AddPrismTest(Socks5UdpE2ETest.cpp)
target_link_libraries(Socks5UdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolSocks5 PrismTestSupport)
