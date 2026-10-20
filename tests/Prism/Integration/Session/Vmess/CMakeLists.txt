# VMess 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(VMessE2ETest.cpp)
target_sources(VMessE2ETest PRIVATE
    VMessTrafficIdentityE2ETest.cpp
    VMessTcpE2ETestSupport.hpp)
target_link_libraries(VMessE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(VMessUdpE2ETest.cpp)
target_link_libraries(VMessUdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
