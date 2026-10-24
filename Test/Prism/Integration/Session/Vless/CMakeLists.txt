# VLESS 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(VlessE2ETest.cpp)
target_sources(VlessE2ETest PRIVATE VlessTestSupport.hpp)
target_link_libraries(VlessE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolVless PrismTestSupport)
AddPrismTest(VlessUpstreamAbortE2ETest.cpp)
target_sources(VlessUpstreamAbortE2ETest PRIVATE VlessTestSupport.hpp)
target_link_libraries(VlessUpstreamAbortE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolVless PrismTestSupport)
AddPrismTest(VlessUdpE2ETest.cpp)
target_link_libraries(VlessUdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
