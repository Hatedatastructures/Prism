# VLESS 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(E2ETest.cpp VlessE2ETest)
target_sources(VlessE2ETest PRIVATE VlessTestSupport.hpp)
target_link_libraries(VlessE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolVless PrismTestSupport)
AddPrismTest(UpstreamAbortE2ETest.cpp VlessUpstreamAbortE2ETest)
target_sources(VlessUpstreamAbortE2ETest PRIVATE VlessTestSupport.hpp)
target_link_libraries(VlessUpstreamAbortE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolVless PrismTestSupport)
AddPrismTest(UdpE2ETest.cpp VlessUdpE2ETest)
target_link_libraries(VlessUdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
