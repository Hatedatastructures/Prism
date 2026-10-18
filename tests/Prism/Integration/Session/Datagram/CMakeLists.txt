# 中立数据报 association/service 场景
AddPrismTest(CanonicalAssociationTest.cpp)
target_link_libraries(CanonicalAssociationTest PRIVATE PrismIngressContract PrismComposition PrismNet PrismTestSupport)

AddPrismTest(DatagramProtocolServiceTest.cpp)
target_link_libraries(DatagramProtocolServiceTest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition
    PrismProtocolSocks5 PrismProtocolVless PrismBoundary PrismTestSupport)
target_sources(DatagramProtocolServiceTest PRIVATE ../../../Boundary/DatagramServiceTestSupport.hpp)
