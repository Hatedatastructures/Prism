# 中立数据报 association/service 场景
AddPrismTest(AssociationTest.cpp CanonicalAssociationTest)
target_link_libraries(CanonicalAssociationTest PRIVATE
    PrismFoundation PrismIngressContract PrismComposition PrismNet PrismTransport PrismNetworkModel
    PrismProtocolSocks5 PrismProtocolVless PrismTestSupport)

AddPrismTest(ProtocolTest.cpp DatagramProtocolTest)
target_link_libraries(DatagramProtocolTest PRIVATE
    PrismFoundation PrismTransport PrismNetworkModel PrismNet PrismRuntime PrismComposition
    PrismProtocolAnytls PrismProtocolQuic PrismProtocolQuicNative PrismProtocolShadowsocks2022
    PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismBoundary PrismTestSupport)
target_sources(DatagramProtocolTest PRIVATE ../../../Boundary/Datagram/ServiceTestSupport.hpp)
