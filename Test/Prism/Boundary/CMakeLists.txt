# Boundary 子模块测试
AddPrismTest(Datagram/BoundaryTest.cpp DatagramBoundaryTest)
target_link_libraries(DatagramBoundaryTest PRIVATE PrismBoundary PrismNet)

AddPrismTest(Datagram/ServiceTest.cpp DatagramServiceTest)
target_link_libraries(DatagramServiceTest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition
    PrismProtocolSocks5 PrismProtocolVless PrismProtocolQuic PrismProtocolQuicNative
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVmess
    PrismBoundary PrismTestSupport)
target_sources(DatagramServiceTest PRIVATE Datagram/ServiceTestSupport.hpp)

AddPrismTest(Dispatch/DispatcherTest.cpp BoundaryDispatcherTest)
target_link_libraries(BoundaryDispatcherTest PRIVATE
    PrismBoundary PrismFoundation PrismDatagramContract PrismIngressContract
    PrismIngressModel PrismTestSupport)

AddPrismTest(Quic/CidRegistryTest.cpp QuicConnectionRegistryTest)
target_sources(QuicConnectionRegistryTest PRIVATE ../../TestSupport/Prism/QuicFactory.hpp)
target_link_libraries(QuicConnectionRegistryTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolQuicNative
    PrismDatagramContract PrismIngressContract PrismBoundary PrismTestSupport)

AddPrismTest(Quic/GatewayLifecycleTest.cpp QuicGatewayLifecycleTest)
target_link_libraries(QuicGatewayLifecycleTest PRIVATE PrismBoundary)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(QuicConnectionRegistryTest PRIVATE
    Quic/GenerationBindingTest.cpp
    Quic/RegistryOwnerTest.cpp
)
