# Boundary 子模块测试
AddPrismTest(DatagramBoundaryTest.cpp)
target_link_libraries(DatagramBoundaryTest PRIVATE PrismBoundary PrismNet)

AddPrismTest(DatagramBoundaryServiceTest.cpp)
target_link_libraries(DatagramBoundaryServiceTest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition
    PrismProtocolSocks5 PrismProtocolVless PrismProtocolQuic PrismProtocolQuicNative
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVmess
    PrismBoundary PrismTestSupport)
target_sources(DatagramBoundaryServiceTest PRIVATE DatagramServiceTestSupport.hpp)

AddPrismTest(BoundaryDispatcherTest.cpp)
target_link_libraries(BoundaryDispatcherTest PRIVATE
    PrismBoundary PrismFoundation PrismDatagramContract PrismIngressContract
    PrismIngressModel PrismTestSupport)

AddPrismTest(QuicConnectionRegistryTest.cpp)
target_sources(QuicConnectionRegistryTest PRIVATE ../../TestSupport/Prism/QuicFactory.hpp)
target_link_libraries(QuicConnectionRegistryTest PRIVATE
    PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolQuicNative
    PrismDatagramContract PrismIngressContract PrismBoundary PrismTestSupport)

AddPrismTest(QuicPacketGatewayLifecycleTest.cpp)
target_link_libraries(QuicPacketGatewayLifecycleTest PRIVATE PrismBoundary)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(QuicConnectionRegistryTest PRIVATE
    QuicGenerationBindingTest.cpp
    QuicConnectionRegistryTypedOwnerTest.cpp
)
