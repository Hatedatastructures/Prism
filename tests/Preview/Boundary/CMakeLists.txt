# Boundary 子模块测试
AddPreviewTest(DatagramBoundaryTest.cpp)
target_link_libraries(DatagramBoundaryTest PRIVATE PreviewBoundary)

AddPreviewTest(DatagramBoundaryServiceTest.cpp)
target_link_libraries(DatagramBoundaryServiceTest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition
    PreviewProtocolSocks5 PreviewProtocolVless PreviewBoundary PreviewTestSupport)
target_sources(DatagramBoundaryServiceTest PRIVATE DatagramServiceTestSupport.hpp)

AddPreviewTest(BoundaryDispatcherTest.cpp)
target_link_libraries(BoundaryDispatcherTest PRIVATE PreviewBoundary PreviewTestSupport)

AddPreviewTest(QuicConnectionRegistryTest.cpp)
target_sources(QuicConnectionRegistryTest PRIVATE ../../TestSupport/Preview/QuicFactory.hpp)
target_link_libraries(QuicConnectionRegistryTest PRIVATE
    PreviewFoundation PreviewTransport PreviewProtocolQuicNative PreviewBoundary PreviewTestSupport)

AddPreviewTest(QuicPacketGatewayLifecycleTest.cpp)
target_link_libraries(QuicPacketGatewayLifecycleTest PRIVATE PreviewBoundary)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(QuicConnectionRegistryTest PRIVATE
    QuicGenerationBindingTest.cpp
    QuicConnectionRegistryTypedOwnerTest.cpp
)
