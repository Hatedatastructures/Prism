# 中立数据报 association/service 场景
AddPreviewTest(CanonicalAssociationTest.cpp)
target_link_libraries(CanonicalAssociationTest PRIVATE PreviewIngressContract PreviewComposition PreviewNet PreviewTestSupport)

AddPreviewTest(DatagramProtocolServiceTest.cpp)
target_link_libraries(DatagramProtocolServiceTest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition
    PreviewProtocolSocks5 PreviewProtocolVless PreviewBoundary PreviewTestSupport)
target_sources(DatagramProtocolServiceTest PRIVATE ../../../Boundary/DatagramServiceTestSupport.hpp)
