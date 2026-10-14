# Trojan 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPreviewTest(TrojanE2ETest.cpp)
target_link_libraries(TrojanE2ETest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition PreviewProtocolTrojan PreviewTestSupport)
AddPreviewTest(TrojanUdpE2ETest.cpp)
target_link_libraries(TrojanUdpE2ETest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition PreviewProtocolTrojan PreviewTestSupport)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TrojanE2ETest PRIVATE
    ../../../integration/Session/Trojan/TrojanTrafficIdentityE2ETest.cpp
)
