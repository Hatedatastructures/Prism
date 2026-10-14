# Shadowsocks2022 经真实 Runtime Session 的 TCP 场景
AddPreviewTest(SS2022E2ETest.cpp)
target_link_libraries(SS2022E2ETest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition
    PreviewProtocolShadowsocks2022 PreviewTestSupport)
