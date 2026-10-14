# VMess 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPreviewTest(VMessE2ETest.cpp)
target_link_libraries(VMessE2ETest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition PreviewProtocolVmess PreviewTestSupport)
AddPreviewTest(VMessUdpE2ETest.cpp)
target_link_libraries(VMessUdpE2ETest PRIVATE
    PreviewFoundation PreviewTransport PreviewNet PreviewRuntime PreviewComposition PreviewProtocolVmess PreviewTestSupport)
