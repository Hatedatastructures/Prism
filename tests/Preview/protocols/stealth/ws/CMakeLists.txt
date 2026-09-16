# ws 子模块
AddPreviewTest(WsConnSession.cpp)
target_link_libraries(WsConnSession PRIVATE PreviewTransport PreviewProtocolWs PreviewTestSupport)
