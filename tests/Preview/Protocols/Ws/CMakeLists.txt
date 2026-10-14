# ws 子模块
AddPreviewTest(WsConnSession.cpp)
target_sources(WsConnSession PRIVATE
    WsConnFrame.cpp
    WsConnHandshake.cpp
    WsConnClose.cpp
    WsConnSessionSupport.hpp
    WsFactorySupport.hpp)
target_link_libraries(WsConnSession PRIVATE PreviewTransport PreviewProtocolWs PreviewTestSupport)
AddPreviewTest(WsCodecDeepTest.cpp)
target_link_libraries(WsCodecDeepTest PRIVATE PreviewFoundation PreviewProtocolWs PreviewTestSupport)
target_compile_options(WsCodecDeepTest PRIVATE -O0 -fno-inline)

# 同一实际owner的源文件，复用现有target。
target_sources(WsConnSession PRIVATE
    WsConnActivity.cpp
    WsConnResource.cpp
)
