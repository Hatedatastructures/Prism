# http2 子模块测试
AddPreviewTest(H2CodecTest.cpp)
target_link_libraries(H2CodecTest PRIVATE PreviewProtocolHttp2 PreviewTestSupport)
