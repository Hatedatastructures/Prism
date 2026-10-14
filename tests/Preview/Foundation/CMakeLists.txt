# Foundation value and error contracts.
AddPreviewTest(FoundationValuesTest.cpp)
target_link_libraries(FoundationValuesTest PRIVATE PreviewFoundation)
AddPreviewTest(ByteSpanTest.cpp)
target_link_libraries(ByteSpanTest PRIVATE PreviewFoundation PreviewTestSupport)
target_compile_options(ByteSpanTest PRIVATE -O0 -fno-inline)

# Foundation 契约测试
AddPreviewTest(TrafficSinkContractTest.cpp)
target_link_libraries(TrafficSinkContractTest PRIVATE
    PreviewProtocolSocks5
    PreviewProtocolVless)
