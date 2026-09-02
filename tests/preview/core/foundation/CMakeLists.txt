# Foundation 契约测试
AddPreviewTest(TrafficSinkContractTest.cpp)
target_link_libraries(TrafficSinkContractTest PRIVATE
    PreviewProtocolSocks5
    PreviewProtocolVless)
