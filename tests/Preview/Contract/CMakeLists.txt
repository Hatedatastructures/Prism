AddPreviewTest(Task9ContractTest.cpp)
target_link_libraries(Task9ContractTest PRIVATE
        PreviewComposition
        PreviewProtocolHysteria2
        PreviewProtocolTuic
        PreviewTransport)
