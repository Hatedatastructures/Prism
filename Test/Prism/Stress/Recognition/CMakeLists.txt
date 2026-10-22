# 识别路径稳定性压力测试。
AddPrismTest(RecognitionStabilityTest.cpp)
target_link_libraries(RecognitionStabilityTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition
    PrismProtocolHttp PrismProtocolVless PrismProtocolVmess PrismTestSupport)
