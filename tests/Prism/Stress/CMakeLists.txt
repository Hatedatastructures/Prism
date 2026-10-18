# stress 子模块测试
if(PRISM_ENABLE_STRESS)
    AddPrismTest(NetworkingStressTest.cpp)
 target_link_libraries(NetworkingStressTest PRIVATE PrismTransport PrismNet PrismTestSupport)
    AddPrismTest(RecognitionStabilityTest.cpp)
    target_link_libraries(RecognitionStabilityTest PRIVATE PrismFoundation PrismTransport PrismRuntime PrismComposition PrismProtocolHttp PrismProtocolVless PrismProtocolVmess PrismTestSupport)
endif()
