# stress 子模块测试
if(PRISM_ENABLE_STRESS)
    AddPreviewTest(NetworkingStressTest.cpp)
 target_link_libraries(NetworkingStressTest PRIVATE PreviewTransport PreviewNet PreviewTestSupport)
    AddPreviewTest(RecognitionStabilityTest.cpp)
    target_link_libraries(RecognitionStabilityTest PRIVATE PreviewFoundation PreviewTransport PreviewRuntime PreviewComposition PreviewProtocolHttp PreviewProtocolVless PreviewProtocolVmess PreviewTestSupport)
endif()
