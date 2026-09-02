# stress 子模块测试
if(PRISM_ENABLE_STRESS)
    AddPreviewTest(NetworkingStressTest.cpp)
 target_link_libraries(NetworkingStressTest PRIVATE PreviewTransport PreviewNet PreviewTestSupport)
endif()
