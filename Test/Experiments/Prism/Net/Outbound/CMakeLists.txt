# 出站拨号实验测试。
AddExperimentTest(OutboundTest.cpp)
target_link_libraries(ExperimentOutboundTest PRIVATE
    ExperimentalNetRouteSupport PrismNet)
