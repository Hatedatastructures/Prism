# QUIC 网关实验测试。
AddExperimentTest(CommonTest.cpp GatewayCommonTest)
target_link_libraries(ExperimentGatewayCommonTest PRIVATE
    ExperimentalGatewayCommonSupport PrismBoundary PrismRuntime PrismProtocolQuic)
