# QUIC 网关实验测试。
AddExperimentTest(GatewayCommonTest.cpp)
target_link_libraries(ExperimentGatewayCommonTest PRIVATE
    ExperimentalGatewayCommonSupport PrismBoundary PrismRuntime PrismProtocolQuic)
