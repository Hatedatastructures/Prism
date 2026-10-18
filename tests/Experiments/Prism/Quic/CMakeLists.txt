# QUIC GatewayCommon 实验行为，不属于 Prism 生产 QUIC carrier target。
AddExperimentTest(GatewayCommonTest.cpp)
target_link_libraries(ExperimentGatewayCommonTest PRIVATE PrismBoundary PrismRuntime PrismProtocolQuic)
