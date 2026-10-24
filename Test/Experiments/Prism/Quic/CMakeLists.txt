# QUIC GatewayCommon 实验行为，不属于 Prism 生产 QUIC carrier target。
add_library(ExperimentalGatewayCommonSupport INTERFACE)
target_sources(ExperimentalGatewayCommonSupport INTERFACE Gateway/GatewayCommon.hpp)
add_subdirectory(Gateway)
