AddProductionTest(SessionDiversion.cpp)
AddProductionTest(BalancerDispatchE2E.cpp)
# Session.cpp 暂时禁用：待 session_resources 测试适配
# AddProductionTest(Session.cpp)
AddProductionTest(Transmission.cpp)
# GracefulShutdown.cpp 暂时禁用：待 session_resources 测试适配
# AddProductionTest(GracefulShutdown.cpp)
AddProductionTest(LaunchDeep.cpp)
AddProductionTest(ListenerPure.cpp)
AddProductionTest(WorkerTlsDeep.cpp)
AddProductionTest(QuicGatewayE2E.cpp)
# WorkerDeep.cpp 暂时禁用：待 session_resources 测试适配
# AddProductionTest(WorkerDeep.cpp)
AddProductionTest(HandshakeTimeout.cpp)
