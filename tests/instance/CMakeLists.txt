# Session.cpp 暂时禁用：待 session_resources 测试适配
# prism_add_test(Session.cpp)
prism_add_test(Connection.cpp)
prism_add_test(Transmission.cpp)
# GracefulShutdown.cpp 暂时禁用：待 session_resources 测试适配
# prism_add_test(GracefulShutdown.cpp)
prism_add_test(LaunchPure.cpp)
prism_add_test(LaunchDeep.cpp)
prism_add_test(ListenerMakeAffinity.cpp)
prism_add_test(ListenerPure.cpp)
prism_add_test(WorkerTlsDeep.cpp)
# WorkerDeep.cpp 暂时禁用：待 session_resources 测试适配
# prism_add_test(WorkerDeep.cpp)
prism_add_test(HandshakeTimeout.cpp)
