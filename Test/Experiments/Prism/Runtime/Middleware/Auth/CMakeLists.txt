# 认证中间件实验测试。
AddExperimentTest(AuthMiddlewareTest.cpp)
target_link_libraries(ExperimentAuthMiddlewareTest PRIVATE
    PrismFoundation PrismRuntime ExperimentalAuthentication)

AddExperimentTest(AuthDirectoryTest.cpp)
target_link_libraries(ExperimentAuthDirectoryTest PRIVATE
    PrismFoundation PrismRuntime PrismAccount ExperimentalAuthentication)
