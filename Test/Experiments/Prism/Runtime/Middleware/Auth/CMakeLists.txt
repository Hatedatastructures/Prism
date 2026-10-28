# 认证中间件实验测试。
AddExperimentTest(MiddlewareTest.cpp AuthMiddlewareTest)
target_link_libraries(ExperimentAuthMiddlewareTest PRIVATE
    PrismFoundation PrismRuntime ExperimentalAuthentication)

AddExperimentTest(DirectoryTest.cpp AuthDirectoryTest)
target_link_libraries(ExperimentAuthDirectoryTest PRIVATE
    PrismFoundation PrismRuntime PrismAccount ExperimentalAuthentication)
