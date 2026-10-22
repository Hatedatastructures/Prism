# Reality SessionId 工具实验测试。
AddExperimentTest(SessionIdToolTest.cpp)
target_include_directories(ExperimentSessionIdToolTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ExperimentSessionIdToolTest PRIVATE
    PrismProtocolReality ExperimentalRealitySessionSupport)
