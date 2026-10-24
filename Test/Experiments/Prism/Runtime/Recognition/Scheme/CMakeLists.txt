# Scheme 执行器实验测试。
AddExperimentTest(SchemeExecutorTest.cpp)
target_include_directories(ExperimentSchemeExecutorTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ExperimentSchemeExecutorTest PRIVATE
    ExperimentalRecognitionSupport PrismTransport PrismRuntime)
