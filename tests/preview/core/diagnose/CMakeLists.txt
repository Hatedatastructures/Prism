# diagnose 子模块测试
prism_add_test(ObservabilityTest.cpp)
target_link_libraries(ObservabilityTest PRIVATE vmtest_common)
