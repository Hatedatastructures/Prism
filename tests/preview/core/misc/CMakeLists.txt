# misc 子模块测试
prism_add_test(CoreModulesCoverage.cpp)
target_link_libraries(CoreModulesCoverage PRIVATE vmtest_common)
prism_add_test(OwnershipAudit.cpp)
target_link_libraries(OwnershipAudit PRIVATE vmtest_common)
prism_add_test(TestRunnerDeep.cpp)
target_link_libraries(TestRunnerDeep PRIVATE vmtest_common)
target_compile_options(TestRunnerDeep PRIVATE -O0 -fno-inline)
