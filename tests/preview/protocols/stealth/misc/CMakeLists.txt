# misc 子模块
prism_add_test(StealthVmessErrorCoverage.cpp)
target_link_libraries(StealthVmessErrorCoverage PRIVATE vmtest_common)
target_compile_options(StealthVmessErrorCoverage PRIVATE -O0 -fno-inline)

# misc 子模块
prism_add_test(StealthMuxBeastTest.cpp)
target_link_libraries(StealthMuxBeastTest PRIVATE vmtest_common)

# misc 子模块
prism_add_test(ConnDecoratorDeep.cpp)
target_link_libraries(ConnDecoratorDeep PRIVATE vmtest_common)
target_compile_options(ConnDecoratorDeep PRIVATE -O0 -fno-inline)

