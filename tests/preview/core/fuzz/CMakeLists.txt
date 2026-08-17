# fuzz 子模块测试
prism_add_test(CodecFuzzTest.cpp)
target_link_libraries(CodecFuzzTest PRIVATE vmtest_common)
prism_add_test(FuzzExtendedTest.cpp)
target_link_libraries(FuzzExtendedTest PRIVATE vmtest_common)
prism_add_test(DgramErrorCoverage.cpp)
target_link_libraries(DgramErrorCoverage PRIVATE vmtest_common)
target_compile_options(DgramErrorCoverage PRIVATE -O0 -fno-inline)
