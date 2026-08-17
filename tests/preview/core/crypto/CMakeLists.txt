# crypto 子模块测试
prism_add_test(CoreAead.cpp)
target_link_libraries(CoreAead PRIVATE vmtest_common)
prism_add_test(CryptoExceptionCoverage.cpp)
target_link_libraries(CryptoExceptionCoverage PRIVATE vmtest_common)
