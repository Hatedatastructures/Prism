# http3 子模块测试
prism_add_test(HttpQuicCoverage.cpp)
target_link_libraries(HttpQuicCoverage PRIVATE vmtest_common)
prism_add_test(QpackEncodeOut.cpp)
target_link_libraries(QpackEncodeOut PRIVATE vmtest_common)
prism_add_test(QpackInteropTest.cpp)
target_link_libraries(QpackInteropTest PRIVATE vmtest_common)
