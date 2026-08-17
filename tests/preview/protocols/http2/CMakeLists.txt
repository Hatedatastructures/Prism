# http2 子模块测试
prism_add_test(H2CodecTest.cpp)
target_link_libraries(H2CodecTest PRIVATE vmtest_common)
