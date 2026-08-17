# rate 子模块测试
prism_add_test(RateLimitTest.cpp)
target_link_libraries(RateLimitTest PRIVATE vmtest_common)
