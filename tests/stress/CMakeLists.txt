# stress 工具链（T5-10 D7）
# smoke 参数：短时可重复跑；完整长跑调大轮次

prism_add_test(NetworkingStressTest.cpp)
target_link_libraries(NetworkingStressTest PRIVATE vmtest_common)
