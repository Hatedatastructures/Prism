# stress 子模块测试
if(PRISM_ENABLE_STRESS)
    prism_add_test(NetworkingStressTest.cpp)
    target_link_libraries(NetworkingStressTest PRIVATE vmtest_common)
endif()
