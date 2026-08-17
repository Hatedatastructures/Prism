# nested 子模块
prism_add_test(StealthNestedPerf3.cpp)
target_link_libraries(StealthNestedPerf3 PRIVATE vmtest_common)

# nested 子模块
prism_add_test(StealthNestedPerf2.cpp)
target_link_libraries(StealthNestedPerf2 PRIVATE vmtest_common)

# nested 子模块
prism_add_test(StealthNestedPerf.cpp)
target_link_libraries(StealthNestedPerf PRIVATE vmtest_common)

