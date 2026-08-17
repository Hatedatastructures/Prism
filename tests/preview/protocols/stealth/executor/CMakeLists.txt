# executor 子模块
prism_add_test(StealthExecutorDeep3.cpp)
target_link_libraries(StealthExecutorDeep3 PRIVATE vmtest_common)

# executor 子模块
prism_add_test(StealthExecutorDeep2.cpp)
target_link_libraries(StealthExecutorDeep2 PRIVATE vmtest_common)

