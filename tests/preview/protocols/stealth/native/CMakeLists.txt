# native 子模块
prism_add_test(NativeConnTest.cpp)
target_link_libraries(NativeConnTest PRIVATE vmtest_common)

