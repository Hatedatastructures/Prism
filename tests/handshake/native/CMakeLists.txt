prism_add_test(NativeScheme.cpp)
prism_add_test(NativeSchemePure.cpp)
prism_add_test(NativeConnTest.cpp)
target_link_libraries(NativeConnTest PRIVATE vmtest_common)
