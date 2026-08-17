# protocol 子模块测试
prism_add_test(PreviewProtocolTest.cpp)
target_link_libraries(PreviewProtocolTest PRIVATE vmtest_common)
prism_add_test(TestCommonCodecDeep.cpp)
target_link_libraries(TestCommonCodecDeep PRIVATE vmtest_common)
target_compile_options(TestCommonCodecDeep PRIVATE -O0 -fno-inline)
prism_add_test(TestCommonCodecDeep2.cpp)
target_link_libraries(TestCommonCodecDeep2 PRIVATE vmtest_common)
target_compile_options(TestCommonCodecDeep2 PRIVATE -O0 -fno-inline)
