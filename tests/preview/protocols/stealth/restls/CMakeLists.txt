# restls 子模块
prism_add_test(RestlsConnSession.cpp)
target_link_libraries(RestlsConnSession PRIVATE vmtest_common)

prism_add_test(RestlsCodecDeep.cpp)
target_link_libraries(RestlsCodecDeep PRIVATE vmtest_common)
