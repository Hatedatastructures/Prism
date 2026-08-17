# shadowtls 子模块
prism_add_test(ShadowtlsConnSession.cpp)
target_link_libraries(ShadowtlsConnSession PRIVATE vmtest_common)

prism_add_test(ShadowtlsCodecDeep.cpp)
target_link_libraries(ShadowtlsCodecDeep PRIVATE vmtest_common)
