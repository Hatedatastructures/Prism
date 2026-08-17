# recognition 子模块测试
prism_add_test(RecognitionTest.cpp)
target_link_libraries(RecognitionTest PRIVATE vmtest_common)
prism_add_test(TlsRecord.cpp)
target_link_libraries(TlsRecord PRIVATE vmtest_common)
prism_add_test(TlsSignal.cpp)
target_link_libraries(TlsSignal PRIVATE vmtest_common)
