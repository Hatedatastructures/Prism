prism_add_test(TuicCodec.cpp)


prism_add_test(TuicClientServerPerf.cpp)
target_link_libraries(TuicClientServerPerf PRIVATE vmtest_common)

prism_add_test(TuicConnErrorMatrix.cpp)
