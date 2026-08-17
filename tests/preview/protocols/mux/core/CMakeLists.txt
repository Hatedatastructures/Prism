prism_add_test(ParcelDeep.cpp)
target_link_libraries(ParcelDeep PRIVATE vmtest_common)

prism_add_test(DuctDeep.cpp)
target_link_libraries(DuctDeep PRIVATE vmtest_common)

prism_add_test(MuxCodecTest.cpp)
target_link_libraries(MuxCodecTest PRIVATE vmtest_common)

prism_add_test(MuxCoreDeep.cpp)
target_link_libraries(MuxCoreDeep PRIVATE vmtest_common)

prism_add_test(MuxPerf.cpp)
target_link_libraries(MuxPerf PRIVATE vmtest_common)

prism_add_test(MuxSessionTest.cpp)
target_link_libraries(MuxSessionTest PRIVATE vmtest_common)
target_compile_options(MuxSessionTest PRIVATE -O0 -fno-inline)

prism_add_test(MuxSessionDeep2.cpp)
target_link_libraries(MuxSessionDeep2 PRIVATE vmtest_common)
target_compile_options(MuxSessionDeep2 PRIVATE -O0 -fno-inline)

prism_add_test(MuxSessionDeep.cpp)
target_link_libraries(MuxSessionDeep PRIVATE vmtest_common)
target_compile_options(MuxSessionDeep PRIVATE -O0 -fno-inline)

