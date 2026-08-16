prism_add_test(EchKeygen.cpp)
prism_add_test(EchSchemeDeep.cpp)

prism_add_test(EchNgxTest.cpp)
target_link_libraries(EchNgxTest PRIVATE vmtest_common)
