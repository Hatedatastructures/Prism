prism_add_test(XhttpSchemeDeep.cpp)
prism_add_test(XhttpE2E.cpp)

prism_add_test(XhttpNgxE2E.cpp)
target_link_libraries(XhttpNgxE2E PRIVATE vmtest_common)
