# xhttp 子模块
prism_add_test(XhttpNgxE2E.cpp)
target_link_libraries(XhttpNgxE2E PRIVATE vmtest_common)

prism_add_test(XhttpErrorMatrix.cpp)
target_link_libraries(XhttpErrorMatrix PRIVATE vmtest_common)
