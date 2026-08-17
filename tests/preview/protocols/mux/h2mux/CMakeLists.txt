prism_add_test(H2muxCraftDeep.cpp)
target_link_libraries(H2muxCraftDeep PRIVATE vmtest_common)

prism_add_test(H2muxFrameError.cpp)
target_link_libraries(H2muxFrameError PRIVATE vmtest_common)

prism_add_test(H2muxCraftAsync.cpp)
target_link_libraries(H2muxCraftAsync PRIVATE vmtest_common)

prism_add_test(H2muxCraftDeep2.cpp)
target_link_libraries(H2muxCraftDeep2 PRIVATE vmtest_common)

