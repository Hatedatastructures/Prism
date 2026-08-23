# integration 子模块：SS2022 互操作（独立可执行，非 gtest，成对运行）
add_executable(InteropSs2022Client InteropSs2022Client.cpp)
target_compile_options(InteropSs2022Client PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Client PRIVATE vmtest_common Boost::system)
add_executable(InteropSs2022Server InteropSs2022Server.cpp)
target_compile_options(InteropSs2022Server PRIVATE -g1 -Os)
target_link_libraries(InteropSs2022Server PRIVATE vmtest_common Boost::system)

# L4 生产对拍：preview 客户端 → 生产 Prism 服务端（独立可执行，非 gtest）
add_executable(InteropPrismL4 InteropPrismL4.cpp)
target_compile_options(InteropPrismL4 PRIVATE -g1 -Os)
target_link_libraries(InteropPrismL4 PRIVATE vmtest_common Boost::system)
