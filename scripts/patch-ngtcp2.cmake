# 补丁脚本：修改 ngtcp2 的 CMakeLists.txt，注释与 nghttp2 冲突的 check 自定义目标
# 用法: cmake -P scripts/patch-ngtcp2.cmake <ngtcp2-src-dir>
# 由 CMakeLists.txt FetchContent PATCH_COMMAND 调用（兼容 Windows）
#
# 背景：nghttp2 v1.69 在其 CMakeLists.txt 第 174 行无条件定义
# add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})；ngtcp2 v1.25.0
# 在第 160 行（enable_testing() 之后）同样无条件定义同名目标。
# 两者经 FetchContent 引入同一构建树时目标名冲突（CMP0002），
# 全新构建树（CI）上配置直接失败；本地若有残留产物可能掩盖此问题。

if(NOT DEFINED CMAKE_ARGC)
    message(FATAL_ERROR "usage: cmake -P patch-ngtcp2.cmake <source-dir>")
endif()

set(src_dir "${CMAKE_ARGV3}")
set(cmake_file "${src_dir}/CMakeLists.txt")

file(READ "${cmake_file}" content)
string(REPLACE
    "add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})"
    "# patched: target 'check' collides with nghttp2's 'check' target\n# add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})"
    content "${content}")
file(WRITE "${cmake_file}" "${content}")

message(STATUS "ngtcp2: patched out colliding 'check' custom target")
