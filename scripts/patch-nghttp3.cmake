# 补丁脚本：修改 nghttp3 的 CMakeLists.txt，注释与 nghttp2 冲突的 check 自定义目标
# 用法: cmake -P scripts/patch-nghttp3.cmake <nghttp3-src-dir>
# 由 CMakeLists.txt FetchContent PATCH_COMMAND 调用（兼容 Windows）

if(NOT DEFINED CMAKE_ARGC)
    message(FATAL_ERROR "usage: cmake -P patch-nghttp3.cmake <source-dir>")
endif()

set(src_dir "${CMAKE_ARGV3}")
set(cmake_file "${src_dir}/CMakeLists.txt")

file(READ "${cmake_file}" content)
string(REPLACE
    "add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})"
    "# patched: target 'check' collides with nghttp2's 'check' target\n# add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})"
    content "${content}")
file(WRITE "${cmake_file}" "${content}")

message(STATUS "nghttp3: patched out colliding 'check' custom target")
