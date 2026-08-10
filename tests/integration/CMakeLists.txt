# E2E.cpp 暂时禁用：待 session_resources 测试适配
# prism_add_test(E2E.cpp)
prism_add_test(Regression.cpp)

# --- SS2022 互操作测试（独立可执行，非 gtest） ---
# InteropSs2022Client：C++ common 客户端 → Go 服务端（sing-shadowsocks）
# InteropSs2022Server：C++ common 服务端 ← Go 客户端（sing-shadowsocks v0.2.12）
foreach(_tgt InteropSs2022Client InteropSs2022Server)
    add_executable(${_tgt} ${_tgt}.cpp)
    target_compile_options(${_tgt} PRIVATE -g1 -Os)
    target_link_libraries(${_tgt} PRIVATE prism_test_common Boost::system)
    set_target_properties(${_tgt} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    if(MINGW)
        target_compile_options(${_tgt} PRIVATE -fno-keep-inline-dllexport)
        set_target_properties(${_tgt} PROPERTIES ENABLE_EXPORTS OFF)
    endif()
endforeach()
