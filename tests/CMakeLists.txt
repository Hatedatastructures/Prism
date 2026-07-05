cmake_minimum_required(VERSION 3.23)

include(GoogleTest)

set(_test_common_dir ${CMAKE_CURRENT_SOURCE_DIR}/common)
set(_test_common_gtest_main ${_test_common_dir}/gtest_main.cpp)

# 每个 .cpp 编译为独立可执行文件，避免 Deep 测试 ODR 冲突
function(prism_add_test source_file)
    get_filename_component(test_name ${source_file} NAME_WE)
    add_executable(${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
    target_compile_options(${test_name} PRIVATE -g1 -Os)
    target_link_libraries(${test_name} PRIVATE
        ${PROJECT_NAME}_static_library GTest::gtest)
    target_sources(${test_name} PRIVATE ${_test_common_gtest_main})
    target_include_directories(${test_name} BEFORE PRIVATE
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/src)
    if(MINGW)
        target_compile_options(${test_name} PRIVATE -Wa,-mbig-obj -fno-keep-inline-dllexport)
        # --out-implib 在 .exe 链接时产生无用的导入库，且在某些 MinGW 版本上
        # 与 --gc-sections / 全局静态数据组合导致 "ld returned 5" 错误，显式禁用
        set_target_properties(${test_name} PROPERTIES
            ENABLE_EXPORTS OFF
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
        # Deep 测试 #include 源文件，与静态库产生重复符号；允许第一个定义胜出
        target_link_options(${test_name} PRIVATE -Wl,--allow-multiple-definition)
    endif()
    # gtest_discover_tests 在构建后扫描可执行文件注册 GTest 用例，
    # 使用 PRE_TEST 模式延迟发现，避免 configure 阶段运行未构建的二进制
    # ucrt64 编译的测试需要 ucrt64/bin 在 PATH 中才能加载 DLL，
    # 通过 CMAKE_CROSSCOMPILING_EMULATOR 设置前缀命令注入 PATH
    if(MINGW)
        set_target_properties(${test_name} PROPERTIES
            CROSSCOMPILING_EMULATOR "${CMAKE_COMMAND};-E;env;PATH=C:/msys64/ucrt64/bin")
    endif()
    gtest_discover_tests(${test_name}
        PROPERTIES TIMEOUT 30
        DISCOVERY_MODE PRE_TEST)
endfunction()

add_subdirectory(crypto)
add_subdirectory(protocol)
add_subdirectory(stealth)
add_subdirectory(multiplex)
add_subdirectory(resolve)
add_subdirectory(connect)
add_subdirectory(transport)
add_subdirectory(instance)
add_subdirectory(recognition)
add_subdirectory(foundation)
add_subdirectory(context)
add_subdirectory(outbound)
add_subdirectory(config)
add_subdirectory(worker)
add_subdirectory(infrastructure)
add_subdirectory(integration)
add_subdirectory(concurrency)
