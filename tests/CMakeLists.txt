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
        ${PROJECT_NAME}_static_library GTest::gtest prism_test_common)
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
    # ucrt64 编译的测试需要 ucrt64/bin 在 PATH 中才能加载 DLL。
    # 不用 CROSSCOMPILING_EMULATOR 的 -E env（其 PATH 覆盖且无法包含
    # System32，导致 socket 网络测试偶发访问冲突），改用 ENVIRONMENT
    # 属性直接注入完整 PATH。
    if(MINGW)
        set_target_properties(${test_name} PROPERTIES
            CROSSCOMPILING_EMULATOR "")
    endif()
    gtest_discover_tests(${test_name}
        PROPERTIES TIMEOUT 30
                   ENVIRONMENT "PATH=C:/msys64/ucrt64/bin;C:/Windows/System32;C:/Windows"
        DISCOVERY_MODE PRE_TEST)
endfunction()

add_subdirectory(crypto)
add_subdirectory(dns)
add_subdirectory(common)
add_subdirectory(protocol)
add_subdirectory(handshake)
add_subdirectory(multiplex)
add_subdirectory(connect)
add_subdirectory(transport)
add_subdirectory(recognition)
add_subdirectory(foundation)
add_subdirectory(runtime)
add_subdirectory(settings)
add_subdirectory(infrastructure)
add_subdirectory(integration)
add_subdirectory(concurrency)
add_subdirectory(stress)
add_subdirectory(perf)

# 协议测试公共库（header-only，纯逻辑客户端/服务端实现）

# --- Go 协议兼容性测试（真实 quic-go / sing-quic 客户端，与 mihomo 同栈） ---
# 每个协议独立目录（tests/go/<protocol>/main.go），构建为独立可执行，
# ctest 运行时由 run_go_test.ps1 启动 Prism（显式配置路径）再运行测试。
find_program(GO_EXECUTABLE go)
if(GO_EXECUTABLE AND MINGW)
    set(_go_src_dir ${CMAKE_CURRENT_SOURCE_DIR}/go)
    set(_go_bin_dir ${CMAKE_BINARY_DIR}/tests/go)
    file(MAKE_DIRECTORY ${_go_bin_dir})
    set(_go_test_targets)

    # --- handshake 方案字节级对照工具（纯逻辑，无 Prism 依赖） ---
    # realitycmp / shadowtlscmp / restlscmp / anytlscmp / trusttunnelcmp / wscmp / guncmp
    foreach(_cmp realitycmp shadowtlscmp restlscmp anytlscmp trusttunnelcmp wscmp guncmp)
        add_custom_target(go_cmp_${_cmp} ALL
            COMMAND ${GO_EXECUTABLE} build -o ${_go_bin_dir}/${_cmp}.exe ./${_cmp}
            WORKING_DIRECTORY ${_go_src_dir}
            COMMENT "Building Go ${_cmp} reference tool"
            VERBATIM)
        add_test(NAME GoCmp_${_cmp}
            COMMAND ${_go_bin_dir}/${_cmp}.exe)
        set_tests_properties(GoCmp_${_cmp} PROPERTIES TIMEOUT 30)
    endforeach()

    foreach(_proto hysteria2 tuic)
        add_custom_target(go_test_${_proto} ALL
            COMMAND ${GO_EXECUTABLE} build -o ${_go_bin_dir}/${_proto}.exe ./${_proto}
            WORKING_DIRECTORY ${_go_src_dir}
            COMMENT "Building Go ${_proto} compatibility test"
            VERBATIM)
        list(APPEND _go_test_targets go_test_${_proto})
    endforeach()
    add_custom_target(go_test_vmess ALL
        COMMAND ${GO_EXECUTABLE} build -o ${_go_bin_dir}/vmess_client.exe ./vmess_client
        WORKING_DIRECTORY ${_go_src_dir}
        COMMENT "Building Go vmess compatibility test"
        VERBATIM)
    list(APPEND _go_test_targets go_test_vmess)
    add_custom_target(go_test_singvmess ALL
        COMMAND ${GO_EXECUTABLE} build -o ${_go_bin_dir}/singvmess.exe ./singvmess
        WORKING_DIRECTORY ${_go_src_dir}
        COMMENT "Building Go sing-vmess compatibility test"
        VERBATIM)
    list(APPEND _go_test_targets go_test_singvmess)

    set(_go_prism_exe ${CMAKE_BINARY_DIR}/src/Prism.exe)
    set(_go_prism_cfg ${CMAKE_SOURCE_DIR}/src/configuration.json)
    set(_go_runner ${_go_src_dir}/run_go_test.ps1)
    foreach(_proto hysteria2 tuic)
        add_test(NAME GoCompat_${_proto}
            COMMAND powershell -ExecutionPolicy Bypass -File ${_go_runner}
                    -GoExe ${_go_bin_dir}/${_proto}.exe
                    -PrismExe ${_go_prism_exe}
                    -Config ${_go_prism_cfg})
        set_tests_properties(GoCompat_${_proto} PROPERTIES TIMEOUT 60)
    endforeach()
    add_test(NAME GoCompat_vmess
        COMMAND powershell -ExecutionPolicy Bypass -File ${_go_runner}
                -GoExe ${_go_bin_dir}/vmess_client.exe
                -PrismExe ${_go_prism_exe}
                -Config ${_go_prism_cfg})
    set_tests_properties(GoCompat_vmess PROPERTIES TIMEOUT 60)
    add_test(NAME GoCompat_singvmess
        COMMAND powershell -ExecutionPolicy Bypass -File ${_go_runner}
                -GoExe ${_go_bin_dir}/singvmess.exe
                -PrismExe ${_go_prism_exe}
                -Config ${_go_prism_cfg})
    set_tests_properties(GoCompat_singvmess PROPERTIES TIMEOUT 60)
endif()
