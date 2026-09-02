cmake_minimum_required(VERSION 3.23)

include(GoogleTest)

set(_test_support_runner_dir ${CMAKE_SOURCE_DIR}/tests/TestSupport/Runner)
set(_production_test_main ${_test_support_runner_dir}/gtest_main.cpp)
set(_preview_test_main ${_test_support_runner_dir}/PreviewGtestMain.cpp)

# 每个 .cpp 编译为独立可执行文件，避免 Deep 测试 ODR 冲突
function(AddTestExecutable source_file test_mode support_target main_source)
    get_filename_component(test_name ${source_file} NAME_WE)
    if(NOT test_name MATCHES "^[A-Za-z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Test source produces an invalid target name: ${test_name}")
    endif()
    string(SUBSTRING "${test_name}" 0 1 _test_initial)
    string(TOUPPER "${_test_initial}" _test_initial)
    string(SUBSTRING "${test_name}" 1 -1 _test_tail)
    set(test_name "${_test_initial}${_test_tail}")
    if(NOT test_name MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Test target is not PascalCase: ${test_name}")
    endif()
    add_executable(${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${test_name} PRIVATE -g1 -Os)
    endif()
    target_link_libraries(${test_name} PRIVATE
        GTest::gtest ${support_target})
    if("${test_mode}" STREQUAL "Production" OR "${test_mode}" STREQUAL "Contract")
        target_link_libraries(${test_name} PRIVATE PrismStaticLibrary)
    endif()
    target_sources(${test_name} PRIVATE ${main_source})
    if("${test_mode}" STREQUAL "Preview")
        target_include_directories(${test_name} BEFORE PRIVATE
            ${CMAKE_SOURCE_DIR}/tests
            ${CMAKE_SOURCE_DIR}/preview)
    else()
        target_include_directories(${test_name} BEFORE PRIVATE
            ${CMAKE_SOURCE_DIR}/tests
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/include)
    endif()
    if("${source_file}" MATCHES "StressTest")
        set(_test_labels LABELS stress)
    elseif("${source_file}" MATCHES "Perf")
        set(_test_labels LABELS perf)
    else()
        set(_test_labels)
    endif()
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
    # MinGW 动态链接的测试需要运行时 DLL（libstdc++-6 等）在 PATH 中。
    # 不得硬编码开发者本机 MSYS2 路径（CI 的 MinGW 位于 C:/mingw64/bin，
    # 硬编码会使测试进程 PATH 无法解析 DLL → 0xc0000135），
    # 从编译器位置推导运行时 DLL 目录
    if(MINGW)
        set_target_properties(${test_name} PROPERTIES CROSSCOMPILING_EMULATOR "")
        get_filename_component(_test_runtime_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
        gtest_discover_tests(${test_name}
            PROPERTIES TIMEOUT 60
                       ${_test_labels}
                       ENVIRONMENT "PATH=${_test_runtime_bin};C:/Windows/System32;C:/Windows"
            DISCOVERY_MODE PRE_TEST)
    else()
        # 非 MinGW：继承执行环境 PATH（注入 Windows 风格 PATH 会毁掉
        # Linux 测试进程的共享库解析）
        gtest_discover_tests(${test_name}
            PROPERTIES TIMEOUT 60
                       ${_test_labels}
            DISCOVERY_MODE PRE_TEST)
    endif()
    set_property(GLOBAL APPEND PROPERTY Prism${test_mode}TestTargets ${test_name})
    if("${test_mode}" STREQUAL "Production")
        set_property(GLOBAL APPEND PROPERTY PrismProductionTestSources
                     "${CMAKE_CURRENT_SOURCE_DIR}/${source_file}")
    endif()
endfunction()

function(AddProductionTest source_file)
    AddTestExecutable(${source_file} Production ProductionTestSupport ${_production_test_main})
endfunction()

function(AddPreviewTest source_file)
    AddTestExecutable(${source_file} Preview PreviewTestSupport ${_preview_test_main})
endfunction()

function(AddContractTest source_file)
    AddTestExecutable(${source_file} Contract ContractTestSupport ${_production_test_main})
endfunction()

# 收集项目内部 target 的 direct/interface link closure；外部 imported target
# 不参与遍历，避免配置阶段扫描整个 GTest/依赖图。
function(CollectTestLinkClosure target out_var)
    set(_pending "${target}")
    set(_visited)
    set(_closure)
    while(_pending)
        list(GET _pending 0 _current)
        list(REMOVE_AT _pending 0)
        list(FIND _visited "${_current}" _seen)
        if(NOT _seen EQUAL -1 OR NOT TARGET "${_current}")
            continue()
        endif()
        list(APPEND _visited "${_current}")
        foreach(_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(_dependencies "${_current}" ${_property})
            if(NOT _dependencies OR _dependencies MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_dependency IN LISTS _dependencies)
                if(_dependency MATCHES "^\\$<")
                    continue()
                endif()
                if(_dependency MATCHES "^(PrismStaticLibrary|Preview[A-Za-z0-9]+|ProductionTestSupport|ContractTestSupport)$" AND
                   TARGET "${_dependency}")
                    list(APPEND _closure "${_dependency}")
                    list(APPEND _pending "${_dependency}")
                endif()
            endforeach()
        endforeach()
    endwhile()
    list(REMOVE_DUPLICATES _closure)
    set(${out_var} "${_closure}" PARENT_SCOPE)
endfunction()

function(AssertTestLinkBoundaries)
    if(TARGET TestSupport)
        message(FATAL_ERROR "Legacy TestSupport target must not be defined")
    endif()
    foreach(_mode IN ITEMS Production Preview Contract)
        get_property(_targets GLOBAL PROPERTY Prism${_mode}TestTargets)
        foreach(_target IN LISTS _targets)
            CollectTestLinkClosure(${_target} _closure)
            list(FIND _closure PrismStaticLibrary _has_psm)
            if("${_mode}" STREQUAL "Preview" AND _has_psm GREATER -1)
                message(FATAL_ERROR "Preview test ${_target} transitively links PrismStaticLibrary: ${_closure}")
            endif()
            if("${_mode}" STREQUAL "Production" AND _has_psm EQUAL -1)
                message(FATAL_ERROR "Production test ${_target} does not link PrismStaticLibrary: ${_closure}")
            endif()
            if("${_mode}" STREQUAL "Production")
                foreach(_dependency IN LISTS _closure)
                    if(_dependency MATCHES "^Preview")
                        message(FATAL_ERROR "Production test ${_target} links Preview target ${_dependency}")
                    endif()
                endforeach()
            endif()
            if("${_mode}" STREQUAL "Contract")
                if(_has_psm EQUAL -1)
                    message(FATAL_ERROR "Contract test ${_target} does not link PrismStaticLibrary")
                endif()
                set(_has_preview FALSE)
                foreach(_dependency IN LISTS _closure)
                    if(_dependency MATCHES "^Preview")
                        set(_has_preview TRUE)
                    endif()
                endforeach()
                if(NOT _has_preview)
                    message(FATAL_ERROR "Contract test ${_target} has no Preview dependency")
                endif()
            endif()
        endforeach()
    endforeach()
    message(STATUS "AssertTestLinkBoundaries passed: production/preview/contract link closures checked")
endfunction()

function(AssertProductionSourceBoundaries)
    get_property(_sources GLOBAL PROPERTY PrismProductionTestSources)
    foreach(_source IN LISTS _sources)
        if(NOT EXISTS "${_source}")
            message(FATAL_ERROR "Production test source does not exist: ${_source}")
        endif()
        file(READ "${_source}" _content)
        if(_content MATCHES "#[ \t]*include[ \t]*[<\"]preview/")
            message(FATAL_ERROR
                "Production test source directly includes Preview headers: ${_source}")
        endif()
    endforeach()
    message(STATUS "AssertProductionSourceBoundaries passed: no Production test includes Preview")
endfunction()

# 生产 Foundation 只能理解自身 fault 与系统错误；Preview 协议分类及其
# 数字映射必须停留在 Preview/Composition 边界，避免 psm 反向耦合 Preview。
function(AssertProductionFoundationBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/include/prism/foundation/fault/handling.hpp"
         _production_fault_handling)
    if(_production_fault_handling MATCHES "prism\\.protocol|<preview/|Preview::")
        message(FATAL_ERROR
            "Production Foundation must not depend on Preview protocol categories: "
            "include/prism/foundation/fault/handling.hpp")
    endif()
    message(STATUS "AssertProductionFoundationBoundaries passed: production Foundation is Preview-independent")
endfunction()

function(AssertPreviewProductionBoundaries)
    get_property(_preview_targets DIRECTORY "${CMAKE_SOURCE_DIR}/preview" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_target IN LISTS _preview_targets)
        if(NOT _target MATCHES "^Preview" OR
           _target MATCHES "^PreviewTestSupport$")
            continue()
        endif()
        CollectTestLinkClosure(${_target} _closure)
        foreach(_dependency IN LISTS _closure)
            if(_dependency MATCHES "^(PreviewTestSupport|ProductionTestSupport|ContractTestSupport)$")
                message(FATAL_ERROR
                    "Preview production target ${_target} transitively links test support: ${_closure}")
            endif()
        endforeach()
    endforeach()
    message(STATUS "AssertPreviewProductionBoundaries passed: Preview production closures checked")
endfunction()

function(AssertPreviewDnsResolverBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/preview/Net/Dns/Resolver.hpp" _preview_resolver_source)
    if(_preview_resolver_source MATCHES "\\[this, *&name")
        message(FATAL_ERROR
            "Preview DNS OS resolver must not capture Resolver or borrowed name: "
            "preview/Net/Dns/Resolver.hpp")
    endif()
    message(STATUS "AssertPreviewDnsResolverBoundaries passed: OS resolver captures are value-owned")
endfunction()

function(AssertProductionDnsConcurrentBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/src/prism/net/dns/upstream.cpp" _production_upstream_source)
    if(_production_upstream_source MATCHES "\\[this, *&server")
        message(FATAL_ERROR
            "Production DNS concurrent workers must not capture borrowed server state: "
            "src/prism/net/dns/upstream.cpp")
    endif()
    message(STATUS "AssertProductionDnsConcurrentBoundaries passed: concurrent DNS inputs are value-owned")
endfunction()

function(AssertPreviewIdentityTrafficBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/preview/Runtime/Statistics.hpp" _statistics_source)
    string(FIND "${_statistics_source}" "class IdentityTraffic" _identity_start)
    string(FIND "${_statistics_source}" "class TrafficCounter" _identity_end)
    if(_identity_start LESS 0 OR _identity_end LESS 0 OR _identity_end LESS _identity_start)
        message(FATAL_ERROR "Cannot locate IdentityTraffic section in preview/Runtime/Statistics.hpp")
    endif()
    math(EXPR _identity_length "${_identity_end} - ${_identity_start}")
    string(SUBSTRING "${_statistics_source}" ${_identity_start} ${_identity_length}
           _identity_section)
    if(_identity_section MATCHES "std::mutex|lock_guard|scoped_lock|unique_lock")
        message(FATAL_ERROR
            "IdentityTraffic must use atomic COW snapshots without blocking locks: "
            "preview/Runtime/Statistics.hpp")
    endif()
    message(STATUS "AssertPreviewIdentityTrafficBoundaries passed: IdentityTraffic is lock-free COW")
endfunction()

function(AssertMuxAsyncDriverBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/tests/multiplex/core/MuxUploadSim.cpp" _mux_upload_source)
    if(_mux_upload_source MATCHES "\\.poll\\(|run_for\\(")
        message(FATAL_ERROR
            "MuxUploadSim must use event-driven io_context.run() draining, not poll/run_for: "
            "tests/multiplex/core/MuxUploadSim.cpp")
    endif()
    message(STATUS "AssertMuxAsyncDriverBoundaries passed: MuxUploadSim uses run() only")
endfunction()

function(AssertStealthExecutorAsyncBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/tests/preview/protocols/stealth/executor/StealthExecutorDeep3.cpp"
         _stealth_executor_source)
    if(_stealth_executor_source MATCHES "\\[&\\][ \\t]*\\([ \\t]*\\)[ \\t]*->[ \\t]*net::awaitable")
        message(FATAL_ERROR
            "StealthExecutorDeep3 must use named coroutine functions, not temporary capturing coroutine lambdas")
    endif()
    message(STATUS "AssertStealthExecutorAsyncBoundaries passed: executor coroutines have stable ownership")
endfunction()

function(AssertContractAsyncBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/tests/Contract/TransportContractTest.cpp" _contract_source)
    if(_contract_source MATCHES "\\[[^]]*\\][ \\t]*\\([^)]*\\)[ \\t]*->[ \\t]*net::awaitable")
        message(FATAL_ERROR
            "TransportContractTest must use named coroutine functions, not temporary capturing coroutine lambdas")
    endif()
    message(STATUS "AssertContractAsyncBoundaries passed: contract coroutines have stable ownership")
endfunction()

function(AssertMuxWriteAsyncBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/tests/preview/protocols/mux/core/MuxWriteContract.cpp"
         _mux_write_source)
    if(_mux_write_source MATCHES "\\[[^]]*\\][ \\t]*\\([^)]*\\)[ \\t]*->[ \\t]*net::awaitable")
        message(FATAL_ERROR
            "MuxWriteContract must use named coroutine functions, not temporary capturing coroutine lambdas")
    endif()
    message(STATUS "AssertMuxWriteAsyncBoundaries passed: Mux write coroutines have stable ownership")
endfunction()

add_subdirectory(crypto)
add_subdirectory(dns)
add_subdirectory(common)
add_subdirectory(Contract)
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
add_subdirectory(preview)
add_subdirectory(integration)
add_subdirectory(concurrency)
add_subdirectory(stress)
add_subdirectory(perf)

AssertTestLinkBoundaries()
AssertProductionSourceBoundaries()
AssertProductionFoundationBoundaries()
AssertPreviewProductionBoundaries()
AssertPreviewDnsResolverBoundaries()
AssertProductionDnsConcurrentBoundaries()
AssertPreviewIdentityTrafficBoundaries()
AssertMuxAsyncDriverBoundaries()
AssertStealthExecutorAsyncBoundaries()
AssertContractAsyncBoundaries()
AssertMuxWriteAsyncBoundaries()

# 协议测试公共库（header-only，纯逻辑客户端/服务端实现）

# --- Go 协议兼容性测试（真实 quic-go / sing-quic 客户端，与 mihomo 同栈） ---
# 每个协议独立目录（tests/go/<protocol>/main.go），构建为独立可执行，
# ctest 运行时由 run_go_test.ps1 启动 Prism（显式配置路径）再运行测试。
find_program(GO_EXECUTABLE go)
if(GO_EXECUTABLE AND MINGW)
    set(_GoSrcDir ${CMAKE_CURRENT_SOURCE_DIR}/go)
    set(_GoBinDir ${CMAKE_BINARY_DIR}/tests/go)
    file(MAKE_DIRECTORY ${_GoBinDir})
    set(_GoTestTargets)

    # --- handshake 方案字节级对照工具（纯逻辑，无 Prism 依赖） ---
    # realitycmp / shadowtlscmp / restlscmp / anytlscmp / trusttunnelcmp / wscmp / guncmp
    set(_GoCmpSources realitycmp shadowtlscmp restlscmp anytlscmp trusttunnelcmp wscmp guncmp)
    set(_GoCmpTargets GoCmpReality GoCmpShadowtls GoCmpRestls GoCmpAnytls
                        GoCmpTrusttunnel GoCmpWs GoCmpGun)
    list(LENGTH _GoCmpSources _GoCmpCount)
    math(EXPR _GoCmpLast "${_GoCmpCount} - 1")
    foreach(_Index RANGE 0 ${_GoCmpLast})
        list(GET _GoCmpSources ${_Index} _CmpSource)
        list(GET _GoCmpTargets ${_Index} _CmpTarget)
        add_custom_target(${_CmpTarget} ALL
            COMMAND ${GO_EXECUTABLE} build -o ${_GoBinDir}/${_CmpSource}.exe ./${_CmpSource}
            WORKING_DIRECTORY ${_GoSrcDir}
            COMMENT "Building Go ${_CmpSource} reference tool"
            VERBATIM)
        add_test(NAME ${_CmpTarget}
            COMMAND ${_GoBinDir}/${_CmpSource}.exe)
        set_tests_properties(${_CmpTarget} PROPERTIES TIMEOUT 30)
    endforeach()

    set(_GoProtoSources hysteria2 tuic)
    set(_GoProtoTargets GoTestHysteria2 GoTestTuic)
    list(LENGTH _GoProtoSources _GoProtoCount)
    math(EXPR _GoProtoLast "${_GoProtoCount} - 1")
    foreach(_Index RANGE 0 ${_GoProtoLast})
        list(GET _GoProtoSources ${_Index} _ProtoSource)
        list(GET _GoProtoTargets ${_Index} _ProtoTarget)
        add_custom_target(${_ProtoTarget} ALL
            COMMAND ${GO_EXECUTABLE} build -o ${_GoBinDir}/${_ProtoSource}.exe ./${_ProtoSource}
            WORKING_DIRECTORY ${_GoSrcDir}
            COMMENT "Building Go ${_ProtoSource} compatibility test"
            VERBATIM)
        list(APPEND _GoTestTargets ${_ProtoTarget})
    endforeach()
    # vmess_client 依赖 go.mod 中 mihomo 的 replace 指向的本机源码目录；
    # 该目录不存在（如 CI 干净环境）时跳过注册，避免 ALL 构建失败
    set(_vmess_available OFF)
    if(EXISTS ${_GoSrcDir}/go.mod)
        file(READ ${_GoSrcDir}/go.mod _vmess_gomod)
        if(_vmess_gomod MATCHES "replace[ \t]+github.com/metacubex/mihomo[ \t]*=>[ \t]*([^\r\n]+)")
            set(_vmess_replace_dir "${CMAKE_MATCH_1}")
            string(STRIP "${_vmess_replace_dir}" _vmess_replace_dir)
            if(EXISTS "${_vmess_replace_dir}")
                set(_vmess_available ON)
            endif()
        endif()
    endif()

    if(_vmess_available)
        add_custom_target(GoTestVmess ALL
            COMMAND ${GO_EXECUTABLE} build -o ${_GoBinDir}/vmess_client.exe ./vmess_client
            WORKING_DIRECTORY ${_GoSrcDir}
            COMMENT "Building Go vmess compatibility test"
            VERBATIM)
        list(APPEND _GoTestTargets GoTestVmess)
    else()
        message(STATUS "Go vmess_client skipped: mihomo replace dir not available")
    endif()
    add_custom_target(GoTestSingVmess ALL
        COMMAND ${GO_EXECUTABLE} build -o ${_GoBinDir}/singvmess.exe ./singvmess
        WORKING_DIRECTORY ${_GoSrcDir}
        COMMENT "Building Go sing-vmess compatibility test"
        VERBATIM)
    list(APPEND _GoTestTargets GoTestSingVmess)

    set(_GoPrismExe ${CMAKE_BINARY_DIR}/src/Prism.exe)
    set(_GoPrismConfig ${CMAKE_SOURCE_DIR}/src/configuration.json)
    set(_GoRunner ${_GoSrcDir}/run_go_test.ps1)
    set(_GoCompatTargets GoCompatHysteria2 GoCompatTuic)
    list(LENGTH _GoProtoSources _GoCompatCount)
    math(EXPR _GoCompatLast "${_GoCompatCount} - 1")
    foreach(_Index RANGE 0 ${_GoCompatLast})
        list(GET _GoProtoSources ${_Index} _ProtoSource)
        list(GET _GoCompatTargets ${_Index} _CompatTarget)
        add_test(NAME ${_CompatTarget}
            COMMAND powershell -ExecutionPolicy Bypass -File ${_GoRunner}
                    -GoExe ${_GoBinDir}/${_ProtoSource}.exe
                    -PrismExe ${_GoPrismExe}
                    -Config ${_GoPrismConfig})
        set_tests_properties(${_CompatTarget} PROPERTIES TIMEOUT 60)
    endforeach()
    if(_vmess_available)
        add_test(NAME GoCompatVmess
            COMMAND powershell -ExecutionPolicy Bypass -File ${_GoRunner}
                    -GoExe ${_GoBinDir}/vmess_client.exe
                    -PrismExe ${_GoPrismExe}
                    -Config ${_GoPrismConfig})
        set_tests_properties(GoCompatVmess PROPERTIES TIMEOUT 60)
    endif()
    add_test(NAME GoCompatSingVmess
        COMMAND powershell -ExecutionPolicy Bypass -File ${_GoRunner}
                -GoExe ${_GoBinDir}/singvmess.exe
                -PrismExe ${_GoPrismExe}
                -Config ${_GoPrismConfig})
    set_tests_properties(GoCompatSingVmess PROPERTIES TIMEOUT 60)
endif()
