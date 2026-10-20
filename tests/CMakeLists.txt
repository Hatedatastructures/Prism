cmake_minimum_required(VERSION 3.23)

include(GoogleTest)

set(_prism_test_main ${CMAKE_SOURCE_DIR}/tests/TestSupport/Runner/PrismGtestMain.cpp)

function(AddPrismTest source_file)
    get_filename_component(test_name ${source_file} NAME_WE)
    if(NOT test_name MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Prism test target must be PascalCase: ${test_name}")
    endif()
    if(TARGET ${test_name})
        message(FATAL_ERROR "Duplicate Prism test target name: ${test_name}")
    endif()

    add_executable(${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
    target_sources(${test_name} PRIVATE ${_prism_test_main})
    target_include_directories(${test_name} BEFORE PRIVATE
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/Include)
    target_link_libraries(${test_name} PRIVATE GTest::gtest PrismTestSupport)

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${test_name} PRIVATE -g1 -Os)
    endif()

    if("${source_file}" MATCHES "StressTest")
        set(_test_labels LABELS stress)
    elseif("${source_file}" MATCHES "Perf")
        set(_test_labels LABELS perf)
    else()
        set(_test_labels)
    endif()

    if("${test_name}" STREQUAL "SessionLifecycleTest" OR
       "${test_name}" STREQUAL "SessionServicesTest" OR
       "${test_name}" STREQUAL "SessionControlLifecycleTest" OR
       "${test_name}" STREQUAL "SessionDeliveryLifecycleTest")
        set(_test_prefix TEST_PREFIX "SessionLifecycleTest.")
    elseif("${test_name}" STREQUAL "RuntimeSnapshotTest")
        set(_test_prefix TEST_PREFIX "RuntimeSnapshotTest.")
    else()
        set(_test_prefix)
    endif()

    if(MINGW)
        target_compile_options(${test_name} PRIVATE -Wa,-mbig-obj -fno-keep-inline-dllexport)
        set_target_properties(${test_name} PROPERTIES
            ENABLE_EXPORTS OFF
            CROSSCOMPILING_EMULATOR ""
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
        get_filename_component(_test_runtime_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
        gtest_discover_tests(${test_name}
            ${_test_prefix}
            PROPERTIES TIMEOUT 60
                       ${_test_labels}
                       ENVIRONMENT "PATH=${_test_runtime_bin};C:/Windows/System32;C:/Windows"
            DISCOVERY_MODE PRE_TEST)
    else()
        gtest_discover_tests(${test_name}
            ${_test_prefix}
            PROPERTIES TIMEOUT 60
                       ${_test_labels}
            DISCOVERY_MODE PRE_TEST)
    endif()
    set_property(GLOBAL APPEND PROPERTY PrismTestTargets ${test_name})
endfunction()

function(AddExperimentTest source_file)
    get_filename_component(test_name ${source_file} NAME_WE)
    if(NOT test_name MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Experiment test target must be PascalCase: ${test_name}")
    endif()
    set(experiment_target Experiment${test_name})
    if(TARGET ${experiment_target})
        message(FATAL_ERROR "Duplicate experiment test target name: ${experiment_target}")
    endif()

    add_executable(${experiment_target} ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
    target_sources(${experiment_target} PRIVATE ${_prism_test_main})
    target_include_directories(${experiment_target} BEFORE PRIVATE
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/Include)
    target_link_libraries(${experiment_target} PRIVATE GTest::gtest PrismTestSupport)

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${experiment_target} PRIVATE -g1 -Os)
    endif()

    if(MINGW)
        target_compile_options(${experiment_target} PRIVATE -Wa,-mbig-obj -fno-keep-inline-dllexport)
        set_target_properties(${experiment_target} PROPERTIES
            ENABLE_EXPORTS OFF
            CROSSCOMPILING_EMULATOR ""
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
        get_filename_component(_experiment_test_runtime_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
        gtest_discover_tests(${experiment_target}
            PROPERTIES TIMEOUT 60
                       LABELS experiment
                       ENVIRONMENT "PATH=${_experiment_test_runtime_bin};C:/Windows/System32;C:/Windows"
            DISCOVERY_MODE PRE_TEST)
    else()
        gtest_discover_tests(${experiment_target}
            PROPERTIES TIMEOUT 60
                       LABELS experiment
            DISCOVERY_MODE PRE_TEST)
    endif()
    set_property(GLOBAL APPEND PROPERTY PrismTestTargets ${experiment_target})
endfunction()

function(CollectPrismLinkClosure target out_var)
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
                if(_dependency MATCHES "^(Prism[A-Za-z0-9]*|PrismTestSupport|PrismStaticLibrary|ProductionTestSupport|ContractTestSupport)$" AND
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

function(AssertPrismTestBoundaries)
    get_property(_test_targets GLOBAL PROPERTY PrismTestTargets)
    if(NOT _test_targets)
        message(FATAL_ERROR "Prism test tree registered no GoogleTest targets")
    endif()
    foreach(_target IN LISTS _test_targets)
        get_target_property(_direct_links "${_target}" LINK_LIBRARIES)
        list(FIND _direct_links PrismTestSupport _has_support)
        if(_has_support EQUAL -1)
            message(FATAL_ERROR "Prism test ${_target} does not link PrismTestSupport")
        endif()
        CollectPrismLinkClosure(${_target} _closure)
        foreach(_dependency IN LISTS _closure)
            if(_dependency MATCHES "^(PrismStaticLibrary|ProductionTestSupport|ContractTestSupport)$")
                message(FATAL_ERROR "Prism test ${_target} links retired target ${_dependency}")
            endif()
        endforeach()
    endforeach()
    message(STATUS "AssertPrismTestBoundaries passed: tests link only Prism production and support targets")
endfunction()

function(AssertPrismProductionBoundaries)
    CollectPrismDirectoryTargets("${CMAKE_SOURCE_DIR}/Src/Prism" _production_targets)
    foreach(_target IN LISTS _production_targets)
        if(NOT _target MATCHES "^Prism")
            continue()
        endif()
        CollectPrismLinkClosure(${_target} _closure)
        if("PrismTestSupport" IN_LIST _closure)
            message(FATAL_ERROR "Prism production target ${_target} transitively links test support")
        endif()
    endforeach()
    message(STATUS "AssertPrismProductionBoundaries passed: production targets exclude test support")
endfunction()

function(AssertPrismDnsResolverBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/Include/Prism/Net/Dns/Resolver.hpp" _resolver_source)
    if(_resolver_source MATCHES "\\[this, *&name")
        message(FATAL_ERROR "Prism DNS resolver must not capture Resolver or borrowed name")
    endif()
    message(STATUS "AssertPrismDnsResolverBoundaries passed: DNS resolver inputs are value-owned")
endfunction()

function(AssertPrismTrafficBoundaries)
    file(READ "${CMAKE_SOURCE_DIR}/Include/Prism/Runtime/Statistics.hpp" _statistics_header)
    file(READ "${CMAKE_SOURCE_DIR}/Src/Prism/Runtime/Statistics.cpp" _statistics_implementation)
    if(_statistics_header MATCHES "class (IdentityTraffic|PerWorkerTraffic)|unordered_map<.*string|std::mutex|lock_guard|scoped_lock|unique_lock")
        message(FATAL_ERROR "Prism traffic must use numeric ownership and avoid blocking locks")
    endif()
    set(_statistics_contract "${_statistics_header}\n${_statistics_implementation}")
    if(NOT _statistics_contract MATCHES "boost::lockfree::queue" OR
       NOT _statistics_contract MATCHES "bounded_push" OR
       NOT _statistics_contract MATCHES "capacity<1024>")
        message(FATAL_ERROR "Prism traffic must retain its preallocated bounded observation queue")
    endif()
    message(STATUS "AssertPrismTrafficBoundaries passed: bounded numeric traffic observations")
endfunction()

add_subdirectory(Prism)

option(PRISM_ENABLE_EXPERIMENT_TESTS "Build independent Prism experiment tests" OFF)
if(PRISM_ENABLE_EXPERIMENT_TESTS)
    add_subdirectory(Experiments)
endif()

AssertPrismTestBoundaries()
AssertPrismProductionBoundaries()
AssertPrismDnsResolverBoundaries()
AssertPrismTrafficBoundaries()

if(PRISM_ENABLE_INTEROP)
    find_program(PRISM_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
    if(NOT PRISM_POWERSHELL_EXECUTABLE)
        message(FATAL_ERROR "PRISM_ENABLE_INTEROP requires pwsh or powershell")
    endif()
    add_test(NAME PrismInteropMatrix
        COMMAND ${PRISM_POWERSHELL_EXECUTABLE} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_SOURCE_DIR}/scripts/interop/Run-Matrix.ps1
                -RepoRoot ${CMAKE_SOURCE_DIR}
                -OutputDirectory ${CMAKE_BINARY_DIR}/prism-interop-results
                -PrismExe $<TARGET_FILE:Prism>)
    set_tests_properties(PrismInteropMatrix PROPERTIES
        LABELS interop
        TIMEOUT 900
        RUN_SERIAL TRUE)
endif()
