if(NOT PRISM_ENABLE_BENCHMARK)
    message(STATUS "Benchmarks disabled (PRISM_ENABLE_BENCHMARK=OFF)")
    return()
endif()

find_package(benchmark CONFIG QUIET)

if(NOT benchmark_FOUND)
    include(FetchContent)

    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        benchmark
        URL https://github.com/google/benchmark/archive/refs/tags/v1.9.5.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )

    FetchContent_MakeAvailable(benchmark)
endif()

add_executable(codec_bench codec_bench.cpp)
target_link_libraries(codec_bench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(memory_bench memory_bench.cpp)
target_link_libraries(memory_bench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(mux_bench mux_bench.cpp)
target_link_libraries(mux_bench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

if(MINGW)
    foreach(target_name IN ITEMS codec_bench memory_bench mux_bench)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()