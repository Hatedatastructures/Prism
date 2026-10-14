# Preview 实验性能工具单独登记，不能混入生产性能目标。
if(NOT PRISM_ENABLE_BENCHMARK)
    message(STATUS "Preview experiment performance tools disabled (PRISM_ENABLE_BENCHMARK=OFF)")
    return()
endif()

set(_EXPERIMENT_PERF_TIMEOUT 600)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(_experiment_perf_compile_options -g1 -Os)
else()
    set(_experiment_perf_compile_options)
endif()

add_executable(PreviewExperimentSchedulerBenchmark SchedulerBenchmark.cpp)
target_compile_options(PreviewExperimentSchedulerBenchmark PRIVATE ${_experiment_perf_compile_options})
target_link_libraries(PreviewExperimentSchedulerBenchmark PRIVATE PreviewFoundation)
add_test(NAME Experiment_Preview_SchedulerBenchmark
         COMMAND PreviewExperimentSchedulerBenchmark)
set_tests_properties(Experiment_Preview_SchedulerBenchmark
        PROPERTIES LABELS "experiment;performance" TIMEOUT ${_EXPERIMENT_PERF_TIMEOUT})
