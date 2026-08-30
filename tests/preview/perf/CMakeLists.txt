# preview 性能基准（独立可执行，非 gtest）
# 结果门禁：断链/死循环/完全退化 → 退出码非零。ctest 注册为 perf 标签（
# 有超时门禁，不随默认全量回归跑；单独执行：ctest -L perf）。

if(NOT PRISM_ENABLE_BENCHMARK)
    message(STATUS "Preview performance tests disabled (PRISM_ENABLE_BENCHMARK=OFF)")
    return()
endif()

set(_PERF_TIMEOUT 600)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(_perf_compile_options -g1 -Os)
else()
    set(_perf_compile_options)
endif()

add_executable(AllProtoTransfer AllProtoTransfer.cpp)
target_compile_options(AllProtoTransfer PRIVATE ${_perf_compile_options})
target_link_libraries(AllProtoTransfer PRIVATE vmtest_common)
add_test(NAME Perf_AllProtoTransfer COMMAND AllProtoTransfer)
set_tests_properties(Perf_AllProtoTransfer PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ChunkLimit ChunkLimit.cpp)
target_compile_options(ChunkLimit PRIVATE ${_perf_compile_options})
target_link_libraries(ChunkLimit PRIVATE vmtest_common)
add_test(NAME Perf_ChunkLimit COMMAND ChunkLimit)
set_tests_properties(Perf_ChunkLimit PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(CodecPerf CodecPerf.cpp)
target_compile_options(CodecPerf PRIVATE ${_perf_compile_options})
target_link_libraries(CodecPerf PRIVATE vmtest_common)
add_test(NAME Perf_CodecPerf COMMAND CodecPerf)
set_tests_properties(Perf_CodecPerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ConcurrentBench ConcurrentBench.cpp)
target_compile_options(ConcurrentBench PRIVATE ${_perf_compile_options})
target_link_libraries(ConcurrentBench PRIVATE vmtest_common)
add_test(NAME Perf_ConcurrentBench COMMAND ConcurrentBench)
set_tests_properties(Perf_ConcurrentBench PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(CorePerf CorePerf.cpp)
target_compile_options(CorePerf PRIVATE ${_perf_compile_options})
target_link_libraries(CorePerf PRIVATE vmtest_common benchmark::benchmark)
add_test(NAME Perf_CorePerf COMMAND CorePerf --benchmark_min_time=0.1s)
set_tests_properties(Perf_CorePerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(MultiConnLinear MultiConnLinear.cpp)
target_compile_options(MultiConnLinear PRIVATE ${_perf_compile_options})
target_link_libraries(MultiConnLinear PRIVATE vmtest_common)
add_test(NAME Perf_MultiConnLinear COMMAND MultiConnLinear)
set_tests_properties(Perf_MultiConnLinear PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ProtocolTransferBench ProtocolTransferBench.cpp)
target_compile_options(ProtocolTransferBench PRIVATE ${_perf_compile_options})
target_link_libraries(ProtocolTransferBench PRIVATE vmtest_common)
add_test(NAME Perf_ProtocolTransferBench COMMAND ProtocolTransferBench)
set_tests_properties(Perf_ProtocolTransferBench PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(TransferPerf TransferPerf.cpp)
target_compile_options(TransferPerf PRIVATE ${_perf_compile_options})
target_link_libraries(TransferPerf PRIVATE vmtest_common)
add_test(NAME Perf_TransferPerf COMMAND TransferPerf)
set_tests_properties(Perf_TransferPerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(VmessDepth VmessDepth.cpp)
target_compile_options(VmessDepth PRIVATE ${_perf_compile_options})
target_link_libraries(VmessDepth PRIVATE vmtest_common)
add_test(NAME Perf_VmessDepth COMMAND VmessDepth)
set_tests_properties(Perf_VmessDepth PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(VmessMultiThread VmessMultiThread.cpp)
target_compile_options(VmessMultiThread PRIVATE ${_perf_compile_options})
target_link_libraries(VmessMultiThread PRIVATE vmtest_common)
add_test(NAME Perf_VmessMultiThread COMMAND VmessMultiThread)
set_tests_properties(Perf_VmessMultiThread PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# DNS 解析子系统对标基准（对标 benchmarks/ DnsCacheBench/DnsMessageBench/ResolveBench）
add_executable(DnsPerf DnsPerf.cpp)
target_compile_options(DnsPerf PRIVATE ${_perf_compile_options})
target_link_libraries(DnsPerf PRIVATE vmtest_common)
add_test(NAME Perf_Dns COMMAND DnsPerf)
set_tests_properties(Perf_Dns PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})
