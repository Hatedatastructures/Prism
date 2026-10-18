# preview 性能基准（独立可执行，非 gtest）
# 结果门禁：断链/死循环/完全退化 → 退出码非零。ctest 注册为 perf 标签（
# 有超时门禁，不随默认全量回归跑；单独执行：ctest -L perf）。

if(NOT PRISM_ENABLE_BENCHMARK)
    message(STATUS "Preview performance tests disabled (PRISM_ENABLE_BENCHMARK=OFF)")
    return()
endif()

set(_PERF_TIMEOUT 600)
# 无参数的 Perf_Recognition 保留既有 1000/7/10000、HTTP/VLESS 和三模式矩阵；
# --owner-compare 是显式的 8/64/1024、1/2/4、五轮 AB/BA owner 合同入口。
# owner compare 的 A/B 语义和 Session/Configuration production-entry gap 由运行记录输出。
set(_RECOGNITION_PERF_TIMEOUT 1800)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(_perf_compile_options -g1 -Os)
else()
    set(_perf_compile_options)
endif()

add_executable(StatisticsBenchmark StatisticsBenchmark.cpp)
target_compile_options(StatisticsBenchmark PRIVATE ${_perf_compile_options})
target_link_libraries(StatisticsBenchmark PRIVATE PrismStatistics)
add_test(NAME Perf_StatisticsBenchmark COMMAND StatisticsBenchmark)
set_tests_properties(Perf_StatisticsBenchmark PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(AllProtoTransfer AllProtoTransfer.cpp)
target_compile_options(AllProtoTransfer PRIVATE ${_perf_compile_options})
target_link_libraries(AllProtoTransfer PRIVATE PrismTransport PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_AllProtoTransfer COMMAND AllProtoTransfer)
set_tests_properties(Perf_AllProtoTransfer PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ChunkLimit ChunkLimit.cpp)
target_compile_options(ChunkLimit PRIVATE ${_perf_compile_options})
target_link_libraries(ChunkLimit PRIVATE PrismTransport PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_ChunkLimit COMMAND ChunkLimit)
set_tests_properties(Perf_ChunkLimit PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(CodecPerf CodecPerf.cpp)
target_compile_options(CodecPerf PRIVATE ${_perf_compile_options})
target_link_libraries(CodecPerf PRIVATE PrismProtocolHysteria2 PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTrojan PrismProtocolTuic PrismProtocolVless PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_CodecPerf COMMAND CodecPerf)
set_tests_properties(Perf_CodecPerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ConcurrentBench ConcurrentBench.cpp)
target_compile_options(ConcurrentBench PRIVATE ${_perf_compile_options})
target_link_libraries(ConcurrentBench PRIVATE PrismFoundation PrismProtocolSocks5 PrismTestSupport)
add_test(NAME Perf_ConcurrentBench COMMAND ConcurrentBench)
set_tests_properties(Perf_ConcurrentBench PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(CorePerf CorePerf.cpp)
target_compile_options(CorePerf PRIVATE ${_perf_compile_options})
target_link_libraries(CorePerf PRIVATE PrismFoundation PrismProtocolHttp3 PrismTestSupport benchmark::benchmark)
add_test(NAME Perf_CorePerf COMMAND CorePerf --benchmark_min_time=0.1s)
set_tests_properties(Perf_CorePerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(MultiConnLinear MultiConnLinear.cpp)
target_compile_options(MultiConnLinear PRIVATE ${_perf_compile_options})
target_link_libraries(MultiConnLinear PRIVATE PrismTransport PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_MultiConnLinear COMMAND MultiConnLinear)
set_tests_properties(Perf_MultiConnLinear PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ProtocolTransferBench
        ProtocolTransferBench.cpp
        ProtocolTransferBenchAllocation.cpp
        ProtocolTransferBenchChunk.cpp
        ProtocolTransferBenchPreflight.cpp
        ProtocolTransferBenchReport.cpp
        ProtocolTransferBenchRound.cpp
        ProtocolTransferBenchSocks.cpp
        ProtocolTransferBenchSupport.cpp
        ProtocolTransferBenchVmess.cpp
        ProtocolTransferBench.hpp)
target_compile_options(ProtocolTransferBench PRIVATE ${_perf_compile_options})
target_link_libraries(ProtocolTransferBench PRIVATE PrismTransport PrismProtocolSocks5 PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_ProtocolTransferBench COMMAND ProtocolTransferBench)
set_tests_properties(Perf_ProtocolTransferBench PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(TransferPerf
        TransferPerf.cpp
        TransferPerfAllocation.cpp
        TransferPerfTcpBaseline.cpp
        TransferPerfReport.cpp
        TransferPerfRound.cpp
        TransferPerfSupport.cpp
        TransferPerfTransport.cpp
        TransferPerf.hpp)
target_compile_options(TransferPerf PRIVATE ${_perf_compile_options})
target_link_libraries(TransferPerf PRIVATE PrismTransport PrismProtocolSocks5 PrismTestSupport)
add_test(NAME Perf_TransferPerf COMMAND TransferPerf --io-compare)
set_tests_properties(Perf_TransferPerf PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# 独立真实 Mux child lane：保留 TCP transport 对照的类型边界，单独验证
# Mux::Client/Server、StreamTransmission、确定性碎片和 FIN/EOF/drain。
add_executable(TransferPerfMux TransferPerfMux.cpp TransferPerfMuxMain.cpp TransferPerfMux.hpp)
target_compile_options(TransferPerfMux PRIVATE ${_perf_compile_options})
target_link_libraries(TransferPerfMux PRIVATE PrismTransport PrismProtocolMux)
add_test(NAME Perf_TransferPerfMux COMMAND TransferPerfMux)
set_tests_properties(Perf_TransferPerfMux PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(VmessDepth VmessDepth.cpp)
target_compile_options(VmessDepth PRIVATE ${_perf_compile_options})
target_link_libraries(VmessDepth PRIVATE PrismTransport PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_VmessDepth COMMAND VmessDepth)
set_tests_properties(Perf_VmessDepth PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(VmessMultiThread VmessMultiThread.cpp)
target_compile_options(VmessMultiThread PRIVATE ${_perf_compile_options})
target_link_libraries(VmessMultiThread PRIVATE PrismTransport PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_VmessMultiThread COMMAND VmessMultiThread)
set_tests_properties(Perf_VmessMultiThread PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# DNS 解析子系统对标基准（对标 benchmarks/ DnsCacheBench/DnsMessageBench/ResolveBench）
add_executable(DnsPerf
        DnsPerf.cpp
        DnsPerfAllocation.cpp
        DnsPerfCoalescerMetrics.cpp
        DnsPerfCoalescerOwner.cpp
        DnsPerfCoalescerRun.cpp
        DnsPerfRuntime.cpp
        DnsPerfCoalescer.hpp
        DnsPerf.hpp
        DnsPerfRuntime.hpp)
target_compile_options(DnsPerf PRIVATE ${_perf_compile_options})
target_link_libraries(DnsPerf PRIVATE PrismNet PrismTestSupport)
add_test(NAME Perf_Dns COMMAND DnsPerf)
set_tests_properties(Perf_Dns PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# Configuration Parser/Validator baseline; the executable emits fixed-trace A/B records.
add_executable(ConfigurationValidationCompare
        ConfigurationValidationCompare.cpp
        ConfigurationValidationCompare.hpp
        ConfigurationValidationCompareAllocation.cpp
        ConfigurationValidationCompareAllocation.hpp
        ConfigurationValidationCompareScenario.cpp
        ConfigurationValidationCompareScenario.hpp
        ConfigurationValidationCompareMeasure.cpp
        ConfigurationValidationCompareMeasure.hpp
        ConfigurationValidationCompareReport.cpp)
target_compile_options(ConfigurationValidationCompare PRIVATE ${_perf_compile_options})
target_link_libraries(ConfigurationValidationCompare PRIVATE PrismConfiguration PrismComposition)
if(WIN32)
    target_link_libraries(ConfigurationValidationCompare PRIVATE psapi)
endif()
add_test(NAME Perf_ConfigurationValidationCompareValidation
        COMMAND ConfigurationValidationCompare --validate-only)
set_tests_properties(Perf_ConfigurationValidationCompareValidation
        PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# Same-trace DNS cache structure comparison; A/B/C are selected per process.
add_executable(DnsCacheCompare
        DnsCacheCompare.cpp
        DnsCacheCompareAllocation.cpp
        DnsCacheCompareMeasure.cpp
        DnsCacheMeasure.hpp
        DnsCacheScenario.cpp
        DnsCacheScenario.hpp
        DnsCacheVariants.hpp)
target_compile_options(DnsCacheCompare PRIVATE ${_perf_compile_options})
target_link_libraries(DnsCacheCompare PRIVATE PrismNet)
if(WIN32)
    target_link_libraries(DnsCacheCompare PRIVATE psapi)
endif()
add_test(NAME Perf_DnsCacheCompareValidation COMMAND DnsCacheCompare --validate-only)
set_tests_properties(Perf_DnsCacheCompareValidation PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})
add_test(NAME Perf_DnsCacheCompareSmoke
        COMMAND DnsCacheCompare --variant A --capacity 64 --hit-rate 95
                --distribution uniform --executors 1 --operations 1000)
set_tests_properties(Perf_DnsCacheCompareSmoke PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# SessionRegistry A/B/C same-trace comparison.  This is an experiment harness;
# it does not replace Preview/Runtime/SessionRegistry.hpp.
add_executable(SessionRegistryCompare
        SessionRegistryCompare.cpp
        SessionRegistryCompare.hpp
        SessionRegistryCompareCorrectness.cpp
        SessionRegistryCompareCorrectness.hpp
        SessionRegistryCompareMeasure.cpp
        SessionRegistryCompareModelA.cpp
        SessionRegistryCompareModelB.cpp
        SessionRegistryCompareModelC.cpp
        SessionRegistryCompareModels.cpp
        SessionRegistryCompareModels.hpp
        SessionRegistryCompareReport.cpp
        SessionRegistryCompareSampling.cpp
        SessionRegistryCompareSampling.hpp
        SessionRegistryCompareTrace.cpp
        SessionRegistryCompareTrace.hpp)
target_compile_options(SessionRegistryCompare PRIVATE ${_perf_compile_options})
target_link_libraries(SessionRegistryCompare PRIVATE PrismRuntime)
if(WIN32)
    target_link_libraries(SessionRegistryCompare PRIVATE psapi)
endif()
add_test(NAME Perf_SessionRegistryCompareValidation
        COMMAND SessionRegistryCompare --validate-only)
set_tests_properties(Perf_SessionRegistryCompareValidation
        PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# Mailbox 旧实现同 trace 基线；1/2/4 producer 由 CLI 分别运行。
add_executable(MailboxCompare
        MailboxCompare.cpp
        MailboxCompare.hpp
        MailboxCompareMeasure.cpp
        MailboxCompareTrace.cpp
        MailboxCompareTrace.hpp)
target_compile_options(MailboxCompare PRIVATE ${_perf_compile_options})
target_link_libraries(MailboxCompare PRIVATE PrismRuntime)
if(WIN32)
    target_link_libraries(MailboxCompare PRIVATE psapi)
endif()
add_test(NAME Perf_MailboxCompareValidation
        COMMAND MailboxCompare --validate-only)
set_tests_properties(Perf_MailboxCompareValidation
        PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

# TokenBucket 正常路径同 trace 基线；固定 Now 的 1/2/4 线程与单线程补发由 CLI 选择。
add_executable(TokenBucketCompare TokenBucketCompare.cpp)
target_compile_options(TokenBucketCompare PRIVATE ${_perf_compile_options})
target_link_libraries(TokenBucketCompare PRIVATE PrismFoundation)
if(WIN32)
    target_link_libraries(TokenBucketCompare PRIVATE psapi)
endif()
add_test(NAME Perf_TokenBucketCompareValidation
        COMMAND TokenBucketCompare --validate-only)
set_tests_properties(Perf_TokenBucketCompareValidation
        PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(RecognitionPerf
        RecognitionPerf.cpp
        RecognitionPerfAllocation.cpp
        RecognitionPerfOwnerMeasure.cpp
        RecognitionPerfOwnerMeasure.hpp
        RecognitionPerfOwnerTrace.cpp
        RecognitionPerfOwnerWorkers.cpp
        RecognitionPerfPipeline.cpp
        RecognitionPerf.hpp)
target_compile_options(RecognitionPerf PRIVATE ${_perf_compile_options})
target_link_libraries(RecognitionPerf PRIVATE PrismFoundation PrismTransport PrismRuntime PrismComposition PrismBoundary PrismProtocolHttp PrismProtocolVless PrismProtocolVmess PrismTestSupport)
add_test(NAME Perf_Recognition COMMAND RecognitionPerf)
# RecognitionPerf intentionally performs a large warmup/sample matrix; allow
# extra wall time for slower or contended CI hosts without relaxing other perf tests.
set_tests_properties(Perf_Recognition PROPERTIES LABELS perf TIMEOUT ${_RECOGNITION_PERF_TIMEOUT})

add_executable(CompactPathBenchmark DiagnosePathBenchmark.cpp)
target_compile_definitions(CompactPathBenchmark PRIVATE PRISM_DIAGNOSE_COMPACT_BENCHMARK=1)
target_compile_options(CompactPathBenchmark PRIVATE ${_perf_compile_options})
target_link_libraries(CompactPathBenchmark PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)
add_test(NAME Perf_CompactPathBenchmark
        COMMAND CompactPathBenchmark "${CMAKE_BINARY_DIR}/preview-diagnose-compact.json")
set_tests_properties(Perf_CompactPathBenchmark PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})

add_executable(ExtendedPathBenchmark DiagnosePathBenchmark.cpp)
target_compile_definitions(ExtendedPathBenchmark PRIVATE PRISM_DIAGNOSE_EXTENDED_BENCHMARK=1)
target_compile_options(ExtendedPathBenchmark PRIVATE ${_perf_compile_options})
target_link_libraries(ExtendedPathBenchmark PRIVATE
        PrismFoundation PrismTestSupport spdlog::spdlog)
add_test(NAME Perf_ExtendedPathBenchmark_HumanWithFields
        COMMAND ExtendedPathBenchmark HumanWithFields
                "${CMAKE_BINARY_DIR}/preview-diagnose-human-with-fields.json")
add_test(NAME Perf_ExtendedPathBenchmark_Structured
        COMMAND ExtendedPathBenchmark Structured
                "${CMAKE_BINARY_DIR}/preview-diagnose-structured.json")
set_tests_properties(Perf_ExtendedPathBenchmark_HumanWithFields
        Perf_ExtendedPathBenchmark_Structured PROPERTIES LABELS perf TIMEOUT ${_PERF_TIMEOUT})
add_custom_target(PreviewDiagnoseBench DEPENDS CompactPathBenchmark ExtendedPathBenchmark)

# Domain-level benchmark entry points. These depend on existing focused
# executables and are intentionally excluded from the default build.
add_custom_target(PreviewCodecBench DEPENDS CodecPerf CorePerf)
add_custom_target(PreviewTransportBench DEPENDS
        TransferPerf TransferPerfMux ProtocolTransferBench ConcurrentBench)
add_custom_target(PreviewRuntimeBench DEPENDS AllProtoTransfer MultiConnLinear VmessDepth VmessMultiThread)
add_custom_target(PreviewDnsBench DEPENDS DnsPerf DnsCacheCompare)

# 任务身份快照同输入五轮对照；原集合仅作为实验基线，未进入正式生产接口。
add_executable(TaskIdSetCompare
        TaskIdSetCompare.cpp
        TaskIdSetMeasurement.cpp
        TaskIdSetMeasurement.hpp)
target_compile_options(TaskIdSetCompare PRIVATE ${_perf_compile_options})
target_link_libraries(TaskIdSetCompare PRIVATE PrismLifecycle)
add_test(NAME Perf_TaskIdSetCompare COMMAND TaskIdSetCompare)
set_tests_properties(Perf_TaskIdSetCompare PROPERTIES LABELS perf TIMEOUT 1800)
