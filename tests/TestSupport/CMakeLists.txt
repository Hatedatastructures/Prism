# 测试支持设施按实现边界拆分；任何 Preview 生产 target 都不得依赖这些 target。

add_library(PreviewTestSupport INTERFACE)
ConfigurePreviewTarget(PreviewTestSupport)
target_compile_definitions(PreviewTestSupport INTERFACE
        PRISM_TEST_REPO_ROOT="${CMAKE_SOURCE_DIR}")
target_sources(PreviewTestSupport INTERFACE
        Fixtures/RuntimeTestHelpers.hpp
        Fixtures/TaskRegistryAccess.hpp
        Fixtures/RecognitionWire.hpp
        Fixtures/StreamFactory.hpp
        Fixtures/MuxRoot.hpp
        Preview/PreviewMockTransport.hpp
        Preview/ProviderBindings.hpp
        Preview/QuicFactory.hpp
        Preview/QuicStreamProviderActivity.hpp
        Preview/DiagnoseTestEnvironment.hpp
        Tls/MockTlsServer.hpp
        Benchmark/Bench.hpp
        Stress/StressHelper.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Quic/GatewayCommon.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Route.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/SchemeExecutor.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/ProbeRecognition.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Runtime/Recognition/ProbeDefense.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Net/Route/Route.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Net/Outbound/Outbound.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Scheduler/Detail/FixedTable.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Scheduler/FairScheduler.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Scheduler/PriorityScheduler.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Scheduler/Scheduler.hpp
        ${CMAKE_SOURCE_DIR}/tests/Experiments/Preview/Scheduler/Types.hpp
)
target_include_directories(PreviewTestSupport INTERFACE
        ${CMAKE_SOURCE_DIR}/Preview
        ${CMAKE_SOURCE_DIR}/tests
)
target_link_libraries(PreviewTestSupport INTERFACE
        PreviewFoundation
        PreviewProtocolsCommon
        OpenSSL::SSL
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly
)

add_library(ProductionTestSupport INTERFACE)
ConfigureProductionTestSupportTarget(ProductionTestSupport)
target_sources(ProductionTestSupport INTERFACE
        Runner/TestRunner.hpp
        Production/ProductionMockTransport.hpp
)
target_include_directories(ProductionTestSupport INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(ProductionTestSupport INTERFACE
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly
)

add_library(ContractTestSupport INTERFACE)
target_link_libraries(ContractTestSupport INTERFACE
        PreviewTestSupport
        ProductionTestSupport
)
