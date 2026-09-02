# 测试支持设施按实现边界拆分；任何 Preview 生产 target 都不得依赖这些 target。

add_library(PreviewTestSupport INTERFACE)
ConfigurePreviewTarget(PreviewTestSupport)
target_sources(PreviewTestSupport INTERFACE
        Fixtures/RuntimeTestHelpers.hpp
        Preview/PreviewMockTransport.hpp
        Tls/MockTlsServer.hpp
        Benchmark/Bench.hpp
        Stress/StressHelper.hpp
)
target_include_directories(PreviewTestSupport INTERFACE
        ${CMAKE_SOURCE_DIR}/preview
        ${CMAKE_SOURCE_DIR}/tests
)
target_link_libraries(PreviewTestSupport INTERFACE
        PreviewFoundation
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
