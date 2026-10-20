# Prism tests share only Prism-owned fixtures and test transports.
add_library(PrismTestSupport INTERFACE)
target_compile_definitions(PrismTestSupport INTERFACE
        PRISM_TEST_REPO_ROOT="${CMAKE_SOURCE_DIR}")
target_sources(PrismTestSupport INTERFACE
        Fixtures/RuntimeTestHelpers.hpp
        Fixtures/TaskRegistryAccess.hpp
        Fixtures/RecognitionWire.hpp
        Fixtures/StreamFactory.hpp
        Fixtures/MuxRoot.hpp
        Prism/AccountAdmissionAuthority.hpp
        Prism/PrismMockTransport.hpp
        Prism/ProviderBindings.hpp
        Prism/GenerationPublication.hpp
        Prism/ProtocolIngressBindings.hpp
        Prism/TuicFactoryFixture.hpp
        Prism/Quic/MemoryDatagramProvider.hpp
        Prism/QuicFactory.hpp
        Prism/QuicStreamProviderActivity.hpp
        Prism/DiagnoseTestEnvironment.hpp
        Tls/MockTlsServer.hpp
        Benchmark/Bench.hpp
        Stress/StressHelper.hpp)
target_include_directories(PrismTestSupport INTERFACE
        ${CMAKE_SOURCE_DIR}/Include
        ${CMAKE_SOURCE_DIR}/tests)
target_link_libraries(PrismTestSupport INTERFACE
        PrismFoundation
        PrismDiagnoseBackend
        PrismProtocolsCommon
        OpenSSL::SSL
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly)
