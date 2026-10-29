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
        Prism/Account/Admission.hpp
        Prism/MockTransport.hpp
        Prism/ProviderBindings.hpp
        Prism/GenerationPublication.hpp
        Prism/Protocol/Ingress.hpp
        Prism/TuicFactoryFixture.hpp
        Prism/Quic/MemoryProvider.hpp
        Prism/QuicFactory.hpp
        Prism/Quic/StreamActivity.hpp
        Prism/Diagnose/Environment.hpp
        Tls/MockTlsServer.hpp
        Benchmark/Bench.hpp
        Stress/StressHelper.hpp)
target_include_directories(PrismTestSupport INTERFACE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/Include
        ${CMAKE_SOURCE_DIR}/Test)
target_link_libraries(PrismTestSupport INTERFACE
        PrismFoundation
        PrismDiagnoseBackend
        PrismProtocolsCommon
        OpenSSL::SSL
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly)
