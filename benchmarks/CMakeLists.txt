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

add_executable(CodecBench CodecBench.cpp)
target_link_libraries(CodecBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(MemoryBench MemoryBench.cpp)
target_link_libraries(MemoryBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(MuxBench MuxBench.cpp)
target_link_libraries(MuxBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(CryptoBench CryptoBench.cpp)
target_link_libraries(CryptoBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(ProtocolBench ProtocolBench.cpp)
target_link_libraries(ProtocolBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(IOBench IOBench.cpp)
target_link_libraries(IOBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(MuxConnBench MuxConnBench.cpp)
target_link_libraries(MuxConnBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(SessionBench SessionBench.cpp)
target_link_libraries(SessionBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(RealityBench RealityBench.cpp)
target_link_libraries(RealityBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(ScaleBench ScaleBench.cpp)
target_link_libraries(ScaleBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(ResourceBench ResourceBench.cpp)
target_link_libraries(ResourceBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(LatencyBench LatencyBench.cpp)
target_link_libraries(LatencyBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(RecognitionBench RecognitionBench.cpp)
target_link_libraries(RecognitionBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(StealthBench StealthBench.cpp)
target_link_libraries(StealthBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(InfraBench InfraBench.cpp)
target_link_libraries(InfraBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(H2MuxBench H2MuxBench.cpp)
target_link_libraries(H2MuxBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(RegressionBench RegressionBench.cpp)
target_link_libraries(RegressionBench PRIVATE ${PROJECT_NAME}_static_library)
target_include_directories(RegressionBench PRIVATE ${PROJECT_SOURCE_DIR}/tests)

add_executable(RealityAuthBench RealityAuthBench.cpp)
target_link_libraries(RealityAuthBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(ResolveBench ResolveBench.cpp)
target_link_libraries(ResolveBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(AnyTLSFrameBench AnyTLSFrameBench.cpp)
target_link_libraries(AnyTLSFrameBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(StealthExtBench StealthExtBench.cpp)
target_link_libraries(StealthExtBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(SsAntiReplayBench SsAntiReplayBench.cpp)
target_link_libraries(SsAntiReplayBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(TlsFrameBench TlsFrameBench.cpp)
target_link_libraries(TlsFrameBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(Socks5FrameBench Socks5FrameBench.cpp)
target_link_libraries(Socks5FrameBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(CryptoMiscBench CryptoMiscBench.cpp)
target_link_libraries(CryptoMiscBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(RecognitionPipeBench RecognitionPipeBench.cpp)
target_link_libraries(RecognitionPipeBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(ConnectPoolBench ConnectPoolBench.cpp)
target_link_libraries(ConnectPoolBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(TrustTunnelBench TrustTunnelBench.cpp)
target_link_libraries(TrustTunnelBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

add_executable(DnsMessageBench DnsMessageBench.cpp)
target_link_libraries(DnsMessageBench PRIVATE ${PROJECT_NAME}_static_library benchmark::benchmark)

if(MINGW)
    foreach(target_name IN ITEMS CodecBench MemoryBench MuxBench CryptoBench ProtocolBench IOBench MuxConnBench SessionBench RealityBench ScaleBench ResourceBench LatencyBench RecognitionBench StealthBench InfraBench H2MuxBench RegressionBench RealityAuthBench ResolveBench AnyTLSFrameBench StealthExtBench SsAntiReplayBench TlsFrameBench Socks5FrameBench CryptoMiscBench RecognitionPipeBench ConnectPoolBench TrustTunnelBench DnsMessageBench)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
