# psm 与 Preview 的公共协议契约测试
AddContractTest(ProtocolContractTest.cpp)
target_link_libraries(ProtocolContractTest PRIVATE
    PreviewProtocolSocks5
    PreviewProtocolVless
    PreviewProtocolTrojan
    PreviewProtocolVmess
    PreviewProtocolShadowsocks2022)

AddContractTest(TransportContractTest.cpp)
target_link_libraries(TransportContractTest PRIVATE PreviewTransport PreviewNet ContractTestSupport )
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(TransportContractTest PRIVATE -U_FORTIFY_SOURCE)
endif()

AddContractTest(PreviewProductionBridgeTest.cpp)
target_link_libraries(PreviewProductionBridgeTest PRIVATE PreviewRuntime)

AddContractTest(PreviewConfigurationTest.cpp)
target_link_libraries(PreviewConfigurationTest PRIVATE PreviewRuntime)

if(PRISM_ENABLE_PERF_CONTRACT)
    AddContractTest(PerformanceContract.cpp)
    target_link_libraries(PerformanceContract PRIVATE
        PreviewProtocolSocks5
        PreviewProtocolVless
        PreviewProtocolShadowsocks2022)
    if(WIN32)
        target_link_libraries(PerformanceContract PRIVATE psapi)
    endif()
endif()
