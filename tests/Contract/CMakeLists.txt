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
