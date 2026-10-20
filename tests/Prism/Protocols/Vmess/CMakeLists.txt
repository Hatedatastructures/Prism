# vmess 子模块测试
AddPrismTest(VmessBeastTest.cpp)
target_link_libraries(VmessBeastTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(VmessClientServerPerf.cpp)
    target_link_libraries(VmessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVmess)
endif()
AddPrismTest(VmessCodecDeep.cpp)
target_link_libraries(VmessCodecDeep PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(VmessConnErrorMatrix.cpp)
target_link_libraries(VmessConnErrorMatrix PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessConnErrorMatrix PRIVATE VmessConnSessionSupport.hpp)
AddPrismTest(VmessConnTerminalReadTest.cpp)
target_link_libraries(VmessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(VmessDatagramTerminalTest.cpp)
target_link_libraries(VmessDatagramTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismProtocolsCommon
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(VmessConnSession.cpp)
target_link_libraries(VmessConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismRuntime
    PrismTransport
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolVmess)
target_sources(VmessConnSession PRIVATE VmessConnSessionSupport.hpp)
AddPrismTest(VmessDgramSession.cpp)
target_link_libraries(VmessDgramSession PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDgramSession PRIVATE VmessConnSessionSupport.hpp)
AddPrismTest(VmessChunkOwnershipAuditTest.cpp)
target_link_libraries(VmessChunkOwnershipAuditTest PRIVATE PrismProtocolVmess)
AddPrismTest(VmessDatagramErrorTest.cpp)
target_link_libraries(VmessDatagramErrorTest PRIVATE PrismAccount PrismFoundation PrismNet PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDatagramErrorTest PRIVATE VmessConnSessionSupport.hpp)
target_compile_options(VmessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(VmessCodecFuzzTest.cpp)
target_link_libraries(VmessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(VmessGoldenVectorTest.cpp)
target_link_libraries(VmessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(VmessStressTest.cpp)
    target_link_libraries(VmessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVmess)
endif()
target_compile_options(VmessCodecDeep PRIVATE -O0 -fno-inline)
