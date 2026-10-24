# vmess 子模块测试
AddPrismTest(Codec/VmessBeastTest.cpp)
target_link_libraries(VmessBeastTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/VmessClientServerPerf.cpp)
    target_link_libraries(VmessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVmess)
endif()
AddPrismTest(Codec/VmessCodecDeep.cpp)
target_link_libraries(VmessCodecDeep PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(Connection/VmessConnErrorMatrix.cpp)
target_link_libraries(VmessConnErrorMatrix PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessConnErrorMatrix PRIVATE Connection/VmessConnSessionSupport.hpp)
AddPrismTest(Connection/VmessConnTerminalReadTest.cpp)
target_link_libraries(VmessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(Datagram/VmessDatagramTerminalTest.cpp)
target_link_libraries(VmessDatagramTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismProtocolsCommon
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(Connection/VmessConnSession.cpp)
target_link_libraries(VmessConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismRuntime
    PrismTransport
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolVmess)
target_sources(VmessConnSession PRIVATE Connection/VmessConnSessionSupport.hpp)
AddPrismTest(Datagram/VmessDgramSession.cpp)
target_link_libraries(VmessDgramSession PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDgramSession PRIVATE Connection/VmessConnSessionSupport.hpp)
AddPrismTest(Connection/VmessChunkOwnerTest.cpp)
target_link_libraries(VmessChunkOwnerTest PRIVATE PrismProtocolVmess)
AddPrismTest(Datagram/VmessDatagramErrorTest.cpp)
target_link_libraries(VmessDatagramErrorTest PRIVATE PrismAccount PrismFoundation PrismNet PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDatagramErrorTest PRIVATE Connection/VmessConnSessionSupport.hpp)
target_compile_options(VmessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/VmessCodecFuzzTest.cpp)
target_link_libraries(VmessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(Codec/VmessGoldenVectorTest.cpp)
target_link_libraries(VmessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/VmessStressTest.cpp)
    target_link_libraries(VmessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVmess)
endif()
target_compile_options(VmessCodecDeep PRIVATE -O0 -fno-inline)
