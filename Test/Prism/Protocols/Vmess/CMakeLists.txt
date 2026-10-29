# vmess 子模块测试
AddPrismTest(Codec/BeastTest.cpp VmessBeastTest)
target_link_libraries(VmessBeastTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp VmessClientServerPerf)
    target_link_libraries(VmessClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolVmess)
endif()
AddPrismTest(Codec/Deep.cpp VmessCodecDeep)
target_link_libraries(VmessCodecDeep PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(Connection/ErrorMatrix.cpp VmessConnErrorMatrix)
target_link_libraries(VmessConnErrorMatrix PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessConnErrorMatrix PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Connection/TerminalReadTest.cpp VmessConnTerminalReadTest)
target_link_libraries(VmessConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(Datagram/TerminalTest.cpp VmessDatagramTerminalTest)
target_link_libraries(VmessDatagramTerminalTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismProtocolsCommon
    PrismTransport
    PrismProtocolVmess)
AddPrismTest(Connection/Session.cpp VmessConnSession)
target_link_libraries(VmessConnSession PRIVATE
    PrismAccount
    PrismFoundation
    PrismRuntime
    PrismTransport
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismProtocolVmess)
target_sources(VmessConnSession PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Datagram/Session.cpp VmessDgramSession)
target_link_libraries(VmessDgramSession PRIVATE PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDgramSession PRIVATE Connection/SessionSupport.hpp)
AddPrismTest(Connection/ChunkOwnerTest.cpp VmessChunkOwnerTest)
target_link_libraries(VmessChunkOwnerTest PRIVATE PrismProtocolVmess)
AddPrismTest(Datagram/ErrorTest.cpp VmessDatagramErrorTest)
target_link_libraries(VmessDatagramErrorTest PRIVATE PrismAccount PrismFoundation PrismNet PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVmess)
target_sources(VmessDatagramErrorTest PRIVATE Connection/SessionSupport.hpp)
target_compile_options(VmessDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/CodecFuzzTest.cpp VmessCodecFuzzTest)
target_link_libraries(VmessCodecFuzzTest PRIVATE PrismFoundation PrismProtocolVmess)
AddPrismTest(Codec/GoldenVectorTest.cpp VmessGoldenVectorTest)
target_link_libraries(VmessGoldenVectorTest PRIVATE PrismFoundation PrismProtocolVmess)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/StressTest.cpp VmessStressTest)
    target_link_libraries(VmessStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolVmess)
endif()
target_compile_options(VmessCodecDeep PRIVATE -O0 -fno-inline)
