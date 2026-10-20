# shadowsocks2022 子模块测试
AddPrismTest(Shadowsocks2022BeastTest.cpp)
target_link_libraries(Shadowsocks2022BeastTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Ss2022ClientServerPerf.cpp)
    target_link_libraries(Ss2022ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolShadowsocks2022)
endif()
AddPrismTest(Ss2022CodecDeep.cpp)
target_sources(Ss2022CodecDeep PRIVATE Ss2022AddressCodecDeep.cpp)
target_link_libraries(Ss2022CodecDeep PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022ConnErrorMatrix.cpp)
target_link_libraries(Ss2022ConnErrorMatrix PRIVATE
    PrismAccount
    PrismFoundation
    PrismProtocolHttp
    PrismProtocolSocks5
    PrismProtocolTrojan
    PrismProtocolVless
    PrismProtocolVmess
    PrismRuntime
    PrismTransport
    PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022ConnTerminalReadTest.cpp)
target_link_libraries(Ss2022ConnTerminalReadTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022ConnDatagramTest.cpp)
target_link_libraries(Ss2022ConnDatagramTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022UdpPacketBoundsTest.cpp)
target_link_libraries(Ss2022UdpPacketBoundsTest PRIVATE
    PrismFoundation
    PrismProtocolShadowsocks2022)
target_compile_options(Ss2022CodecDeep PRIVATE -O0 -fno-inline)
AddPrismTest(Ss2022StructureTest.cpp)
AddPrismTest(Ss2022DgramSession.cpp)
target_link_libraries(Ss2022DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022DatagramErrorTest.cpp)
target_link_libraries(Ss2022DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
target_compile_options(Ss2022DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Shadowsocks2022CodecFuzzTest.cpp)
target_link_libraries(Shadowsocks2022CodecFuzzTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022GoldenVectorTest.cpp)
target_link_libraries(Ss2022GoldenVectorTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
AddPrismTest(Ss2022UdpWireOrder.cpp)
target_link_libraries(Ss2022UdpWireOrder PRIVATE PrismFoundation PrismProtocolShadowsocks2022)

AddPrismTest(SS2022UdpE2ETest.cpp)
target_link_libraries(SS2022UdpE2ETest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
