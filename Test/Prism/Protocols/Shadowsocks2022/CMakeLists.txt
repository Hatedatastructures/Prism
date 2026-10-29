# shadowsocks2022 子模块测试
AddPrismTest(Codec/BeastTest.cpp Shadowsocks2022BeastTest)
target_link_libraries(Shadowsocks2022BeastTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp Ss2022ClientServerPerf)
    target_link_libraries(Ss2022ClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolShadowsocks2022)
endif()
AddPrismTest(Codec/Ss2022CodecDeep.cpp)
target_sources(Ss2022CodecDeep PRIVATE Codec/AddressDeep.cpp)
target_link_libraries(Ss2022CodecDeep PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
AddPrismTest(Connection/Ss2022ConnErrorMatrix.cpp)
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
AddPrismTest(Connection/TerminalReadTest.cpp Ss2022ConnTerminalReadTest)
target_link_libraries(Ss2022ConnTerminalReadTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolShadowsocks2022)
AddPrismTest(Datagram/ConnDgramTest.cpp Ss2022ConnDatagramTest)
target_link_libraries(Ss2022ConnDatagramTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolShadowsocks2022)
AddPrismTest(Datagram/PacketBoundsTest.cpp Ss2022UdpPacketBoundsTest)
target_link_libraries(Ss2022UdpPacketBoundsTest PRIVATE
    PrismFoundation
    PrismProtocolShadowsocks2022)
target_compile_options(Ss2022CodecDeep PRIVATE -O0 -fno-inline)
AddPrismTest(Core/Ss2022StructureTest.cpp)
AddPrismTest(Datagram/Ss2022DgramSession.cpp)
target_link_libraries(Ss2022DgramSession PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
AddPrismTest(Datagram/ErrorTest.cpp Ss2022DatagramErrorTest)
target_link_libraries(Ss2022DatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolShadowsocks2022)
target_compile_options(Ss2022DatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/Ss2022CodecFuzzTest.cpp)
target_link_libraries(Ss2022CodecFuzzTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
AddPrismTest(Codec/GoldenTest.cpp Ss2022GoldenVectorTest)
target_link_libraries(Ss2022GoldenVectorTest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
AddPrismTest(Codec/Ss2022UdpWireOrder.cpp)
target_link_libraries(Ss2022UdpWireOrder PRIVATE PrismFoundation PrismProtocolShadowsocks2022)

AddPrismTest(Datagram/SS2022UdpE2ETest.cpp)
target_link_libraries(SS2022UdpE2ETest PRIVATE PrismFoundation PrismProtocolShadowsocks2022)
