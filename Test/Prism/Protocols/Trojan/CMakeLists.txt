# trojan 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/TrojanClientServerPerf.cpp)
    target_link_libraries(TrojanClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
endif()
AddPrismTest(Codec/TrojanCodecDeep.cpp)
target_link_libraries(TrojanCodecDeep PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Connection/TrojanConnErrorMatrix.cpp)
target_link_libraries(TrojanConnErrorMatrix PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(Connection/TrojanConnTerminalReadTest.cpp)
target_link_libraries(TrojanConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTrojan)
AddPrismTest(Connection/TrojanHandshakeTimeoutTest.cpp)
target_link_libraries(TrojanHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(Connection/TrojanConnSession.cpp)
target_link_libraries(TrojanConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(Datagram/TrojanDgramSession.cpp)
target_link_libraries(TrojanDgramSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(Datagram/TrojanDatagramErrorTest.cpp)
target_link_libraries(TrojanDatagramErrorTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
target_compile_options(TrojanDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Datagram/TrojanDgramEndTest.cpp)
target_link_libraries(TrojanDgramEndTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismIoContracts
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
AddPrismTest(Codec/TrojanCodecFuzzTest.cpp)
target_link_libraries(TrojanCodecFuzzTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Codec/TrojanGoldenVectorTest.cpp)
target_link_libraries(TrojanGoldenVectorTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Codec/TrojanBeastTest.cpp)
target_link_libraries(TrojanBeastTest PRIVATE PrismFoundation PrismProtocolTrojan)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/TrojanStressTest.cpp)
    target_link_libraries(TrojanStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
endif()
target_compile_options(TrojanCodecDeep PRIVATE -O0 -fno-inline)

AddPrismTest(Datagram/CanonicalDatagramTest.cpp)
target_link_libraries(CanonicalDatagramTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismIoContracts
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(CanonicalDatagramTest PRIVATE Datagram/TrojanDatagramTestSupport.hpp)
AddPrismTest(Datagram/CanonicalWorkspaceTest.cpp)
target_link_libraries(CanonicalWorkspaceTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(CanonicalWorkspaceTest PRIVATE Datagram/TrojanDatagramTestSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TrojanConnSession PRIVATE
    Connection/TrojanConnIoContractTest.cpp
)
