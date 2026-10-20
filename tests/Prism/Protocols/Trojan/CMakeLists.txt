# trojan 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(TrojanClientServerPerf.cpp)
    target_link_libraries(TrojanClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
endif()
AddPrismTest(TrojanCodecDeep.cpp)
target_link_libraries(TrojanCodecDeep PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(TrojanConnErrorMatrix.cpp)
target_link_libraries(TrojanConnErrorMatrix PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(TrojanConnTerminalReadTest.cpp)
target_link_libraries(TrojanConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTrojan)
AddPrismTest(TrojanHandshakeTimeoutTest.cpp)
target_link_libraries(TrojanHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(TrojanConnSession.cpp)
target_link_libraries(TrojanConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(TrojanDgramSession.cpp)
target_link_libraries(TrojanDgramSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(TrojanDatagramErrorTest.cpp)
target_link_libraries(TrojanDatagramErrorTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
target_compile_options(TrojanDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(TrojanDatagramSessionTerminalTest.cpp)
target_link_libraries(TrojanDatagramSessionTerminalTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismIoContracts
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
AddPrismTest(TrojanCodecFuzzTest.cpp)
target_link_libraries(TrojanCodecFuzzTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(TrojanGoldenVectorTest.cpp)
target_link_libraries(TrojanGoldenVectorTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(TrojanBeastTest.cpp)
target_link_libraries(TrojanBeastTest PRIVATE PrismFoundation PrismProtocolTrojan)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(TrojanStressTest.cpp)
    target_link_libraries(TrojanStressTest PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
endif()
target_compile_options(TrojanCodecDeep PRIVATE -O0 -fno-inline)

AddPrismTest(CanonicalDatagramTest.cpp)
target_link_libraries(CanonicalDatagramTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismIoContracts
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(CanonicalDatagramTest PRIVATE TrojanDatagramTestSupport.hpp)
AddPrismTest(CanonicalDatagramWorkspaceTest.cpp)
target_link_libraries(CanonicalDatagramWorkspaceTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(CanonicalDatagramWorkspaceTest PRIVATE TrojanDatagramTestSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TrojanConnSession PRIVATE
    ../../Protocols/Trojan/TrojanConnIoContractTest.cpp
)
