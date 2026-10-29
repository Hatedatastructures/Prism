# trojan 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp TrojanClientServerPerf)
    target_link_libraries(TrojanClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
endif()
AddPrismTest(Codec/Deep.cpp TrojanCodecDeep)
target_link_libraries(TrojanCodecDeep PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Connection/ErrorMatrix.cpp TrojanConnErrorMatrix)
target_link_libraries(TrojanConnErrorMatrix PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(Connection/TerminalReadTest.cpp TrojanConnTerminalReadTest)
target_link_libraries(TrojanConnTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTrojan)
AddPrismTest(Connection/HandshakeTimeoutTest.cpp TrojanHandshakeTimeoutTest)
target_link_libraries(TrojanHandshakeTimeoutTest PRIVATE PrismFoundation PrismTransport PrismProtocolTrojan)
AddPrismTest(Connection/Session.cpp TrojanConnSession)
target_link_libraries(TrojanConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(Datagram/Session.cpp TrojanDgramSession)
target_link_libraries(TrojanDgramSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
AddPrismTest(Datagram/ErrorTest.cpp TrojanDatagramErrorTest)
target_link_libraries(TrojanDatagramErrorTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrojan)
target_compile_options(TrojanDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Datagram/EndTest.cpp TrojanDgramEndTest)
target_link_libraries(TrojanDgramEndTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismIoContracts
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
AddPrismTest(Codec/CodecFuzzTest.cpp TrojanCodecFuzzTest)
target_link_libraries(TrojanCodecFuzzTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Codec/GoldenVectorTest.cpp TrojanGoldenVectorTest)
target_link_libraries(TrojanGoldenVectorTest PRIVATE PrismFoundation PrismProtocolTrojan)
AddPrismTest(Codec/BeastTest.cpp TrojanBeastTest)
target_link_libraries(TrojanBeastTest PRIVATE PrismFoundation PrismProtocolTrojan)
if(PRISM_ENABLE_STRESS)
    AddPrismTest(Stress/StressTest.cpp TrojanStressTest)
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
target_sources(CanonicalDatagramTest PRIVATE Datagram/DatagramTestSupport.hpp)
AddPrismTest(Datagram/NativeReadFailureTest.cpp)
target_link_libraries(NativeReadFailureTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismIoContracts
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(NativeReadFailureTest PRIVATE Datagram/DatagramTestSupport.hpp)
AddPrismTest(Datagram/WorkspaceTest.cpp CanonicalWorkspaceTest)
target_link_libraries(CanonicalWorkspaceTest PRIVATE
    PrismFoundation
    PrismNet
    PrismNetworkModel
    PrismTransport
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolTrojan)
target_sources(CanonicalWorkspaceTest PRIVATE Datagram/DatagramTestSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TrojanConnSession PRIVATE
    Connection/IoContractTest.cpp
)
