# Trojan 经真实 Runtime Session 的 TCP/UDP 纵向场景
AddPrismTest(TrojanE2ETest.cpp)
target_link_libraries(TrojanE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismProtocolAnytls
    PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
AddPrismTest(TrojanUdpE2ETest.cpp)
target_link_libraries(TrojanUdpE2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition PrismDatagramContract
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TrojanE2ETest PRIVATE
    TrojanTrafficIdentityE2ETest.cpp
)
