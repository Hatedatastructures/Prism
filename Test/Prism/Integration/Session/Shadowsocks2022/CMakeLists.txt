# Shadowsocks2022 经真实 Runtime Session 的 TCP 场景
AddPrismTest(SS2022E2ETest.cpp)
target_link_libraries(SS2022E2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition
    PrismProtocolAnytls PrismProtocolShadowsocks2022 PrismProtocolTrojan PrismProtocolVless
    PrismProtocolVmess PrismTestSupport)

AddPrismTest(Ss2022GatewayTest.cpp)
target_link_libraries(Ss2022GatewayTest PRIVATE
    PrismFoundation
    PrismAccount
    PrismNet
    PrismBoundary
    PrismDatagramContract
    PrismIngressContract
    PrismProtocolHttp
    PrismProtocolSocks5
    PrismRuntime
    PrismProtocolShadowsocks2022)
