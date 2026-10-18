# Shadowsocks2022 经真实 Runtime Session 的 TCP 场景
AddPrismTest(SS2022E2ETest.cpp)
target_link_libraries(SS2022E2ETest PRIVATE
    PrismFoundation PrismTransport PrismNet PrismRuntime PrismComposition
    PrismProtocolShadowsocks2022 PrismTestSupport)
