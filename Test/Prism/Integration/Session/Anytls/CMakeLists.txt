AddPrismTest(AnytlsShutdownTest.cpp)
target_link_libraries(AnytlsShutdownTest PRIVATE
    PrismFoundation PrismProtocolAnytls PrismRuntime PrismTransport)

AddPrismTest(AnytlsAdmissionOwnerTest.cpp)
target_link_libraries(AnytlsAdmissionOwnerTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIngressModel
    PrismIngressContract
    PrismRuntime
    PrismStreamContract
    PrismNet
    PrismProtocolMux
    PrismProtocolAnytls
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismTransport)
