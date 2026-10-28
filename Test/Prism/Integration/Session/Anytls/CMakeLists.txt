AddPrismTest(ShutdownTest.cpp AnytlsShutdownTest)
target_link_libraries(AnytlsShutdownTest PRIVATE
    PrismFoundation PrismProtocolAnytls PrismRuntime PrismTransport)

AddPrismTest(AdmissionOwnerTest.cpp AnytlsAdmissionOwnerTest)
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
