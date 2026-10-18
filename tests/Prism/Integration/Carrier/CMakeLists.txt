AddPrismTest(CarrierMuxTest.cpp)
target_link_libraries(CarrierMuxTest PRIVATE PrismProtocolAnytls PrismProtocolGun PrismProtocolMux
    PrismProtocolReality PrismProtocolRestls PrismProtocolShadowtls PrismProtocolTrusttunnel PrismProtocolWs)
AddPrismTest(Hysteria2TuicBeastTest.cpp)
target_link_libraries(Hysteria2TuicBeastTest PRIVATE PrismProtocolHysteria2 PrismProtocolTuic PrismTestSupport)
AddPrismTest(RecognitionQuicCarrier.cpp)
target_link_libraries(RecognitionQuicCarrier PRIVATE PrismFoundation PrismTransport PrismProtocolQuic
    PrismProtocolHysteria2 PrismProtocolTuic PrismProtocolMux PrismTestSupport)
foreach(_case IN ITEMS VmessCarrierErrorTest CarrierHandshakeErrorTest HttpCarrierHandshakeErrorTest)
    AddPrismTest(${_case}.cpp)
    target_sources(${_case} PRIVATE CarrierErrorFixture.hpp)
    target_link_libraries(${_case} PRIVATE PrismTransport PrismProtocolAnytls PrismProtocolGun
        PrismProtocolReality PrismProtocolRestls PrismProtocolShadowtls PrismProtocolTrusttunnel
        PrismProtocolVmess PrismProtocolWs)
    target_compile_options(${_case} PRIVATE -O0 -fno-inline)
endforeach()
target_sources(HttpCarrierHandshakeErrorTest PRIVATE ../../Protocols/Ws/WsFactorySupport.hpp)
AddPrismTest(CarrierWireVectorTest.cpp)
target_link_libraries(CarrierWireVectorTest PRIVATE PrismComposition PrismProtocolReality
    PrismProtocolRestls PrismProtocolShadowtls)
