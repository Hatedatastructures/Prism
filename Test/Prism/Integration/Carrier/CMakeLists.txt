AddPrismTest(RecognitionQuicCarrier.cpp)
target_link_libraries(RecognitionQuicCarrier PRIVATE PrismFoundation PrismTransport PrismProtocolQuic
    PrismProtocolHysteria2 PrismProtocolTuic PrismProtocolMux PrismTestSupport)
foreach(_case IN ITEMS VmessCarrierErrorTest CarrierHandshakeErrorTest HttpCarrierErrorTest)
    AddPrismTest(${_case}.cpp)
    target_include_directories(${_case} PRIVATE ${PROJECT_SOURCE_DIR}/Src)
    target_sources(${_case} PRIVATE CarrierErrorFixture.hpp)
    target_link_libraries(${_case} PRIVATE PrismTransport PrismProtocolAnytls PrismProtocolGun
        PrismProtocolReality PrismProtocolRestls PrismProtocolShadowtls PrismProtocolTrusttunnel
        PrismProtocolVmess PrismProtocolWs)
    target_compile_options(${_case} PRIVATE -O0 -fno-inline)
endforeach()
target_sources(HttpCarrierErrorTest PRIVATE ../../Protocols/Ws/Admission/WsFactorySupport.hpp)
target_link_libraries(HttpCarrierErrorTest PRIVATE PrismFoundation)
