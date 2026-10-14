AddPreviewTest(CarrierMuxTest.cpp)
target_link_libraries(CarrierMuxTest PRIVATE PreviewProtocolAnytls PreviewProtocolGun PreviewProtocolMux
    PreviewProtocolReality PreviewProtocolRestls PreviewProtocolShadowtls PreviewProtocolTrusttunnel PreviewProtocolWs)
AddPreviewTest(Hysteria2TuicBeastTest.cpp)
target_link_libraries(Hysteria2TuicBeastTest PRIVATE PreviewProtocolHysteria2 PreviewProtocolTuic PreviewTestSupport)
AddPreviewTest(RecognitionQuicCarrier.cpp)
target_link_libraries(RecognitionQuicCarrier PRIVATE PreviewFoundation PreviewTransport PreviewProtocolQuic
    PreviewProtocolHysteria2 PreviewProtocolTuic PreviewProtocolMux PreviewTestSupport)
foreach(_case IN ITEMS VmessCarrierErrorTest CarrierHandshakeErrorTest HttpCarrierHandshakeErrorTest)
    AddPreviewTest(${_case}.cpp)
    target_sources(${_case} PRIVATE CarrierErrorFixture.hpp)
    target_link_libraries(${_case} PRIVATE PreviewTransport PreviewProtocolAnytls PreviewProtocolGun
        PreviewProtocolReality PreviewProtocolRestls PreviewProtocolShadowtls PreviewProtocolTrusttunnel
        PreviewProtocolVmess PreviewProtocolWs)
    target_compile_options(${_case} PRIVATE -O0 -fno-inline)
endforeach()
target_sources(HttpCarrierHandshakeErrorTest PRIVATE ../../Protocols/Ws/WsFactorySupport.hpp)
AddPreviewTest(CarrierWireVectorTest.cpp)
target_link_libraries(CarrierWireVectorTest PRIVATE PreviewComposition PreviewProtocolReality
    PreviewProtocolRestls PreviewProtocolShadowtls)

# 同一实际owner的源文件，复用现有target。
target_sources(CarrierHandshakeErrorTest PRIVATE
    ../../../Experiments/Reality/SessionIdChannelErrorTest.cpp
)
