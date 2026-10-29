# anytls 子模块
AddPrismTest(Codec/DeepTest.cpp AnytlsCodecDeepTest)
target_link_libraries(AnytlsCodecDeepTest PRIVATE PrismFoundation PrismProtocolAnytls)
target_compile_options(AnytlsCodecDeepTest PRIVATE -O0 -fno-inline)

AddPrismTest(Codec/FrameEndTest.cpp AnytlsFrameEndTest)
target_link_libraries(AnytlsFrameEndTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(Connection/TerminalReadTest.cpp AnytlsConnTerminalReadTest)
target_link_libraries(AnytlsConnTerminalReadTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(Connection/SessionOwnerTest.cpp AnytlsSessionOwnerTest)
target_link_libraries(AnytlsSessionOwnerTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIngressModel
    PrismIngressContract
    PrismLifecycle
    PrismProtocolAnytls
    PrismProtocolMux
    PrismProtocolHttp
    PrismProtocolShadowsocks2022
    PrismProtocolSocks5
    PrismRuntime
    PrismStreamContract
    PrismNet
    PrismTransport)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(AnytlsSessionOwnerTest PRIVATE
    Connection/HandshakeFailureTest.cpp
    Connection/CancelClassTest.cpp
)
target_include_directories(AnytlsSessionOwnerTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

AddPrismTest(Codec/AuthFrameTest.cpp AnytlsAuthFrameTest)
target_link_libraries(AnytlsAuthFrameTest PRIVATE PrismFoundation PrismProtocolAnytls)
