# anytls 子模块
AddPrismTest(AnytlsCodecDeepTest.cpp)
target_link_libraries(AnytlsCodecDeepTest PRIVATE PrismFoundation PrismProtocolAnytls)
target_compile_options(AnytlsCodecDeepTest PRIVATE -O0 -fno-inline)

AddPrismTest(AnytlsFrameReaderTerminalTest.cpp)
target_link_libraries(AnytlsFrameReaderTerminalTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(AnytlsConnTerminalReadTest.cpp)
target_link_libraries(AnytlsConnTerminalReadTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(AnytlsSessionOwnerTest.cpp)
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
    ../../Protocols/Anytls/AnytlsHandshakeFailureTest.cpp
    AnytlsCancellationClassificationTest.cpp
)
target_include_directories(AnytlsSessionOwnerTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

AddPrismTest(AnytlsAuthFrameTest.cpp)
target_link_libraries(AnytlsAuthFrameTest PRIVATE PrismFoundation PrismProtocolAnytls)
