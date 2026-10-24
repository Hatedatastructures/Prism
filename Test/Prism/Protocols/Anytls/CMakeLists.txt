# anytls 子模块
AddPrismTest(Codec/AnytlsCodecDeepTest.cpp)
target_link_libraries(AnytlsCodecDeepTest PRIVATE PrismFoundation PrismProtocolAnytls)
target_compile_options(AnytlsCodecDeepTest PRIVATE -O0 -fno-inline)

AddPrismTest(Codec/AnytlsFrameEndTest.cpp)
target_link_libraries(AnytlsFrameEndTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(Connection/AnytlsConnTerminalReadTest.cpp)
target_link_libraries(AnytlsConnTerminalReadTest PRIVATE
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolAnytls)

AddPrismTest(Connection/AnytlsSessionOwnerTest.cpp)
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
    Connection/AnytlsHandshakeFailureTest.cpp
    Connection/AnytlsCancelClassTest.cpp
)
target_include_directories(AnytlsSessionOwnerTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

AddPrismTest(Codec/AnytlsAuthFrameTest.cpp)
target_link_libraries(AnytlsAuthFrameTest PRIVATE PrismFoundation PrismProtocolAnytls)
