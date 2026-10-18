# anytls 子模块
AddPrismTest(AnytlsCodecDeepTest.cpp)
target_link_libraries(AnytlsCodecDeepTest PRIVATE PrismFoundation PrismProtocolAnytls PrismTestSupport)
target_compile_options(AnytlsCodecDeepTest PRIVATE -O0 -fno-inline)

AddPrismTest(AnytlsAdmissionOwnerTest.cpp)
target_link_libraries(AnytlsAdmissionOwnerTest PRIVATE PrismProtocolAnytls)
AddPrismTest(AnytlsSessionOwnerTest.cpp)
target_link_libraries(AnytlsSessionOwnerTest PRIVATE PrismProtocolAnytls)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(AnytlsSessionOwnerTest PRIVATE
    ../../Protocols/Anytls/AnytlsHandshakeFailureTest.cpp
    AnytlsCancellationClassificationTest.cpp
)
