# anytls 子模块
AddPreviewTest(AnytlsCodecDeepTest.cpp)
target_link_libraries(AnytlsCodecDeepTest PRIVATE PreviewFoundation PreviewProtocolAnytls PreviewTestSupport)
target_compile_options(AnytlsCodecDeepTest PRIVATE -O0 -fno-inline)

AddPreviewTest(AnytlsAdmissionOwnerTest.cpp)
target_link_libraries(AnytlsAdmissionOwnerTest PRIVATE PreviewProtocolAnytls)
AddPreviewTest(AnytlsSessionOwnerTest.cpp)
target_link_libraries(AnytlsSessionOwnerTest PRIVATE PreviewProtocolAnytls)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(AnytlsSessionOwnerTest PRIVATE
    ../../protocols/Anytls/AnytlsHandshakeFailureTest.cpp
)
