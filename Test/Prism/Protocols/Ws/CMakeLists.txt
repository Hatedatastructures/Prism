# ws 子模块
AddPrismTest(Connection/Session.cpp WsConnSession)
target_include_directories(WsConnSession PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_sources(WsConnSession PRIVATE
    Codec/ConnFrame.cpp
    Connection/HandshakeTerminal.cpp
    Connection/Handshake.cpp
    Connection/Close.cpp
    Connection/SessionSupport.hpp
    Admission/FactorySupport.hpp)
target_link_libraries(WsConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolWs)
AddPrismTest(Codec/DeepTest.cpp WsCodecDeepTest)
target_include_directories(WsCodecDeepTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsCodecDeepTest PRIVATE PrismFoundation PrismProtocolWs)
target_compile_options(WsCodecDeepTest PRIVATE -O0 -fno-inline)

# 同一实际owner的源文件，复用现有target。
target_sources(WsConnSession PRIVATE
    Connection/Activity.cpp
    Connection/Resource.cpp
)

AddPrismTest(Codec/AcceptFrameTest.cpp WsAcceptFrameTest)
target_include_directories(WsAcceptFrameTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsAcceptFrameTest PRIVATE PrismFoundation PrismProtocolWs)
