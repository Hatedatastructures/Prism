# ws 子模块
AddPrismTest(Connection/WsConnSession.cpp)
target_include_directories(WsConnSession PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_sources(WsConnSession PRIVATE
    Codec/WsConnFrame.cpp
    Connection/WsConnHandshakeTerminal.cpp
    Connection/WsConnHandshake.cpp
    Connection/WsConnClose.cpp
    Connection/WsConnSessionSupport.hpp
    Admission/WsFactorySupport.hpp)
target_link_libraries(WsConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolWs)
AddPrismTest(Codec/WsCodecDeepTest.cpp)
target_include_directories(WsCodecDeepTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsCodecDeepTest PRIVATE PrismFoundation PrismProtocolWs)
target_compile_options(WsCodecDeepTest PRIVATE -O0 -fno-inline)

# 同一实际owner的源文件，复用现有target。
target_sources(WsConnSession PRIVATE
    Connection/WsConnActivity.cpp
    Connection/WsConnResource.cpp
)

AddPrismTest(Codec/WsAcceptFrameTest.cpp)
target_include_directories(WsAcceptFrameTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsAcceptFrameTest PRIVATE PrismFoundation PrismProtocolWs)
