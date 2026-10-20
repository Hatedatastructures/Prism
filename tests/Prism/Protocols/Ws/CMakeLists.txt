# ws 子模块
AddPrismTest(WsConnSession.cpp)
target_include_directories(WsConnSession PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_sources(WsConnSession PRIVATE
    WsConnFrame.cpp
    WsConnHandshakeTerminal.cpp
    WsConnHandshake.cpp
    WsConnClose.cpp
    WsConnSessionSupport.hpp
    WsFactorySupport.hpp)
target_link_libraries(WsConnSession PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolWs)
AddPrismTest(WsCodecDeepTest.cpp)
target_include_directories(WsCodecDeepTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsCodecDeepTest PRIVATE PrismFoundation PrismProtocolWs)
target_compile_options(WsCodecDeepTest PRIVATE -O0 -fno-inline)

# 同一实际owner的源文件，复用现有target。
target_sources(WsConnSession PRIVATE
    WsConnActivity.cpp
    WsConnResource.cpp
)

AddPrismTest(WsAcceptFrameTest.cpp)
target_include_directories(WsAcceptFrameTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(WsAcceptFrameTest PRIVATE PrismFoundation PrismProtocolWs)
