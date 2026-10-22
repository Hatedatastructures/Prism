# restls 子模块
AddPrismTest(Codec/RestlsCodecTest.cpp)
target_include_directories(RestlsCodecTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsCodecTest PRIVATE PrismFoundation PrismProtocolRestls)
AddPrismTest(Connection/RestlsConnSession.cpp)
target_sources(RestlsConnSession PRIVATE Connection/RestlsRecordTerminalTest.cpp)
target_include_directories(RestlsConnSession PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsConnSession PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolRestls)

AddPrismTest(Codec/RestlsCodecDeep.cpp)
target_include_directories(RestlsCodecDeep PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsCodecDeep PRIVATE PrismProtocolRestls)

AddPrismTest(Connection/RestlsServerHandshakeTest.cpp)
target_include_directories(RestlsServerHandshakeTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsServerHandshakeTest PRIVATE PrismProtocolRestls)

AddPrismTest(Connection/RestlsServerRelayTest.cpp)
target_include_directories(RestlsServerRelayTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsServerRelayTest PRIVATE PrismFoundation PrismTransport PrismProtocolRestls)

AddPrismTest(Core/RestlsCarrierTest.cpp)
target_include_directories(RestlsCarrierTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsCarrierTest PRIVATE PrismTransport PrismProtocolRestls)

AddPrismTest(Codec/RestlsAuthKeyTest.cpp)
target_include_directories(RestlsAuthKeyTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RestlsAuthKeyTest PRIVATE PrismFoundation PrismProtocolRestls)
