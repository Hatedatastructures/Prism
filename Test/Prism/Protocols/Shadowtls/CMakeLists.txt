# shadowtls 子模块
AddPrismTest(Core/CarrierTest.cpp ShadowtlsCarrierTest)
target_include_directories(ShadowtlsCarrierTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsCarrierTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismComposition PrismProtocolShadowtls)
AddPrismTest(Connection/Session.cpp ShadowtlsConnSession)
target_include_directories(ShadowtlsConnSession PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsConnSession PRIVATE PrismFoundation PrismTransport PrismProtocolShadowtls)

AddPrismTest(Connection/RecordEndTest.cpp ShadowtlsRecordEndTest)
target_include_directories(ShadowtlsRecordEndTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsRecordEndTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolShadowtls OpenSSL::Crypto)

AddPrismTest(Codec/Deep.cpp ShadowtlsCodecDeep)
target_include_directories(ShadowtlsCodecDeep PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsCodecDeep PRIVATE PrismProtocolShadowtls)

AddPrismTest(Connection/Relay.cpp ShadowtlsRelay)
target_include_directories(ShadowtlsRelay PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsRelay PRIVATE PrismProtocolShadowtls PrismTransport)

AddPrismTest(Connection/SessionIdTest.cpp ShadowtlsSessionIdTest)
target_include_directories(ShadowtlsSessionIdTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ShadowtlsSessionIdTest PRIVATE PrismProtocolShadowtls)
