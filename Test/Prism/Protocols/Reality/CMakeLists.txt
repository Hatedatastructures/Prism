# reality 子模块
AddPrismTest(Codec/RealityKeygenTest.cpp)
target_include_directories(RealityKeygenTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityKeygenTest PRIVATE PrismProtocolReality)
AddPrismTest(Codec/RealityCertificateTest.cpp)
target_include_directories(RealityCertificateTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCertificateTest PRIVATE PrismFoundation PrismProtocolReality OpenSSL::Crypto)
AddPrismTest(Connection/RealityResponseTest.cpp)
target_include_directories(RealityResponseTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityResponseTest PRIVATE PrismProtocolReality OpenSSL::Crypto)
AddPrismTest(Codec/RealityCodecDeepTest.cpp)
target_include_directories(RealityCodecDeepTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCodecDeepTest PRIVATE PrismProtocolReality)
target_compile_options(RealityCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Core/RealityCarrierTest.cpp)
target_include_directories(RealityCarrierTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCarrierTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolReality OpenSSL::Crypto)

# 同一实际owner的源文件，复用现有target。
target_sources(RealityCarrierTest PRIVATE
    Admission/RealityPreparedTest.cpp
    Connection/RealityRecordTerminalTest.cpp
)

AddPrismTest(Codec/RealityKeyMaterialTest.cpp)
target_include_directories(RealityKeyMaterialTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityKeyMaterialTest PRIVATE PrismProtocolReality)
