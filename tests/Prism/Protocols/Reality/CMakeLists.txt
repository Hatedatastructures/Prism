# reality 子模块
AddPrismTest(RealityKeygenTest.cpp)
target_include_directories(RealityKeygenTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityKeygenTest PRIVATE PrismProtocolReality)
AddPrismTest(RealityCertificateTest.cpp)
target_include_directories(RealityCertificateTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCertificateTest PRIVATE PrismFoundation PrismProtocolReality OpenSSL::Crypto)
AddPrismTest(RealityResponseTest.cpp)
target_include_directories(RealityResponseTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityResponseTest PRIVATE PrismProtocolReality OpenSSL::Crypto)
AddPrismTest(RealityCodecDeepTest.cpp)
target_include_directories(RealityCodecDeepTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCodecDeepTest PRIVATE PrismProtocolReality)
target_compile_options(RealityCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(RealityCarrierTest.cpp)
target_include_directories(RealityCarrierTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityCarrierTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolReality OpenSSL::Crypto)

# 同一实际owner的源文件，复用现有target。
target_sources(RealityCarrierTest PRIVATE
    RealityPreparedAdmissionTest.cpp
    RealityRecordTerminalTest.cpp
)

AddPrismTest(RealityKeyMaterialTest.cpp)
target_include_directories(RealityKeyMaterialTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(RealityKeyMaterialTest PRIVATE PrismProtocolReality)
