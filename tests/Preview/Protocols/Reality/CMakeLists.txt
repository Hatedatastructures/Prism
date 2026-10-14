# reality 子模块
AddPreviewTest(../../../Experiments/Reality/RealityKeygenTest.cpp)
target_link_libraries(RealityKeygenTest PRIVATE PreviewProtocolReality PreviewTestSupport)
AddPreviewTest(RealityCertificateTest.cpp)
target_link_libraries(RealityCertificateTest PRIVATE PreviewProtocolReality PreviewTestSupport OpenSSL::Crypto)
AddPreviewTest(RealityResponseTest.cpp)
target_link_libraries(RealityResponseTest PRIVATE PreviewProtocolReality PreviewTestSupport)
AddPreviewTest(RealityCodecDeepTest.cpp)
target_link_libraries(RealityCodecDeepTest PRIVATE PreviewProtocolReality PreviewTestSupport)
target_compile_options(RealityCodecDeepTest PRIVATE -O0 -fno-inline)
AddPreviewTest(RealityCarrierTest.cpp)
target_link_libraries(RealityCarrierTest PRIVATE PreviewProtocolReality)

# 同一实际owner的源文件，复用现有target。
target_sources(RealityCarrierTest PRIVATE
    RealityPreparedAdmissionTest.cpp
)
