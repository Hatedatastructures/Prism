AddPreviewTest(FacadeCarrierTest.cpp)
target_link_libraries(FacadeCarrierTest PRIVATE
        PreviewFoundation
        PreviewTransport
        PreviewComposition
        PreviewProtocolReality
        PreviewProtocolRestls
        PreviewProtocolShadowtls
        PreviewTestSupport
)

AddPreviewTest(CarrierWireVectorTest.cpp)
target_link_libraries(CarrierWireVectorTest PRIVATE
        PreviewFoundation
        PreviewComposition
        PreviewProtocolReality
        PreviewProtocolRestls
        PreviewProtocolShadowtls
        PreviewTestSupport
)

AddPreviewTest(RealityCarrierTest.cpp)
target_link_libraries(RealityCarrierTest PRIVATE
        PreviewFoundation
        PreviewTransport
        PreviewComposition
        PreviewProtocolReality
        PreviewTestSupport
)

AddPreviewTest(AnytlsCarrierTest.cpp)
target_link_libraries(AnytlsCarrierTest PRIVATE
        PreviewFoundation
        PreviewTransport
        PreviewRuntime
        PreviewComposition
        PreviewProtocolAnytls
        PreviewTestSupport
)

AddPreviewTest(RestlsCodecTest.cpp)
target_link_libraries(RestlsCodecTest PRIVATE
        PreviewFoundation
        PreviewProtocolRestls
        PreviewTestSupport
)

AddPreviewTest(RestlsCarrierTest.cpp)
target_link_libraries(RestlsCarrierTest PRIVATE
        PreviewFoundation
        PreviewTransport
        PreviewComposition
        PreviewProtocolRestls
        PreviewTestSupport
)

AddPreviewTest(ShadowtlsCarrierTest.cpp)
target_link_libraries(ShadowtlsCarrierTest PRIVATE
        PreviewFoundation
        PreviewTransport
        PreviewComposition
        PreviewProtocolShadowtls
        PreviewTestSupport
)
