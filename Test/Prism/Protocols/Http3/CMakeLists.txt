# http3 子模块测试
AddPrismTest(Core/HttpQuicCoverage.cpp)
target_link_libraries(HttpQuicCoverage PRIVATE
    PrismFoundation PrismProtocolHttp3Core PrismProtocolHttp3)
AddPrismTest(Codec/QpackEncodeOut.cpp)
target_link_libraries(QpackEncodeOut PRIVATE PrismFoundation PrismProtocolHttp3Core)
AddPrismTest(Codec/QpackInteropTest.cpp)
target_link_libraries(QpackInteropTest PRIVATE PrismFoundation PrismProtocolHttp3Core)
AddPrismTest(Connection/NativeHttp3Session.cpp)
target_link_libraries(NativeHttp3Session PRIVATE PrismFoundation PrismIoContracts PrismLifecycle
    PrismProtocolHttp3 PrismProtocolQuic PrismProtocolQuicNative)
AddPrismTest(Connection/NativeHttp3ReadLoopTest.cpp)
target_include_directories(NativeHttp3ReadLoopTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src
    "${nghttp3_SOURCE_DIR}/lib/includes")
target_link_libraries(NativeHttp3ReadLoopTest PRIVATE PrismFoundation PrismIoContracts PrismLifecycle
    PrismProtocolHttp3 PrismProtocolQuic PrismProtocolQuicNative)
AddPrismTest(Connection/SessionHeaderContractTest.cpp)
target_include_directories(SessionHeaderContractTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src
    "${nghttp3_SOURCE_DIR}/lib/includes")
target_link_libraries(SessionHeaderContractTest PRIVATE PrismFoundation PrismProtocolHttp3)
AddPrismTest(Codec/Http3QpackFuzzTest.cpp)
target_link_libraries(Http3QpackFuzzTest PRIVATE PrismProtocolHttp3Core PrismProtocolHttpCompression)
