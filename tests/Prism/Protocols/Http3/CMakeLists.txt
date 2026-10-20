# http3 子模块测试
AddPrismTest(HttpQuicCoverage.cpp)
target_link_libraries(HttpQuicCoverage PRIVATE
    PrismFoundation PrismProtocolHttp3Core PrismProtocolHttp3)
AddPrismTest(QpackEncodeOut.cpp)
target_link_libraries(QpackEncodeOut PRIVATE PrismFoundation PrismProtocolHttp3Core)
AddPrismTest(QpackInteropTest.cpp)
target_link_libraries(QpackInteropTest PRIVATE PrismFoundation PrismProtocolHttp3Core)
AddPrismTest(NativeHttp3Session.cpp)
target_link_libraries(NativeHttp3Session PRIVATE PrismFoundation PrismIoContracts PrismLifecycle
    PrismProtocolHttp3 PrismProtocolQuic PrismProtocolQuicNative)
AddPrismTest(NativeHttp3ReadLoopTest.cpp)
target_include_directories(NativeHttp3ReadLoopTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src
    "${nghttp3_SOURCE_DIR}/lib/includes")
target_link_libraries(NativeHttp3ReadLoopTest PRIVATE PrismFoundation PrismIoContracts PrismLifecycle
    PrismProtocolHttp3 PrismProtocolQuic PrismProtocolQuicNative)
AddPrismTest(SessionHeaderContractTest.cpp)
target_include_directories(SessionHeaderContractTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src
    "${nghttp3_SOURCE_DIR}/lib/includes")
target_link_libraries(SessionHeaderContractTest PRIVATE PrismFoundation PrismProtocolHttp3)
AddPrismTest(Http3QpackFuzzTest.cpp)
target_link_libraries(Http3QpackFuzzTest PRIVATE PrismProtocolHttp3Core PrismProtocolHttpCompression)
