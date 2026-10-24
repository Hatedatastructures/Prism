# tuic 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/TuicClientServerPerf.cpp)
    target_link_libraries(TuicClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTuic PrismTestSupport)
endif()
AddPrismTest(Connection/TuicConnErrorMatrix.cpp)
target_link_libraries(TuicConnErrorMatrix PRIVATE PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(Codec/TuicDgramDeep.cpp)
target_link_libraries(TuicDgramDeep PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(Datagram/TuicDgramProviderTest.cpp)
target_link_libraries(TuicDgramProviderTest PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(Datagram/TuicDatagramErrorTest.cpp)
target_link_libraries(TuicDatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/TuicCodecFuzzTest.cpp)
target_link_libraries(TuicCodecFuzzTest PRIVATE PrismProtocolTuic PrismTestSupport)
AddPrismTest(Codec/TuicCodecDeepTest.cpp)
target_link_libraries(TuicCodecDeepTest PRIVATE PrismFoundation PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/TuicCodecRoundtripTest.cpp)
target_link_libraries(TuicCodecRoundtripTest PRIVATE PrismFoundation PrismProtocolTuic)
AddPrismTest(Connection/TuicConnSession.cpp)
target_link_libraries(TuicConnSession PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTuic PrismTestSupport)

AddPrismTest(Connection/TuicTerminalReadTest.cpp)
target_sources(TuicTerminalReadTest PRIVATE
    Connection/TuicConnTerminalReadTest.cpp
    Connection/TuicDgramFragmentReadTest.cpp
    Connection/TuicAuthTerminalReadTest.cpp
    Connection/TuicTerminalReadSupport.hpp)
target_link_libraries(TuicTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTuic)

AddPrismTest(Admission/TuicAdmissionTest.cpp)
target_link_libraries(TuicAdmissionTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(Admission/TuicAdmissionCloseTest.cpp)
target_link_libraries(TuicAdmissionCloseTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)

AddPrismTest(Admission/TuicFactoryTest.cpp)
target_sources(TuicFactoryTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(
    TuicFactoryTest PRIVATE PrismFoundation PrismAccount PrismTransport PrismNet
                            PrismRuntime PrismProtocolQuic PrismProtocolQuicNative
                            PrismProtocolTuic PrismTestSupport)
