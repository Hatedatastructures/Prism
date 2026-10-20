# tuic 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(TuicClientServerPerf.cpp)
    target_link_libraries(TuicClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTuic PrismTestSupport)
endif()
AddPrismTest(TuicConnErrorMatrix.cpp)
target_link_libraries(TuicConnErrorMatrix PRIVATE PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(TuicDgramDeep.cpp)
target_link_libraries(TuicDgramDeep PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(TuicDgramProviderTest.cpp)
target_link_libraries(TuicDgramProviderTest PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(TuicDatagramErrorTest.cpp)
target_link_libraries(TuicDatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(TuicCodecFuzzTest.cpp)
target_link_libraries(TuicCodecFuzzTest PRIVATE PrismProtocolTuic PrismTestSupport)
AddPrismTest(TuicCodecDeepTest.cpp)
target_link_libraries(TuicCodecDeepTest PRIVATE PrismFoundation PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(TuicCodecRoundtripTest.cpp)
target_link_libraries(TuicCodecRoundtripTest PRIVATE PrismFoundation PrismProtocolTuic)
AddPrismTest(TuicConnSession.cpp)
target_link_libraries(TuicConnSession PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicTerminalReadTest.cpp)
target_link_libraries(TuicTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTuic)

AddPrismTest(TuicAdmissionTest.cpp)
target_link_libraries(TuicAdmissionTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(TuicAdmissionCloseTest.cpp)
target_link_libraries(TuicAdmissionCloseTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicFactoryTest.cpp)
target_sources(TuicFactoryTest PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(
    TuicFactoryTest PRIVATE PrismFoundation PrismAccount PrismTransport PrismNet
                            PrismRuntime PrismProtocolQuic PrismProtocolQuicNative
                            PrismProtocolTuic PrismTestSupport)
