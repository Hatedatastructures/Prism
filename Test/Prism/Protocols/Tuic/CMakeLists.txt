# tuic 子模块测试
if(PRISM_ENABLE_BENCHMARK)
    AddPrismTest(Performance/ClientServerPerf.cpp TuicClientServerPerf)
    target_link_libraries(TuicClientServerPerf PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismProtocolTuic PrismTestSupport)
endif()
AddPrismTest(Connection/ErrorMatrix.cpp TuicConnErrorMatrix)
target_link_libraries(TuicConnErrorMatrix PRIVATE PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(Codec/DgramDeep.cpp TuicDgramDeep)
target_link_libraries(TuicDgramDeep PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(Datagram/ProviderTest.cpp TuicDgramProviderTest)
target_link_libraries(TuicDgramProviderTest PRIVATE PrismFoundation PrismTransport PrismProtocolQuic PrismProtocolTuic PrismTestSupport)
AddPrismTest(Datagram/ErrorTest.cpp TuicDatagramErrorTest)
target_link_libraries(TuicDatagramErrorTest PRIVATE PrismFoundation PrismTransport PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicDatagramErrorTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/CodecFuzzTest.cpp TuicCodecFuzzTest)
target_link_libraries(TuicCodecFuzzTest PRIVATE PrismProtocolTuic PrismTestSupport)
AddPrismTest(Codec/DeepTest.cpp TuicCodecDeepTest)
target_link_libraries(TuicCodecDeepTest PRIVATE PrismFoundation PrismProtocolTuic PrismTestSupport)
target_compile_options(TuicCodecDeepTest PRIVATE -O0 -fno-inline)
AddPrismTest(Codec/RoundtripTest.cpp TuicCodecRoundtripTest)
target_link_libraries(TuicCodecRoundtripTest PRIVATE PrismFoundation PrismProtocolTuic)
AddPrismTest(Connection/Session.cpp TuicConnSession)
target_link_libraries(TuicConnSession PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolTuic PrismTestSupport)

AddPrismTest(Connection/DgramTerminalTest.cpp TuicTerminalReadTest)
target_sources(TuicTerminalReadTest PRIVATE
    Connection/ConnTerminalTest.cpp
    Connection/DgramFragmentReadTest.cpp
    Connection/AuthTerminalReadTest.cpp
    Connection/TerminalReadSupport.hpp)
target_link_libraries(TuicTerminalReadTest PRIVATE
    PrismAccount
    PrismFoundation
    PrismIoContracts
    PrismTransport
    PrismProtocolTuic)

AddPrismTest(Admission/AdmissionTest.cpp TuicAdmissionTest)
target_link_libraries(TuicAdmissionTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)
AddPrismTest(Admission/CloseTest.cpp TuicAdmissionCloseTest)
target_link_libraries(TuicAdmissionCloseTest PRIVATE
    PrismAccount PrismFoundation PrismIoContracts PrismLifecycle PrismProtocolsCommon
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismTransport PrismProtocolTuic PrismTestSupport)

AddPrismTest(Admission/FactoryTest.cpp TuicFactoryTest)
target_sources(TuicFactoryTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(
    TuicFactoryTest PRIVATE PrismFoundation PrismAccount PrismTransport PrismNet
                            PrismRuntime PrismProtocolQuic PrismProtocolQuicNative
                            PrismProtocolTuic PrismTestSupport)
