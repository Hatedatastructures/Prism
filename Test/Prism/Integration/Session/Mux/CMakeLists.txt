# Mux root 经真实 Runtime Session 的集成场景
AddPrismTest(MuxE2ETest.cpp)
target_link_libraries(MuxE2ETest PRIVATE PrismRuntime PrismProtocolTrojan PrismProtocolMux
    PrismIngressContract PrismTestSupport)

AddPrismTest(ConfiguredMuxProviderTest.cpp)
target_sources(ConfiguredMuxProviderTest PRIVATE MuxProviderFallbackTest.cpp)
target_link_libraries(ConfiguredMuxProviderTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolWs PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(MuxCarrierFallbackTest.cpp)
target_link_libraries(MuxCarrierFallbackTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolSocks5 PrismProtocolWs
    PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(MuxSessionAdmissionTest.cpp)
AddPrismTest(MuxSocks5RootTest.cpp)
AddPrismTest(MuxSs2022RootTest.cpp)
AddPrismTest(MuxVlessSessionTest.cpp)
set(PrismConfiguredMuxSessionOwners
    PrismAccount PrismConfiguration PrismFoundation PrismProtocolMux
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVless
    PrismRuntime PrismTransport)
target_link_libraries(MuxSessionAdmissionTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(MuxSocks5RootTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(MuxSs2022RootTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(MuxVlessSessionTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_sources(MuxSessionAdmissionTest PRIVATE MuxScenarioTypes.hpp MuxScenarioFlow.hpp MuxScenarioSetup.hpp MuxScenarioAsserts.hpp)
target_sources(MuxSocks5RootTest PRIVATE MuxScenarioTypes.hpp MuxScenarioFlow.hpp MuxScenarioSetup.hpp MuxScenarioAsserts.hpp MuxMultiRootTypes.hpp ConfiguredMuxMultiRootFlow.hpp)
target_sources(MuxSs2022RootTest PRIVATE MuxScenarioTypes.hpp MuxScenarioFlow.hpp MuxScenarioSetup.hpp MuxScenarioAsserts.hpp MuxMultiRootTypes.hpp ConfiguredMuxMultiRootFlow.hpp)
target_sources(MuxVlessSessionTest PRIVATE MuxScenarioTypes.hpp)
foreach(PrismConfiguredMuxTarget IN ITEMS
        ConfiguredMuxProviderTest
        MuxCarrierFallbackTest
        MuxSessionAdmissionTest
        MuxSocks5RootTest
        MuxSs2022RootTest
        MuxVlessSessionTest)
    target_include_directories(${PrismConfiguredMuxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()

AddPrismTest(MuxRootOwnerTest.cpp)
target_sources(MuxRootOwnerTest PRIVATE
    MuxRootFinishFailureTest.cpp
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux/MuxRootCloseTestSupport.hpp"
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux/MuxAcceptSupport.hpp")
target_include_directories(MuxRootOwnerTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux")
target_link_libraries(MuxRootOwnerTest PRIVATE
    PrismProtocolTrojan PrismProtocolMux PrismAccount PrismIngressContract
    PrismFoundation PrismLifecycle PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime)

AddPrismTest(MuxH2RootOwnerTest.cpp)
target_link_libraries(MuxH2RootOwnerTest PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolHttp2 PrismProtocolMux)
