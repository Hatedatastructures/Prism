# Mux root 经真实 Runtime Session 的集成场景
AddPrismTest(E2ETest.cpp MuxE2ETest)
target_link_libraries(MuxE2ETest PRIVATE PrismRuntime PrismProtocolTrojan PrismProtocolMux
    PrismIngressContract PrismTestSupport)

AddPrismTest(ProviderConfigTest.cpp ConfiguredMuxProviderTest)
target_sources(ConfiguredMuxProviderTest PRIVATE ProviderFallbackTest.cpp)
target_link_libraries(ConfiguredMuxProviderTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolWs PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(CarrierFallbackTest.cpp MuxCarrierFallbackTest)
target_link_libraries(MuxCarrierFallbackTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolSocks5 PrismProtocolWs
    PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(AdmissionTest.cpp MuxSessionAdmissionTest)
AddPrismTest(Socks5RootTest.cpp MuxSocks5RootTest)
AddPrismTest(Ss2022RootTest.cpp MuxSs2022RootTest)
AddPrismTest(VlessSessionTest.cpp MuxVlessSessionTest)
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
target_sources(MuxSessionAdmissionTest PRIVATE ScenarioTypes.hpp ScenarioFlow.hpp ScenarioSetup.hpp ScenarioAsserts.hpp)
target_sources(MuxSocks5RootTest PRIVATE ScenarioTypes.hpp ScenarioFlow.hpp ScenarioSetup.hpp ScenarioAsserts.hpp MultiRootTypes.hpp MultiRootFlow.hpp)
target_sources(MuxSs2022RootTest PRIVATE ScenarioTypes.hpp ScenarioFlow.hpp ScenarioSetup.hpp ScenarioAsserts.hpp MultiRootTypes.hpp MultiRootFlow.hpp)
target_sources(MuxVlessSessionTest PRIVATE ScenarioTypes.hpp)
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

AddPrismTest(RootOwnerTest.cpp MuxRootOwnerTest)
target_sources(MuxRootOwnerTest PRIVATE
    RootFinishFailureTest.cpp
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux/RootCloseTestSupport.hpp"
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux/AcceptSupport.hpp")
target_include_directories(MuxRootOwnerTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Test/Prism/Protocols/Mux/Mux")
target_link_libraries(MuxRootOwnerTest PRIVATE
    PrismProtocolTrojan PrismProtocolMux PrismAccount PrismIngressContract
    PrismFoundation PrismLifecycle PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime)

AddPrismTest(H2RootOwnerTest.cpp MuxH2RootOwnerTest)
target_link_libraries(MuxH2RootOwnerTest PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolHttp2 PrismProtocolMux)
