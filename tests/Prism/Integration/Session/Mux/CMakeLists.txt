# Mux root 经真实 Runtime Session 的集成场景
AddPrismTest(MuxE2ETest.cpp)
target_link_libraries(MuxE2ETest PRIVATE PrismRuntime PrismProtocolTrojan PrismProtocolMux
    PrismIngressContract PrismTestSupport)

AddPrismTest(ConfiguredMuxProviderTest.cpp)
target_sources(ConfiguredMuxProviderTest PRIVATE ConfiguredMuxProviderFallbackTest.cpp)
target_link_libraries(ConfiguredMuxProviderTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolWs PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(ConfiguredMuxCarrierFallbackTest.cpp)
target_link_libraries(ConfiguredMuxCarrierFallbackTest PRIVATE PrismApplication PrismComposition
    PrismDatagramContract PrismFoundation PrismProtocolSocks5 PrismProtocolWs
    PrismRuntime PrismTransport PrismTestSupport)
AddPrismTest(ConfiguredMuxSessionAdmissionTest.cpp)
AddPrismTest(ConfiguredMuxSessionSocks5RootTest.cpp)
AddPrismTest(ConfiguredMuxSessionSs2022RootTest.cpp)
AddPrismTest(ConfiguredMuxSessionVlessTest.cpp)
set(PrismConfiguredMuxSessionOwners
    PrismAccount PrismConfiguration PrismFoundation PrismProtocolMux
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismProtocolVless
    PrismRuntime PrismTransport)
target_link_libraries(ConfiguredMuxSessionAdmissionTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(ConfiguredMuxSessionSocks5RootTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(ConfiguredMuxSessionSs2022RootTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_link_libraries(ConfiguredMuxSessionVlessTest PRIVATE PrismApplication PrismComposition
    ${PrismConfiguredMuxSessionOwners} PrismTestSupport)
target_sources(ConfiguredMuxSessionAdmissionTest PRIVATE ConfiguredMuxSessionScenarioTypes.hpp ConfiguredMuxSessionScenarioFlow.hpp ConfiguredMuxSessionScenarioSetup.hpp ConfiguredMuxSessionScenarioAssertions.hpp)
target_sources(ConfiguredMuxSessionSocks5RootTest PRIVATE ConfiguredMuxSessionScenarioTypes.hpp ConfiguredMuxSessionScenarioFlow.hpp ConfiguredMuxSessionScenarioSetup.hpp ConfiguredMuxSessionScenarioAssertions.hpp ConfiguredMuxMultiRootTypes.hpp ConfiguredMuxMultiRootFlow.hpp)
target_sources(ConfiguredMuxSessionSs2022RootTest PRIVATE ConfiguredMuxSessionScenarioTypes.hpp ConfiguredMuxSessionScenarioFlow.hpp ConfiguredMuxSessionScenarioSetup.hpp ConfiguredMuxSessionScenarioAssertions.hpp ConfiguredMuxMultiRootTypes.hpp ConfiguredMuxMultiRootFlow.hpp)
target_sources(ConfiguredMuxSessionVlessTest PRIVATE ConfiguredMuxSessionScenarioTypes.hpp)
foreach(PrismConfiguredMuxTarget IN ITEMS
        ConfiguredMuxProviderTest
        ConfiguredMuxCarrierFallbackTest
        ConfiguredMuxSessionAdmissionTest
        ConfiguredMuxSessionSocks5RootTest
        ConfiguredMuxSessionSs2022RootTest
        ConfiguredMuxSessionVlessTest)
    target_include_directories(${PrismConfiguredMuxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()

AddPrismTest(MuxRootOwnerTest.cpp)
target_sources(MuxRootOwnerTest PRIVATE
    MuxRootFinishFailureTest.cpp
    "${PROJECT_SOURCE_DIR}/tests/Prism/Protocols/Mux/MuxRootCloseTestSupport.hpp"
    "${PROJECT_SOURCE_DIR}/tests/Prism/Protocols/Mux/MuxStreamAcceptInputTestSupport.hpp")
target_include_directories(MuxRootOwnerTest PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/Prism/Protocols/Mux")
target_link_libraries(MuxRootOwnerTest PRIVATE
    PrismProtocolTrojan PrismProtocolMux PrismAccount PrismIngressContract
    PrismFoundation PrismLifecycle PrismTransport PrismProtocolHttp
    PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime)

AddPrismTest(MuxH2RootOwnerTest.cpp)
target_link_libraries(MuxH2RootOwnerTest PRIVATE
    PrismAccount PrismFoundation PrismRuntime PrismTransport
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5
    PrismProtocolTrojan PrismProtocolHttp2 PrismProtocolMux)
