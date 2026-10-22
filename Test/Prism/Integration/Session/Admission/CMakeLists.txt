# 跨协议 admission/adapter 与统一 reply 错误场景
AddPrismTest(AdapterAdmissionTest.cpp)
AddPrismTest(AdapterErrorMappingTest.cpp)
target_link_libraries(AdapterAdmissionTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismAccount
    PrismProtocolAnytls PrismProtocolHttp PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess
    PrismProtocolShadowsocks2022
    PrismIngressContract PrismTestSupport)
target_sources(AdapterAdmissionTest PRIVATE AdapterTestSupport.hpp)
target_sources(AdapterAdmissionTest PRIVATE AccountLeaseAdmissionTest.cpp)
target_link_libraries(AdapterErrorMappingTest PRIVATE PrismFoundation PrismTransport PrismRuntime PrismComposition
    PrismAccount PrismIngressContract PrismProtocolAnytls PrismProtocolHttp PrismProtocolShadowsocks2022
    PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)
target_sources(AdapterErrorMappingTest PRIVATE AdapterTestSupport.hpp)
AddPrismTest(AdapterMuxLeaseTest.cpp)
target_link_libraries(AdapterMuxLeaseTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismAccount PrismProtocolMux
    PrismProtocolAnytls PrismProtocolTrojan PrismProtocolVless PrismProtocolVmess PrismTestSupport)

AddPrismTest(PostDialReplyFailureTest.cpp)
target_link_libraries(PostDialReplyFailureTest PRIVATE
    PrismFoundation PrismTransport PrismRuntime PrismComposition PrismAccount
    PrismProtocolHttp PrismProtocolSocks5 PrismTestSupport)

AddPrismTest(ProviderAcceptPathTest.cpp)
target_link_libraries(ProviderAcceptPathTest PRIVATE
    PrismApplication PrismComposition PrismFoundation PrismRuntime PrismTransport)
target_sources(ProviderAcceptPathTest PRIVATE
    ProviderDrainOwnershipTest.cpp)
AddPrismTest(ProviderClosingOwnerTest.cpp)
target_link_libraries(ProviderClosingOwnerTest PRIVATE PrismApplication PrismComposition PrismFoundation
    PrismProtocolsCommon PrismRuntime PrismTransport PrismTestSupport)
target_include_directories(ProviderAcceptPathTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Src")
target_include_directories(ProviderClosingOwnerTest PRIVATE
    "${PROJECT_SOURCE_DIR}/Src")
