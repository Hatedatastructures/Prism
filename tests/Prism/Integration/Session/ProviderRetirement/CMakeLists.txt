AddPrismTest(ProviderSessionRetirementTest.cpp)
target_link_libraries(ProviderSessionRetirementTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolProviderLifecycle PrismProtocolQuic
    PrismProtocolVless PrismProtocolsCommon PrismRuntime PrismTestSupport PrismTransport)
AddPrismTest(BindingLifetimeTest.cpp)
target_sources(BindingLifetimeTest PRIVATE BindingRetentionTest.cpp)
target_link_libraries(BindingLifetimeTest PRIVATE
    PrismProtocolsCommon PrismFoundation PrismAccount PrismIoContracts PrismDatagramContract
    PrismNetworkModel PrismRuntime PrismTransport PrismProtocolSocks5 PrismProtocolShadowsocks2022
    PrismTestSupport)
set(_binding_lifetime_labels_file "${CMAKE_CURRENT_BINARY_DIR}/BindingLifetimeLabels.cmake")
file(GENERATE
    OUTPUT "${_binding_lifetime_labels_file}"
    CONTENT [=[
if(DEFINED BindingLifetimeTest_TESTS AND BindingLifetimeTest_TESTS)
    set_tests_properties(${BindingLifetimeTest_TESTS} PROPERTIES LABELS integration)
endif()
]=])
set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${_binding_lifetime_labels_file}")
AddPrismTest(ProviderAdmissionDrainRetentionTest.cpp)
target_link_libraries(ProviderAdmissionDrainRetentionTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolProviderLifecycle
    PrismProtocolsCommon PrismTestSupport PrismTransport)
AddPrismTest(ProviderSessionDrainCoordinatorTest.cpp)
target_link_libraries(ProviderSessionDrainCoordinatorTest PRIVATE PrismProtocolsCommon PrismTestSupport)
