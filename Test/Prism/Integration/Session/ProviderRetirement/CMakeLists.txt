AddPrismTest(ProviderRetireTest.cpp)
target_link_libraries(ProviderRetireTest PRIVATE
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
AddPrismTest(DrainHoldTest.cpp ProviderDrainHoldTest)
target_link_libraries(ProviderDrainHoldTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolProviderLifecycle
    PrismProtocolsCommon PrismTestSupport PrismTransport)
AddPrismTest(DrainCoordTest.cpp ProviderDrainCoordTest)
target_link_libraries(ProviderDrainCoordTest PRIVATE PrismProtocolsCommon PrismTestSupport)
