# configuration 子模块测试
AddPrismTest(ConfigurationAssemblyTest.cpp)
AddPrismTest(ConfigurationPreflightTest.cpp)
AddPrismTest(ConfigurationSchemaTest.cpp)
AddPrismTest(ConfigurationSecretTest.cpp)
AddPrismTest(ConfigCapabilityTest.cpp)
AddPrismTest(ConfigGenerationTest.cpp)
target_link_libraries(ConfigurationAssemblyTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition PrismNetworkModel PrismProtocolVless
    PrismRuntime PrismTestSupport)
target_sources(ConfigurationAssemblyTest PRIVATE ConfigurationTestSupport.hpp)
target_link_libraries(ConfigurationPreflightTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationPreflightTest PRIVATE ConfigurationTestSupport.hpp)
target_link_libraries(ConfigurationSchemaTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationSchemaTest PRIVATE ConfigurationTestSupport.hpp)
target_link_libraries(ConfigurationSecretTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationSecretTest PRIVATE ConfigurationTestSupport.hpp)
target_link_libraries(ConfigCapabilityTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigCapabilityTest PRIVATE ConfigurationTestSupport.hpp)
target_link_libraries(ConfigGenerationTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigGenerationTest PRIVATE ConfigurationTestSupport.hpp)
AddPrismTest(ConfigurationOrderTest.cpp)
target_link_libraries(ConfigurationOrderTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(ValidationHeadersTest.cpp)
target_link_libraries(ValidationHeadersTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(SecretResolutionStageTest.cpp)
target_link_libraries(SecretResolutionStageTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(ConfigStageOrderTest.cpp)
target_link_libraries(ConfigStageOrderTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition)
foreach(PrismConfigurationWhiteboxTarget IN ITEMS
        ConfigurationOrderTest
        ValidationHeadersTest)
    target_include_directories(${PrismConfigurationWhiteboxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()
