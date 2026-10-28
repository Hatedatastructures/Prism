# configuration 子模块测试
AddPrismTest(AssemblyTest.cpp ConfigurationAssemblyTest)
AddPrismTest(PreflightTest.cpp ConfigurationPreflightTest)
AddPrismTest(SchemaTest.cpp ConfigurationSchemaTest)
AddPrismTest(SecretTest.cpp ConfigurationSecretTest)
AddPrismTest(CapabilityTest.cpp ConfigCapabilityTest)
AddPrismTest(GenerationTest.cpp ConfigGenerationTest)
target_link_libraries(ConfigurationAssemblyTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition PrismNetworkModel PrismProtocolVless
    PrismRuntime PrismTestSupport)
target_sources(ConfigurationAssemblyTest PRIVATE ConfigSupport.hpp)
target_link_libraries(ConfigurationPreflightTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationPreflightTest PRIVATE ConfigSupport.hpp)
target_link_libraries(ConfigurationSchemaTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationSchemaTest PRIVATE ConfigSupport.hpp)
target_link_libraries(ConfigurationSecretTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigurationSecretTest PRIVATE ConfigSupport.hpp)
target_link_libraries(ConfigCapabilityTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigCapabilityTest PRIVATE ConfigSupport.hpp)
target_link_libraries(ConfigGenerationTest PRIVATE
    PrismConfiguration PrismComposition PrismRuntime PrismTestSupport)
target_sources(ConfigGenerationTest PRIVATE ConfigSupport.hpp)
AddPrismTest(OrderTest.cpp ConfigurationOrderTest)
target_link_libraries(ConfigurationOrderTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(ValidationHeadersTest.cpp)
target_link_libraries(ValidationHeadersTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(SecretStageTest.cpp SecretResolutionStageTest)
target_link_libraries(SecretResolutionStageTest PRIVATE PrismConfiguration PrismComposition PrismTestSupport)
AddPrismTest(StageOrderTest.cpp ConfigStageOrderTest)
target_link_libraries(ConfigStageOrderTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition)
foreach(PrismConfigurationWhiteboxTarget IN ITEMS
        ConfigurationOrderTest
        ValidationHeadersTest)
    target_include_directories(${PrismConfigurationWhiteboxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()
