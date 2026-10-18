AddPrismTest(Task10OperationsTest.cpp)
target_link_libraries(Task10OperationsTest PRIVATE PrismOperations)
target_sources(Task10OperationsTest PRIVATE OperationsHttpAuthTestSupport.hpp)
target_sources(Task10OperationsTest PRIVATE OperationPublicationTest.cpp)

AddPrismTest(OperationsHttpTest.cpp)
target_link_libraries(OperationsHttpTest PRIVATE PrismApplication PrismOperations)
target_sources(OperationsHttpTest PRIVATE OperationsHttpAuthTestSupport.hpp)

AddPrismTest(OperationsDrainContractTest.cpp)
target_link_libraries(OperationsDrainContractTest PRIVATE PrismOperations)
target_sources(OperationsDrainContractTest PRIVATE OperationsHttpAuthTestSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(OperationsHttpTest PRIVATE
    ConfigurationOutcomeHttpTest.cpp
    ConfigurationRestartFieldsTest.cpp
    OperationsMetadataTest.cpp
    ManagementQueryContractTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(OperationsHttpTest PRIVATE
    OperationsWebHttpRuntimeTest.cpp
    OperationsWebResourcesTest.cpp
)
