AddPreviewTest(Task10OperationsTest.cpp)
target_link_libraries(Task10OperationsTest PRIVATE PreviewOperations)
target_sources(Task10OperationsTest PRIVATE OperationsHttpAuthTestSupport.hpp)
target_sources(Task10OperationsTest PRIVATE OperationPublicationTest.cpp)

AddPreviewTest(OperationsHttpTest.cpp)
target_link_libraries(OperationsHttpTest PRIVATE PreviewApplication PreviewOperations)
target_sources(OperationsHttpTest PRIVATE OperationsHttpAuthTestSupport.hpp)

AddPreviewTest(OperationsDrainContractTest.cpp)
target_link_libraries(OperationsDrainContractTest PRIVATE PreviewOperations)
target_sources(OperationsDrainContractTest PRIVATE OperationsHttpAuthTestSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(OperationsHttpTest PRIVATE
    ConfigurationOutcomeHttpTest.cpp
    ConfigurationRestartFieldsTest.cpp
    OperationsMetadataTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(OperationsHttpTest PRIVATE
    OperationsWebHttpRuntimeTest.cpp
    OperationsWebResourcesTest.cpp
)
