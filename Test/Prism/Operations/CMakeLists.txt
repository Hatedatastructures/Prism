AddPrismTest(Management/Task10OperationsTest.cpp)
target_link_libraries(Task10OperationsTest PRIVATE PrismOperations PrismStatistics)
target_sources(Task10OperationsTest PRIVATE Http/OperationsAuthSupport.hpp)
target_sources(Task10OperationsTest PRIVATE Management/OperationPublicationTest.cpp)
target_sources(Task10OperationsTest PRIVATE Http/OperationsParserTest.cpp)
target_include_directories(Task10OperationsTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")

AddPrismTest(Http/OperationsHttpTest.cpp)
target_link_libraries(OperationsHttpTest PRIVATE
    PrismApplication PrismFoundation PrismOperations PrismRuntime PrismStatistics)
target_sources(OperationsHttpTest PRIVATE Http/OperationsAuthSupport.hpp)

AddPrismTest(Management/OperationsDrainTest.cpp)
target_link_libraries(OperationsDrainTest PRIVATE PrismOperations)
target_sources(OperationsDrainTest PRIVATE Http/OperationsAuthSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(OperationsHttpTest PRIVATE
    Http/HttpConnectionEndTest.cpp
    Http/HttpDeadlineDrainTest.cpp
    Http/ConfigOutcomeHttpTest.cpp
    Configuration/ConfigRestartFieldsTest.cpp
    Management/OperationsMetadataTest.cpp
    Management/ManagementQueryTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(OperationsHttpTest PRIVATE
    Web/OperationsWebRuntimeTest.cpp
    Web/OperationsWebResourcesTest.cpp
    Web/OperationsWebTestSupport.hpp
)
target_include_directories(OperationsHttpTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
