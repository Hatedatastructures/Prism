AddPrismTest(Management/ManagementTest.cpp Task10OperationsTest)
target_link_libraries(Task10OperationsTest PRIVATE PrismOperations PrismStatistics)
target_sources(Task10OperationsTest PRIVATE Http/AuthSupport.hpp)
target_sources(Task10OperationsTest PRIVATE Management/PublicationTest.cpp)
target_sources(Task10OperationsTest PRIVATE Http/ParserTest.cpp)
target_include_directories(Task10OperationsTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")

AddPrismTest(Http/HttpTest.cpp OperationsHttpTest)
target_link_libraries(OperationsHttpTest PRIVATE
    PrismApplication PrismFoundation PrismOperations PrismRuntime PrismStatistics)
target_sources(OperationsHttpTest PRIVATE Http/AuthSupport.hpp)

AddPrismTest(Management/DrainTest.cpp OperationsDrainTest)
target_link_libraries(OperationsDrainTest PRIVATE PrismOperations)
target_sources(OperationsDrainTest PRIVATE Http/AuthSupport.hpp)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(OperationsHttpTest PRIVATE
    Http/ConnectionEndTest.cpp
    Http/DeadlineDrainTest.cpp
    Http/ConfigOutcomeHttpTest.cpp
    Configuration/RestartFieldsTest.cpp
    Management/MetadataTest.cpp
    Management/QueryTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(OperationsHttpTest PRIVATE
    Web/RuntimeTest.cpp
    Web/ResourcesTest.cpp
    Web/WebTestSupport.hpp
)
target_include_directories(OperationsHttpTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
