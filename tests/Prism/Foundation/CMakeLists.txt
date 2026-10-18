# Foundation value and error contracts.
AddPrismTest(FoundationValuesTest.cpp)
target_link_libraries(FoundationValuesTest PRIVATE PrismFoundation)
AddPrismTest(Storage/SqliteTest.cpp)
target_link_libraries(SqliteTest PRIVATE PrismFoundation)
AddPrismTest(ByteSpanTest.cpp)
target_link_libraries(ByteSpanTest PRIVATE PrismFoundation PrismTestSupport)
target_compile_options(ByteSpanTest PRIVATE -O0 -fno-inline)

# Foundation 契约测试
AddPrismTest(TrafficSinkContractTest.cpp)
target_link_libraries(TrafficSinkContractTest PRIVATE PrismFoundation)
