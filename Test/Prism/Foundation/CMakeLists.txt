# Foundation value and error contracts.
add_subdirectory(Context)
add_subdirectory(Traffic)
add_subdirectory(Value)
AddPrismTest(Storage/SqliteTest.cpp)
target_link_libraries(SqliteTest PRIVATE PrismFoundation)
