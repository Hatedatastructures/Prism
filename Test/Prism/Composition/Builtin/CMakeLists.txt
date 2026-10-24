# Composition 内建描述符与能力测试。
AddPrismTest(BuiltinRegistryTest.cpp)
AddPrismTest(BuiltinTest.cpp)
target_link_libraries(BuiltinRegistryTest PRIVATE PrismComposition)
target_link_libraries(BuiltinTest PRIVATE PrismComposition)
