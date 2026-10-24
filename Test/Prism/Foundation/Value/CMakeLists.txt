# Foundation 值类型测试。
AddPrismTest(ByteSpanTest.cpp)
target_link_libraries(ByteSpanTest PRIVATE PrismFoundation PrismTestSupport)
target_compile_options(ByteSpanTest PRIVATE -O0 -fno-inline)
AddPrismTest(ValuesTest.cpp)
target_link_libraries(ValuesTest PRIVATE PrismFoundation)
