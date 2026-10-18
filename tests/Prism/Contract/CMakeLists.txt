AddPrismTest(Task9ContractTest.cpp)
target_link_libraries(Task9ContractTest PRIVATE
        PrismComposition
        PrismProtocolHysteria2
        PrismProtocolTuic
        PrismTransport)
