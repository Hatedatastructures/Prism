AddPrismTest(Task9ContractTest.cpp)
target_link_libraries(Task9ContractTest PRIVATE
        PrismComposition
        PrismIngressContract
        PrismProtocolHysteria2
        PrismProtocolTuic
        PrismTransport)

AddPrismTest(AdmissionTransportRetirementTest.cpp)
target_link_libraries(AdmissionTransportRetirementTest PRIVATE
    PrismIngressContract PrismIoContracts PrismFoundation PrismTransport)
