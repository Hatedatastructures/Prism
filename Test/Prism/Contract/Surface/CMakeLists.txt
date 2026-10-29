# 公共契约表面测试。
AddPrismTest(ContractTest.cpp SurfaceContractTest)
target_link_libraries(SurfaceContractTest PRIVATE
    PrismComposition
    PrismIngressContract
    PrismProtocolHysteria2
    PrismProtocolTuic
    PrismTransport)
