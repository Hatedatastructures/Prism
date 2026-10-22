# 公共契约表面测试。
AddPrismTest(SurfaceContractTest.cpp)
target_link_libraries(SurfaceContractTest PRIVATE
    PrismComposition
    PrismIngressContract
    PrismProtocolHysteria2
    PrismProtocolTuic
    PrismTransport)
