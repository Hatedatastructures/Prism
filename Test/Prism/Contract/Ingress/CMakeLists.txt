# Ingress 契约退役测试。
AddPrismTest(AdmissionRetireTest.cpp)
target_link_libraries(AdmissionRetireTest PRIVATE
    PrismIngressContract PrismIoContracts PrismFoundation PrismTransport)
