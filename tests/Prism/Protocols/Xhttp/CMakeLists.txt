# xhttp 子模块
AddPrismTest(XhttpNgxE2E.cpp)
target_link_libraries(XhttpNgxE2E PRIVATE PrismTransport PrismProtocolHttp2 PrismProtocolXhttp PrismTestSupport)
AddPrismTest(XhttpNgxFactoryE2E.cpp)
target_link_libraries(XhttpNgxFactoryE2E PRIVATE PrismTransport PrismProtocolHttp2 PrismProtocolXhttp PrismTestSupport)

AddPrismTest(XhttpErrorMatrix.cpp)
target_link_libraries(XhttpErrorMatrix PRIVATE PrismProtocolXhttp PrismTestSupport)
AddPrismTest(XhttpErrorCloseMatrix.cpp)
target_link_libraries(XhttpErrorCloseMatrix PRIVATE PrismProtocolXhttp PrismTestSupport)

# 同一实际owner的源文件，复用现有target。
target_sources(XhttpNgxE2E PRIVATE
    XhttpTestRetirement.hpp
)
