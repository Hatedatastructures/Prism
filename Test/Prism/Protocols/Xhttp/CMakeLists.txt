# xhttp 子模块
AddPrismTest(Core/StreamOneTest.cpp XhttpNgxE2E)
target_include_directories(XhttpNgxE2E PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(XhttpNgxE2E PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolHttp2 PrismProtocolXhttp
    OpenSSL::SSL OpenSSL::Crypto)
AddPrismTest(Admission/FactoryTest.cpp XhttpNgxFactoryE2E)
target_include_directories(XhttpNgxFactoryE2E PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(XhttpNgxFactoryE2E PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolHttp2 PrismProtocolXhttp
    OpenSSL::SSL OpenSSL::Crypto)
target_sources(XhttpNgxFactoryE2E PRIVATE Core/FactoryScenario.hpp)

AddPrismTest(Core/ErrorMatrix.cpp XhttpErrorMatrix)
target_include_directories(XhttpErrorMatrix PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(XhttpErrorMatrix PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolHttp2 PrismProtocolXhttp)
target_sources(XhttpErrorMatrix PRIVATE Connection/ReadTerminalTest.cpp)
AddPrismTest(Connection/ErrorCloseMatrix.cpp XhttpErrorCloseMatrix)
target_include_directories(XhttpErrorCloseMatrix PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(XhttpErrorCloseMatrix PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolHttp2 PrismProtocolXhttp)

# 同一实际owner的源文件，复用现有target。
target_sources(XhttpNgxE2E PRIVATE
    Core/Retirement.hpp
)
