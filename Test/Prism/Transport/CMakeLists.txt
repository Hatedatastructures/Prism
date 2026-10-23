# transport 子模块测试
AddPrismTest(Decorators/ConnDecoratorDeep.cpp)
target_link_libraries(ConnDecoratorDeep PRIVATE PrismFoundation PrismTransport PrismProtocolAnytls PrismProtocolGun
    PrismProtocolMux PrismProtocolReality PrismProtocolTuic)
target_compile_options(ConnDecoratorDeep PRIVATE -O0 -fno-inline)
AddPrismTest(Core/TransmissionLayerTest.cpp)
AddPrismTest(Core/TransmissionHandlerTest.cpp)
target_link_libraries(TransmissionLayerTest PRIVATE
    PrismFoundation PrismIoContracts PrismProtocolsCommon PrismTransport PrismTestSupport)
target_include_directories(TransmissionLayerTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_sources(TransmissionLayerTest PRIVATE Core/TransmissionSupport.hpp)
target_link_libraries(TransmissionHandlerTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(TransmissionHandlerTest PRIVATE Core/TransmissionSupport.hpp)
AddPrismTest(Core/PrismTransmissionTest.cpp)
target_link_libraries(PrismTransmissionTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Core/MockTransportContractTest.cpp)
target_link_libraries(MockTransportContractTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Tls/NativeTlsTest.cpp)
target_link_libraries(NativeTlsTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Core/TestPsmTransport.cpp)
target_link_libraries(TestPsmTransport PRIVATE PrismFoundation PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Decorators/PadTransportTest.cpp)
AddPrismTest(Decorators/PreviewTransportTest.cpp)
AddPrismTest(Decorators/EncryptedDecoratorTest.cpp)
AddPrismTest(Core/ConnectorTest.cpp)
AddPrismTest(Reliable/ReliableTransportTest.cpp)
AddPrismTest(Unreliable/UnreliableTransportTest.cpp)
AddPrismTest(Reliable/ReliableCallbackTest.cpp)
target_link_libraries(PadTransportTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(PadTransportTest PRIVATE Core/TransportDecoratorSupport.hpp)
target_link_libraries(PreviewTransportTest PRIVATE PrismFoundation PrismIoContracts PrismTransport PrismTestSupport)
target_sources(PreviewTransportTest PRIVATE Core/TransportDecoratorSupport.hpp Decorators/ReplayCloseUnderlyingTest.cpp)
target_link_libraries(EncryptedDecoratorTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismTestSupport)
target_sources(EncryptedDecoratorTest PRIVATE Core/TransportDecoratorSupport.hpp)
target_link_libraries(ConnectorTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(ConnectorTest PRIVATE Core/TransportDecoratorSupport.hpp)
target_link_libraries(ReliableTransportTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(ReliableTransportTest PRIVATE Core/TransportDecoratorSupport.hpp)
target_link_libraries(UnreliableTransportTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(UnreliableTransportTest PRIVATE Core/TransportDecoratorSupport.hpp)
target_link_libraries(ReliableCallbackTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Core/TransportTest.cpp)
target_link_libraries(TransportTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_sources(TransportTest PRIVATE Memory/MemoryStreamTest.cpp Memory/MemoryStreamThroughputTest.cpp)
target_sources(ReliableTransportTest PRIVATE Reliable/ReliableTimeoutTest.cpp)
target_sources(UnreliableTransportTest PRIVATE Unreliable/UnreliableTimeoutTest.cpp)

AddPrismTest(Benchmark/BenchmarkResultTest.cpp)
target_link_libraries(BenchmarkResultTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Core/TransportCoverageTest.cpp)
target_link_libraries(TransportCoverageTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
AddPrismTest(Decorators/PadOwnershipAuditTest.cpp)
target_link_libraries(PadOwnershipAuditTest PRIVATE PrismFoundation PrismTransport PrismTestSupport)
target_compile_options(TestPsmTransport PRIVATE -O0 -fno-inline)
target_compile_options(PadTransportTest PRIVATE -O0 -fno-inline)
target_compile_options(PreviewTransportTest PRIVATE -O0 -fno-inline)
target_compile_options(EncryptedDecoratorTest PRIVATE -O0 -fno-inline)
target_compile_options(ConnectorTest PRIVATE -O0 -fno-inline)
target_compile_options(ReliableTransportTest PRIVATE -O0 -fno-inline)
target_compile_options(UnreliableTransportTest PRIVATE -O0 -fno-inline)
target_compile_options(ReliableCallbackTest PRIVATE -O0 -fno-inline)

# _FORTIFY_SOURCE 决定 Boost.Asio endpoint 存储布局，UDP 测试 TU 必须与生产库一致。
if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    foreach(TransportFortifyTarget IN ITEMS TestPsmTransport UnreliableTransportTest)
        target_compile_options(${TransportFortifyTarget} PRIVATE
            "$<$<CONFIG:Debug>:-U_FORTIFY_SOURCE>"
            "$<$<CONFIG:Release>:-O1>"
            "$<$<CONFIG:RelWithDebInfo>:-O1>"
            "$<$<CONFIG:MinSizeRel>:-O1>")
    endforeach()
endif()




# 仅实际消费共享有界池fixture的既有target登记。
foreach(TransportResourceTarget IN ITEMS
    ConnDecoratorDeep ConnectorTest EncryptedDecoratorTest NativeTlsTest PadOwnershipAuditTest
    PadTransportTest PreviewTransportTest ReliableTransportTest TestPsmTransport TransmissionLayerTest
    TransportCoverageTest TransportTest UnreliableTransportTest)
target_sources(${TransportResourceTarget} PRIVATE Core/TransportResources.hpp)
endforeach()

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(TransmissionLayerTest PRIVATE
    Decorators/CarrierActivityReceiptTest.cpp
)
