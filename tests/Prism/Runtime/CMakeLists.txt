# Runtime 子模块测试
AddPrismTest(ListenerAdmissionTest.cpp)
AddPrismTest(ListenerSessionShutdownTest.cpp)
AddPrismTest(ListenerLifecycleTest.cpp)
AddPrismTest(ListenerCapacityTest.cpp)
AddPrismTest(ListenerAcceptRecoveryTest.cpp)
AddPrismTest(ListenerMuxShutdownTest.cpp)
target_link_libraries(ListenerAdmissionTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerAdmissionTest PRIVATE ListenerTestSupport.hpp)
target_link_libraries(ListenerSessionShutdownTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerSessionShutdownTest PRIVATE ListenerTestSupport.hpp)
target_link_libraries(ListenerLifecycleTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerLifecycleTest PRIVATE ListenerTestSupport.hpp)
target_link_libraries(ListenerCapacityTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerCapacityTest PRIVATE ListenerTestSupport.hpp)
target_link_libraries(ListenerAcceptRecoveryTest PRIVATE PrismFoundation PrismRuntime PrismTestSupport)
target_link_libraries(ListenerMuxShutdownTest PRIVATE
    PrismFoundation PrismIngressContract PrismIoContracts PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(ListenerMuxShutdownTest PRIVATE ListenerTestSupport.hpp)

AddPrismTest(SessionOrchestrationTest.cpp)
target_link_libraries(SessionOrchestrationTest PRIVATE
    PrismAccount PrismFoundation PrismLifecycle PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(SessionRegistryTest.cpp)
target_link_libraries(SessionRegistryTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(SessionRegistryLifecycleTest.cpp)
target_link_libraries(SessionRegistryLifecycleTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(SessionServicesTest.cpp)
AddPrismTest(SessionControlLifecycleTest.cpp)
AddPrismTest(SessionDeliveryLifecycleTest.cpp)
target_link_libraries(SessionServicesTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismProtocolsCommon PrismRuntime
    PrismTestSupport PrismTransport)
target_sources(SessionServicesTest PRIVATE SessionLifecycleTestSupport.hpp)
target_link_libraries(SessionControlLifecycleTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionControlLifecycleTest PRIVATE SessionLifecycleTestSupport.hpp)
target_link_libraries(SessionDeliveryLifecycleTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionDeliveryLifecycleTest PRIVATE SessionLifecycleTestSupport.hpp)
AddPrismTest(SessionModuleContractTest.cpp)
target_link_libraries(SessionModuleContractTest PRIVATE PrismFoundation PrismTransport PrismRuntime PrismTestSupport)

AddPrismTest(TrafficIdentityTest.cpp)
target_link_libraries(TrafficIdentityTest PRIVATE PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(TrafficMiddlewareTest.cpp)
target_link_libraries(TrafficMiddlewareTest PRIVATE
    PrismAccount PrismFoundation PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(RuntimeSnapshotTest.cpp)
target_link_libraries(RuntimeSnapshotTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(DnsSessionDialTest.cpp)
target_link_libraries(DnsSessionDialTest PRIVATE
    PrismFoundation PrismIngressContract PrismNet PrismNetworkModel
    PrismRuntime PrismTestSupport PrismTransport)

AddPrismTest(MailboxTest.cpp)
target_link_libraries(MailboxTest PRIVATE PrismRuntime)
target_include_directories(MailboxTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransportsTest.cpp)
target_link_libraries(ActiveTransportsTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransportsRetryTest.cpp)
target_link_libraries(ActiveTransportsRetryTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ListenerConnectionDrainRetirementTest.cpp)
target_link_libraries(ListenerConnectionDrainRetirementTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(RejectedDatagramDrainTest.cpp)
target_link_libraries(RejectedDatagramDrainTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransportsCanceledRetirementTest.cpp)
target_link_libraries(ActiveTransportsCanceledRetirementTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport PrismTransport)
target_include_directories(ActiveTransportsCanceledRetirementTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransportsMuxCloseTest.cpp)
target_link_libraries(ActiveTransportsMuxCloseTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(WorkerGroupTest.cpp)
target_link_libraries(WorkerGroupTest PRIVATE PrismFoundation PrismRuntime)
target_include_directories(WorkerGroupTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(SessionRegistryLifecycleTest PRIVATE
    GenerationPublicationAccountAdmissionTest.cpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(ListenerAdmissionTest PRIVATE
    ListenerWorkerAdmissionTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(SessionServicesTest PRIVATE
    SessionServicesFailureTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(MailboxTest PRIVATE
    WorkerTestSupport.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(WorkerGroupTest PRIVATE
    WorkerTestSupport.hpp
)
