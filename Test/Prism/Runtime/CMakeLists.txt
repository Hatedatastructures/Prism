# Runtime 子模块测试
AddPrismTest(Listener/AdmissionTest.cpp ListenerAdmissionTest)
AddPrismTest(Listener/ShutdownTest.cpp ListenerShutdownTest)
AddPrismTest(Listener/LifecycleTest.cpp ListenerLifecycleTest)
AddPrismTest(Listener/CapacityTest.cpp ListenerCapacityTest)
AddPrismTest(Listener/AcceptRecoveryTest.cpp ListenerAcceptRecoveryTest)
AddPrismTest(Listener/MuxShutdownTest.cpp ListenerMuxShutdownTest)
target_link_libraries(ListenerAdmissionTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerAdmissionTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerShutdownTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerShutdownTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerLifecycleTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerLifecycleTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerCapacityTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerCapacityTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerAcceptRecoveryTest PRIVATE PrismFoundation PrismRuntime PrismTestSupport)
target_include_directories(ListenerAcceptRecoveryTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(ListenerMuxShutdownTest PRIVATE
    PrismFoundation PrismIngressContract PrismIoContracts PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(ListenerMuxShutdownTest PRIVATE Listener/ListenerTestSupport.hpp)

AddPrismTest(Session/OrchestrationTest.cpp SessionOrchestrationTest)
target_link_libraries(SessionOrchestrationTest PRIVATE
    PrismAccount PrismFoundation PrismLifecycle PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Session/RegistryTest.cpp SessionRegistryTest)
target_link_libraries(SessionRegistryTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(Session/RegistryLifecycleTest.cpp)
target_link_libraries(RegistryLifecycleTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(Session/ServicesTest.cpp SessionServicesTest)
AddPrismTest(Session/ControlTest.cpp SessionControlTest)
AddPrismTest(Session/DeliveryTest.cpp SessionDeliveryTest)
target_link_libraries(SessionServicesTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismProtocolsCommon PrismRuntime
    PrismTestSupport PrismTransport)
target_sources(SessionServicesTest PRIVATE Session/LifecycleSupport.hpp)
target_link_libraries(SessionControlTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionControlTest PRIVATE Session/LifecycleSupport.hpp)
target_link_libraries(SessionDeliveryTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionDeliveryTest PRIVATE Session/LifecycleSupport.hpp)
AddPrismTest(Session/ModuleContractTest.cpp SessionModuleContractTest)
target_link_libraries(SessionModuleContractTest PRIVATE PrismFoundation PrismTransport PrismRuntime PrismTestSupport)

AddPrismTest(Traffic/IdentityTest.cpp TrafficIdentityTest)
target_link_libraries(TrafficIdentityTest PRIVATE PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Traffic/MiddlewareTest.cpp TrafficMiddlewareTest)
target_link_libraries(TrafficMiddlewareTest PRIVATE
    PrismAccount PrismFoundation PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Runtime/SnapshotTest.cpp RuntimeSnapshotTest)
target_link_libraries(RuntimeSnapshotTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(Dns/SessionDialTest.cpp DnsSessionDialTest)
target_link_libraries(DnsSessionDialTest PRIVATE
    PrismFoundation PrismIngressContract PrismNet PrismNetworkModel
    PrismRuntime PrismTestSupport PrismTransport)

AddPrismTest(Mailbox/MailboxTest.cpp)
target_link_libraries(MailboxTest PRIVATE PrismRuntime)
target_include_directories(MailboxTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/OwnershipTest.cpp ActiveTransportsTest)
target_link_libraries(ActiveTransportsTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransports/RetryTest.cpp ActiveTransportsRetryTest)
target_link_libraries(ActiveTransportsRetryTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(Listener/DrainTest.cpp ListenerDrainTest)
target_link_libraries(ListenerDrainTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(Session/RejectedDrainTest.cpp RejectedDatagramDrainTest)
target_link_libraries(RejectedDatagramDrainTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransports/CanceledRetireTest.cpp)
target_sources(CanceledRetireTest PRIVATE
    ActiveTransports/RetireSupport.hpp)
target_link_libraries(CanceledRetireTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport PrismTransport)
target_include_directories(CanceledRetireTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/CancelOnlyTest.cpp)
target_sources(CancelOnlyTest PRIVATE
    ActiveTransports/RetireSupport.hpp)
target_link_libraries(CancelOnlyTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport PrismTransport)
target_include_directories(CancelOnlyTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/ActiveMuxCloseTest.cpp)
target_link_libraries(ActiveMuxCloseTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(Worker/GroupTest.cpp WorkerGroupTest)
target_link_libraries(WorkerGroupTest PRIVATE PrismFoundation PrismRuntime)
target_include_directories(WorkerGroupTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(RegistryLifecycleTest PRIVATE
    Session/GenerationAccountTest.cpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(ListenerAdmissionTest PRIVATE
    Listener/WorkerTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(SessionServicesTest PRIVATE
    Session/ServicesFailureTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(MailboxTest PRIVATE
    Worker/WorkerTestSupport.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(WorkerGroupTest PRIVATE
    Worker/WorkerTestSupport.hpp
)
