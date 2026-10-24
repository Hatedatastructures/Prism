# Runtime 子模块测试
AddPrismTest(Listener/ListenerAdmissionTest.cpp)
AddPrismTest(Listener/ListenerShutdownTest.cpp)
AddPrismTest(Listener/ListenerLifecycleTest.cpp)
AddPrismTest(Listener/ListenerCapacityTest.cpp)
AddPrismTest(Listener/ListenerAcceptRecoveryTest.cpp)
AddPrismTest(Listener/ListenerMuxShutdownTest.cpp)
target_link_libraries(ListenerAdmissionTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerAdmissionTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerShutdownTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerShutdownTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerLifecycleTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerLifecycleTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerCapacityTest PRIVATE PrismFoundation PrismTransport PrismNet PrismRuntime PrismTestSupport)
target_sources(ListenerCapacityTest PRIVATE Listener/ListenerTestSupport.hpp)
target_link_libraries(ListenerAcceptRecoveryTest PRIVATE PrismFoundation PrismRuntime PrismTestSupport)
target_link_libraries(ListenerMuxShutdownTest PRIVATE
    PrismFoundation PrismIngressContract PrismIoContracts PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(ListenerMuxShutdownTest PRIVATE Listener/ListenerTestSupport.hpp)

AddPrismTest(Session/SessionOrchestrationTest.cpp)
target_link_libraries(SessionOrchestrationTest PRIVATE
    PrismAccount PrismFoundation PrismLifecycle PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Session/SessionRegistryTest.cpp)
target_link_libraries(SessionRegistryTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(Session/RegistryLifecycleTest.cpp)
target_link_libraries(RegistryLifecycleTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(Session/SessionServicesTest.cpp)
AddPrismTest(Session/SessionControlTest.cpp)
AddPrismTest(Session/SessionDeliveryTest.cpp)
target_link_libraries(SessionServicesTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismProtocolsCommon PrismRuntime
    PrismTestSupport PrismTransport)
target_sources(SessionServicesTest PRIVATE Session/SessionLifecycleSupport.hpp)
target_link_libraries(SessionControlTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionControlTest PRIVATE Session/SessionLifecycleSupport.hpp)
target_link_libraries(SessionDeliveryTest PRIVATE
    PrismAccount PrismFoundation PrismIngressContract PrismNet PrismRuntime PrismTestSupport
    PrismTransport)
target_sources(SessionDeliveryTest PRIVATE Session/SessionLifecycleSupport.hpp)
AddPrismTest(Session/SessionModuleContractTest.cpp)
target_link_libraries(SessionModuleContractTest PRIVATE PrismFoundation PrismTransport PrismRuntime PrismTestSupport)

AddPrismTest(Traffic/TrafficIdentityTest.cpp)
target_link_libraries(TrafficIdentityTest PRIVATE PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Traffic/TrafficMiddlewareTest.cpp)
target_link_libraries(TrafficMiddlewareTest PRIVATE
    PrismAccount PrismFoundation PrismTransport PrismRuntime PrismTestSupport)
AddPrismTest(Runtime/RuntimeSnapshotTest.cpp)
target_link_libraries(RuntimeSnapshotTest PRIVATE PrismRuntime PrismTestSupport)

AddPrismTest(Dns/DnsSessionDialTest.cpp)
target_link_libraries(DnsSessionDialTest PRIVATE
    PrismFoundation PrismIngressContract PrismNet PrismNetworkModel
    PrismRuntime PrismTestSupport PrismTransport)

AddPrismTest(Mailbox/MailboxTest.cpp)
target_link_libraries(MailboxTest PRIVATE PrismRuntime)
target_include_directories(MailboxTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/ActiveTransportsTest.cpp)
target_link_libraries(ActiveTransportsTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransports/ActiveTransportsRetryTest.cpp)
target_link_libraries(ActiveTransportsRetryTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(Listener/ListenerDrainTest.cpp)
target_link_libraries(ListenerDrainTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(Session/RejectedDatagramDrainTest.cpp)
target_link_libraries(RejectedDatagramDrainTest PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolsCommon PrismRuntime PrismTestSupport
    PrismTransport)
AddPrismTest(ActiveTransports/CanceledRetireTest.cpp)
target_sources(CanceledRetireTest PRIVATE
    ActiveTransports/CanceledRetireTestSupport.hpp)
target_link_libraries(CanceledRetireTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport PrismTransport)
target_include_directories(CanceledRetireTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/CancelOnlyTest.cpp)
target_sources(CancelOnlyTest PRIVATE
    ActiveTransports/CanceledRetireTestSupport.hpp)
target_link_libraries(CancelOnlyTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport PrismTransport)
target_include_directories(CancelOnlyTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(ActiveTransports/ActiveMuxCloseTest.cpp)
target_link_libraries(ActiveMuxCloseTest PRIVATE
    PrismFoundation PrismIngressContract PrismRuntime PrismTestSupport)
AddPrismTest(Worker/WorkerGroupTest.cpp)
target_link_libraries(WorkerGroupTest PRIVATE PrismFoundation PrismRuntime)
target_include_directories(WorkerGroupTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(RegistryLifecycleTest PRIVATE
    Session/GenerationAccountTest.cpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(ListenerAdmissionTest PRIVATE
    Listener/ListenerWorkerTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(SessionServicesTest PRIVATE
    Session/SessionServicesFailureTest.cpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(MailboxTest PRIVATE
    Worker/WorkerTestSupport.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(WorkerGroupTest PRIVATE
    Worker/WorkerTestSupport.hpp
)
