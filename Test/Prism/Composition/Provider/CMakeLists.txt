AddPrismTest(CatalogTest.cpp ProviderCatalogTest)
AddPrismTest(AnytlsRetirementTest.cpp)
AddPrismTest(QuicProviderTest.cpp)
target_sources(AnytlsRetirementTest PRIVATE CatalogFixture.hpp)
target_link_libraries(AnytlsRetirementTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismRuntime PrismComposition
    PrismProtocolAnytls PrismTestSupport)
target_link_libraries(QuicProviderTest PRIVATE
    PrismComposition PrismFoundation PrismAccount PrismNet PrismIngressContract
    PrismProtocolQuic PrismProtocolQuicNative)
target_sources(QuicProviderTest PRIVATE QuicFixture.hpp CatalogFixture.hpp ../../../TestSupport/Prism/QuicFactory.hpp)

AddPrismTest(Hysteria2FactoryTest.cpp)
target_sources(Hysteria2FactoryTest PRIVATE QuicFixture.hpp CatalogFixture.hpp)
target_link_libraries(Hysteria2FactoryTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismComposition PrismProtocolQuic PrismProtocolQuicNative
    PrismProtocolHysteria2 PrismProtocolHttp3 PrismTestSupport)

target_link_libraries(ProviderCatalogTest PRIVATE
    PrismComposition PrismFoundation PrismAccount PrismIoContracts PrismIngressModel
    PrismIngressContract PrismStreamContract PrismTransport PrismProtocolShadowsocks2022)
AddPrismTest(StandardProviderTest.cpp)
target_sources(StandardProviderTest PRIVATE CatalogFixture.hpp)
target_link_libraries(StandardProviderTest PRIVATE
    PrismComposition PrismFoundation PrismAccount PrismNet PrismProtocolSocks5
    PrismProtocolShadowsocks2022)

# 本卡实际 provider/认证/入口消费者的单一并行构建门禁。
add_custom_target(PrismProviderValidation)
add_dependencies(PrismProviderValidation
    QuicProviderTest
    QuicConnectionRegistryTest
    QuicOwnershipTest
    QuicGatewayLifecycleTest
    DatagramBoundaryTest
    Task9FrontIntegration
    Hysteria2FactoryTest
    Hysteria2AdmissionTest
    Hysteria2Http3AuthTest
    Hysteria2ConnSession
    Hysteria2ConnErrorMatrix
    Hysteria2RoundtripTest
    TuicCodecRoundtripTest
    TuicFactoryTest
    TuicFactoryLeaseTest
    TuicConnectionLeaseTest
    TuicAdmissionTest
    TuicConnSession
    TuicConnErrorMatrix
    TuicDgramDeep
    NativeHttp3Session
    NativeQuicLoopback
    QuicLoopbackOwnerTest
    NativeDatagramInboxTest
    HttpQuicCoverage
    RecognitionQuicCarrier
    BuiltinTest
    ProtocolCatalogTest
    BindingLifetimeTest
    ProviderClosingOwnerTest
    WorkerGroupTest
    TaskRegistryCoreTest
    TaskRegistryDrainTest
    TaskOwnershipLifecycleTest
    InteropProviderDatagrams
    InteropHysteria2
    InteropHysteria2Client
    InteropTuic
    Hysteria2InteropBlocker
    AdapterMuxLeaseTest
    AdapterAdmissionTest
    AdapterErrorMappingTest
    AppAssemblyLifecycleTest
    AppStartupLifecycleTest
    AppProtocolConfigTest
    ApplicationNativeTlsTest
    ApplicationRequestPathTest
    AuthenticatorTest
    CandidateFactoryTest
    CandidateHeaderTest
    CandidateRegistryTest
    CanonicalAccountTest
    CanonicalAssociationTest
    ConfigurationOrderTest
    ConfigStageOrderTest
    ConfigurationAssemblyTest
    ConfigurationPreflightTest
    ConfigurationSchemaTest
    ConfigurationSecretTest
    ConfigCapabilityTest
    ConfigGenerationTest
    ValidationHeadersTest
    ConfiguredComponentsTest
    ConfiguredAdmissionTest
    ConfiguredModeCommitTest
    ConfiguredCancelTest
    ConfiguredRecognition
    DatagramServiceTest
    DatagramProtocolTest
    DecisionTableTest
    HttpForwardBasicTest
    HttpForwardOperationsTest
    InteropRecognition
    InteropSocks5
    InteropSs2022Client
    LayeredCandidateTest
    MixedTrialAdmissionTest
    MixedTrialLifecycleTest
    MixedTrialRecognition
    PostDialReplyFailureTest
    Prism
    ProbeBufferTest
    ProfileCompileTest
    ProfileCompileHandleTest
    ProfileComponentsTest
    ProfileHeaderContractTest
    ProviderAcceptPathTest
    ProviderCatalogTest
    AnytlsRetirementTest
    AnytlsAdmissionOwnerTest
    RealityCarrierStartupTest
    RealityRecognition
    CarrierSelectionTest
    CarrierProtocolTest
    RecognitionProtocolTest
    RecognitionProbeRouteTest
    RecognitionTlsTest
    RestlsStartupTest
    SecretResolutionStageTest
    SessionAdmissionTest
    SessionCancelTest
    Shadowsocks2022BeastTest
    Socks5IngressTest
    Socks5CancelIngressTest
    Socks5BeastTest
    Socks5CodecOwnerTest
    Socks5ConnErrorMatrix
    Socks5ConnSession
    Socks5DeferredReplyTest
    Socks5DgramSession
    Socks5LongitudinalCoverage
    Socks5TcpE2ETest
    Socks5TypedHandoffTest
    Socks5UdpE2ETest
    Ss2022CodecDeep
    Ss2022ConnErrorMatrix
    Ss2022DgramSession
    SS2022E2ETest
    Ss2022GatewayTest
    SS2022UdpE2ETest
    Ss2022UdpWireOrder
    StandardProviderTest
    TlsRecordReassemblyTest
    TlsRecognitionPipelineTest
    TrustTunnelStartupTest
    TuicStartupTest
    TuicUdpAdmissionTest
)

if(PRISM_ENABLE_STRESS)
    add_dependencies(PrismProviderValidation Hysteria2StressTest Socks5StressTest)
endif()

if(PRISM_ENABLE_BENCHMARK)
    add_dependencies(PrismProviderValidation
        Hysteria2ClientServerPerf
        TuicClientServerPerf
        Socks5ClientServerPerf
        Ss2022ClientServerPerf)
endif()
