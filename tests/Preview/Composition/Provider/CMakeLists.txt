AddPreviewTest(ProviderCatalogTest.cpp)
AddPreviewTest(AnytlsProviderRetirementTest.cpp)
AddPreviewTest(QuicProviderTest.cpp)
target_sources(AnytlsProviderRetirementTest PRIVATE CatalogFixture.hpp)
target_link_libraries(AnytlsProviderRetirementTest PRIVATE
    PreviewFoundation PreviewTransport PreviewRuntime PreviewComposition
    PreviewProtocolAnytls PreviewTestSupport)
target_link_libraries(QuicProviderTest PRIVATE PreviewComposition)
target_sources(QuicProviderTest PRIVATE QuicFixture.hpp CatalogFixture.hpp ../../../TestSupport/Preview/QuicFactory.hpp)

AddPreviewTest(Hysteria2FactoryTest.cpp)
target_sources(Hysteria2FactoryTest PRIVATE QuicFixture.hpp CatalogFixture.hpp)
target_link_libraries(Hysteria2FactoryTest PRIVATE
    PreviewFoundation PreviewAccount PreviewTransport PreviewNet PreviewRuntime
    PreviewComposition PreviewProtocolQuic PreviewProtocolQuicNative
    PreviewProtocolHysteria2 PreviewProtocolHttp3 PreviewTestSupport)

AddPreviewTest(TuicFactoryTest.cpp)
target_sources(TuicFactoryTest PRIVATE TuicFactoryFixture.hpp)
target_link_libraries(
    TuicFactoryTest PRIVATE PreviewFoundation PreviewAccount PreviewTransport PreviewNet
                            PreviewRuntime PreviewProtocolQuic PreviewProtocolQuicNative
                            PreviewProtocolTuic PreviewComposition PreviewTestSupport)

AddPreviewTest(TuicConnectionLeaseTest.cpp)
target_sources(TuicConnectionLeaseTest PRIVATE TuicFactoryFixture.hpp)
target_link_libraries(
    TuicConnectionLeaseTest PRIVATE PreviewFoundation PreviewAccount PreviewTransport PreviewNet
                                   PreviewRuntime PreviewProtocolQuic PreviewProtocolQuicNative
                                   PreviewProtocolTuic PreviewComposition PreviewTestSupport)

AddPreviewTest(TuicUdpAdmissionTest.cpp)
target_sources(TuicUdpAdmissionTest PRIVATE TuicFactoryFixture.hpp)
target_link_libraries(
    TuicUdpAdmissionTest PRIVATE PreviewApplication PreviewFoundation PreviewAccount PreviewTransport
                                PreviewNet PreviewRuntime PreviewComposition PreviewProtocolQuic
                                PreviewProtocolQuicNative PreviewProtocolTuic PreviewTestSupport)

AddPreviewTest(BindingLifetimeTest.cpp)
target_sources(BindingLifetimeTest PRIVATE BindingRetentionTest.cpp)
target_link_libraries(BindingLifetimeTest PRIVATE PreviewProtocolsCommon PreviewTestSupport)
target_link_libraries(ProviderCatalogTest PRIVATE PreviewComposition)
AddPreviewTest(StandardProviderTest.cpp)
target_sources(StandardProviderTest PRIVATE CatalogFixture.hpp)
target_link_libraries(StandardProviderTest PRIVATE PreviewComposition)

# 本卡实际 provider/认证/入口消费者的单一并行构建门禁。
add_custom_target(PreviewProviderValidation DEPENDS
    QuicProviderTest
    QuicConnectionRegistryTest
    QuicOwnershipTest
    QuicPacketGatewayLifecycleTest
    DatagramBoundaryTest
    Task9FrontIntegration
    Hysteria2FactoryTest
    Hysteria2AdmissionTest
    Hysteria2Http3AuthTest
    Hysteria2ConnSession
    Hysteria2ConnErrorMatrix
    Hysteria2TuicBeastTest
    Hysteria2StressTest
    Hysteria2ClientServerPerf
    TuicFactoryTest
    TuicConnectionLeaseTest
    TuicAdmissionTest
    TuicConnSession
    TuicConnErrorMatrix
    TuicDgramDeep
    TuicClientServerPerf
    NativeHttp3Session
    NativeQuicLoopback
    NativeDatagramInboxTest
    HttpQuicCoverage
    RecognitionQuicCarrier
    Task9BuiltinTest
    ProtocolCatalogTest
    BindingLifetimeTest
    ProviderClosingOwnerTest
    WorkerGroupTest
    TaskRegistryCoreLifecycleTest
    TaskRegistryDrainLifecycleTest
    TaskOwnershipLifecycleTest
    InteropProviderDatagrams
    InteropHysteria2
    InteropHysteria2Client
    InteropTuic
    Hysteria2InteropBlocker
    AdapterMuxLeaseTest
    AdapterAdmissionTest
    AdapterErrorMappingTest
    ApplicationAssemblyLifecycleTest
    ApplicationStartupLifecycleTest
    ApplicationProtocolConfigurationTest
    ApplicationNativeTlsTest
    ApplicationRequestPathTest
    AuthenticatorTest
    CandidateFactoryTest
    CandidateHeaderContractTest
    CandidateRegistryTest
    CanonicalAccountDatagramTest
    CanonicalAssociationTest
    ConfigurationOrderTest
    ConfigurationStageOrderTest
    ConfigurationAssemblyTest
    ConfigurationPreflightTest
    ConfigurationSchemaTest
    ConfigurationSecretTest
    ConfigurationCapabilityTest
    ConfigurationGenerationTest
    ConfigurationValidationHeadersTest
    ConfiguredComponentsTest
    ConfiguredModeAdmissionTest
    ConfiguredModeCommitTest
    ConfiguredModeCancellationTest
    ConfiguredRecognition
    DatagramBoundaryServiceTest
    DatagramProtocolServiceTest
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
    PrismPreview
    ProbeBufferTest
    ProfileCompileValidationTest
    ProfileCompileHandleTest
    ProfileComponentsTest
    ProfileModelHeaderContractTest
    ProviderAcceptPathTest
    ProviderCatalogTest
    AnytlsProviderRetirementTest
    RealityCarrierStartupTest
    RealityRecognition
    RecognitionCarrierSelectionTest
    RecognitionCarrierProtocolTest
    RecognitionProtocolTest
    RecognitionProbeRouteTest
    RecognitionTlsTest
    RecognitionPipelineTest
    RestlsStartupTest
    SchemeExecutorTest
    SecretResolutionStageTest
    SessionRecognitionAdmissionTest
    SessionRecognitionCancellationTest
    Shadowsocks2022BeastTest
    Socks5AccountIngressBasicTest
    Socks5AccountIngressCancellationTest
    Socks5BeastTest
    Socks5ClientServerPerf
    Socks5CodecOwnerTest
    Socks5ConnErrorMatrix
    Socks5ConnSession
    Socks5DeferredReplyTest
    Socks5DgramSession
    Socks5LongitudinalCoverage
    Socks5StressTest
    Socks5TcpE2ETest
    Socks5TypedHandoffTest
    Socks5UdpE2ETest
    Ss2022ClientServerPerf
    Ss2022CodecDeep
    Ss2022ConnErrorMatrix
    Ss2022DgramSession
    SS2022E2ETest
    Ss2022GatewayTest
    SS2022UdpE2ETest
    Ss2022UdpWireOrder
    StandardProviderTest
    TlsRecordReassemblyTest
    TlsRouteTableTest
    TlsRecognitionPipelineTest
    TrustTunnelStartupTest
    TuicStartupTest
    TuicUdpAdmissionTest
)
