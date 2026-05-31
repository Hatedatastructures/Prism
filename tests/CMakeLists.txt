set(TEST_COMPILE_OPTS -g1 -Os)
if(MINGW)
    list(APPEND TEST_COMPILE_OPTS -fno-keep-inline-dllexport)
    # 自动检测 MinGW 运行时 DLL 所在目录（与 g++ 同目录）
    get_filename_component(_mingw_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
endif()

function(forward_add_test test_name source_file)
    add_executable(${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
    target_compile_options(${test_name} PRIVATE ${TEST_COMPILE_OPTS})
    target_link_libraries(${test_name} PRIVATE ${PROJECT_NAME}_static_library)
    add_test(NAME ${test_name} COMMAND ${test_name})
    if(MINGW AND _mingw_bin_dir)
        set_tests_properties(${test_name} PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_mingw_bin_dir}")
    endif()
endfunction()

# ─── 基础设施 ────────────────────────────────────
forward_add_test(Session        Session.cpp)
forward_add_test(Connection     Connection.cpp)
forward_add_test(Transmission   Transmission.cpp)
forward_add_test(Trace          Trace.cpp)

# ─── 协议 ────────────────────────────────────────
forward_add_test(Http           Http.cpp)
forward_add_test(Socks5         Socks5.cpp)
forward_add_test(Trojan         Trojan.cpp)
forward_add_test(Vless          Vless.cpp)
forward_add_test(Shadowsocks    Shadowsocks.cpp)

# ─── 端到端集成测试 ──────────────────────────────
forward_add_test(E2E             E2E.cpp)

# ─── 回归 ────────────────────────────────────────
forward_add_test(Regression     Regression.cpp)

# ─── 单元测试 ────────────────────────────────────
forward_add_test(HttpParser     HttpParser.cpp)
forward_add_test(Smux           Smux.cpp)
forward_add_test(SmuxCraft      SmuxCraft.cpp)
forward_add_test(Yamux          Yamux.cpp)
forward_add_test(YamuxCraft     YamuxCraft.cpp)
forward_add_test(YamuxWindow    YamuxWindow.cpp)
forward_add_test(MultiplexDuct  MultiplexDuct.cpp)
forward_add_test(Crypto         Crypto.cpp)
forward_add_test(Hkdf           Hkdf.cpp)
forward_add_test(Block          Block.cpp)
forward_add_test(Aead           Aead.cpp)
forward_add_test(Reality        Reality.cpp)
forward_add_test(Blake3         Blake3.cpp)
forward_add_test(X25519         X25519.cpp)
forward_add_test(DnsPacket      DnsPacket.cpp)
forward_add_test(DnsRules       DnsRules.cpp)
forward_add_test(Fault          Fault.cpp)
forward_add_test(Exception      Exception.cpp)
forward_add_test(ProtocolAnalysis ProtocolAnalysis.cpp)
forward_add_test(ProtocolToString ProtocolToString.cpp)
forward_add_test(Balancer       Balancer.cpp)
forward_add_test(DnsCache       DnsCache.cpp)
forward_add_test(AccountDirectory AccountDirectory.cpp)
forward_add_test(Shadowtls      Shadowtls.cpp)
forward_add_test(ShadowTlsE2E   ShadowTlsE2E.cpp)
forward_add_test(Restls         Restls.cpp)
forward_add_test(Config         Config.cpp)
forward_add_test(Base64Encode   Base64Encode.cpp)
forward_add_test(MemoryArena    MemoryArena.cpp)
forward_add_test(PipelinePrimitives PipelinePrimitives.cpp)
forward_add_test(Recognition    Recognition.cpp)
forward_add_test(Executor       Executor.cpp)
forward_add_test(FaultHandling  FaultHandling.cpp)
forward_add_test(SchemeRouteTable SchemeRouteTable.cpp)
forward_add_test(FeatureBitmap  FeatureBitmap.cpp)
forward_add_test(TlsSignal      TlsSignal.cpp)
forward_add_test(TlsHello       TlsHello.cpp)
forward_add_test(H2muxCraft     H2muxCraft.cpp)
forward_add_test(GracefulShutdown GracefulShutdown.cpp)
forward_add_test(TransportLayer TransportLayer.cpp)
forward_add_test(MuxParcel      MuxParcel.cpp)
forward_add_test(HandshakeTimeout HandshakeTimeout.cpp)
forward_add_test(H2mux          H2mux.cpp)
forward_add_test(MuxBootstrap   MuxBootstrap.cpp)
forward_add_test(MuxStressTest  MuxStressTest.cpp)
forward_add_test(MuxLifecycle   MuxLifecycle.cpp)
forward_add_test(MuxMaxStreams  MuxMaxStreams.cpp)

# ─── 覆盖率补充测试 ──────────────────────────────
forward_add_test(TlsRecord      TlsRecord.cpp)
forward_add_test(RealityAuth    RealityAuth.cpp)
forward_add_test(RestlsScript   RestlsScript.cpp)
forward_add_test(AnytlsPadding  AnytlsPadding.cpp)
forward_add_test(Target         Target.cpp)
forward_add_test(TrustTunnel    TrustTunnel.cpp)
forward_add_test(Stats          Stats.cpp)

forward_add_test(TrojanFraming      TrojanFraming.cpp)
forward_add_test(VlessFraming       VlessFraming.cpp)
forward_add_test(CryptoPure         CryptoPure.cpp)
forward_add_test(AeadHkdf           AeadHkdf.cpp)
forward_add_test(RealityKeygen      RealityKeygen.cpp)
forward_add_test(ShadowsocksDatagram ShadowsocksDatagram.cpp)
forward_add_test(SmuxFrameExtra     SmuxFrameExtra.cpp)
forward_add_test(DnsFormat          DnsFormat.cpp)
forward_add_test(RealityResponse    RealityResponse.cpp)

forward_add_test(EchDecrypt         EchDecrypt.cpp)
forward_add_test(NativeScheme       NativeScheme.cpp)
forward_add_test(DetectionPipeline  DetectionPipeline.cpp)
forward_add_test(HttpParserAuth     HttpParserAuth.cpp)
forward_add_test(ListenerPure    ListenerPure.cpp)

# ─── 纯函数补充测试（已有文件，之前未注册） ────────
forward_add_test(PoolPure             PoolPure.cpp)
forward_add_test(DnsUpstreamPure      DnsUpstreamPure.cpp)
forward_add_test(DnsResolverPure      DnsResolverPure.cpp)
forward_add_test(RestlsHandshakePure  RestlsHandshakePure.cpp)
forward_add_test(RealityHandshakePure RealityHandshakePure.cpp)
forward_add_test(AnytlsScheme         AnytlsScheme.cpp)
forward_add_test(ShadowtlsHandshakePure ShadowtlsHandshakePure.cpp)

# ─── Phase 1: 零覆盖纯函数测试 ────────────────────
forward_add_test(StealthCommonPure    StealthCommonPure.cpp)
forward_add_test(ShadowsocksConnPure  ShadowsocksConnPure.cpp)

# ─── Phase 2: 核心模块分支覆盖 ────────────────────
forward_add_test(CryptoErrorPaths     CryptoErrorPaths.cpp)
forward_add_test(SmuxFrameError       SmuxFrameError.cpp)
forward_add_test(YamuxFrameError      YamuxFrameError.cpp)

# ─── Phase 3-4: 帧解析 + Stealth 方案测试 ──────────
forward_add_test(AnytlsFrameParse     AnytlsFrameParse.cpp)
forward_add_test(TrustTunnelPure      TrustTunnelPure.cpp)

# ─── Phase 4: Stealth 方案接口扩展 ─────────────────
forward_add_test(StealthFacadeSchemes StealthFacadeSchemes.cpp)
forward_add_test(AnytlsSchemeExtended AnytlsSchemeExtended.cpp)

# ─── Phase 5: Stats 扩展 ──────────────────────────
forward_add_test(StatsExtended        StatsExtended.cpp)
forward_add_test(DnsCacheExtended     DnsCacheExtended.cpp)
forward_add_test(ConnectPure          ConnectPure.cpp)
forward_add_test(ProbeAnalyzerPure    ProbeAnalyzerPure.cpp)
forward_add_test(TargetResolvePure    TargetResolvePure.cpp)

# ─── Phase 5: Recognition + Balancer + Stats 纯函数 ──
forward_add_test(TlsSignalParse       TlsSignalParse.cpp)
forward_add_test(FeatureBitmapExtended FeatureBitmapExtended.cpp)
forward_add_test(BalancerPure         BalancerPure.cpp)
forward_add_test(TrafficStatePure     TrafficStatePure.cpp)
forward_add_test(Socks5BuildResp      Socks5BuildResp.cpp)
forward_add_test(ShadowsocksFramingPure ShadowsocksFramingPure.cpp)
forward_add_test(RouteTablePure       RouteTablePure.cpp)
forward_add_test(RuntimeStatePure     RuntimeStatePure.cpp)
forward_add_test(VlessFramingPure     VlessFramingPure.cpp)
forward_add_test(TrojanFramingPure    TrojanFramingPure.cpp)
forward_add_test(HttpParserPure       HttpParserPure.cpp)
forward_add_test(TlsRecordPure        TlsRecordPure.cpp)
forward_add_test(TlsHelloPure         TlsHelloPure.cpp)
forward_add_test(TrojanConnPure       TrojanConnPure.cpp)
forward_add_test(ShadowtlsSchemePure  ShadowtlsSchemePure.cpp)
forward_add_test(RealitySchemePure    RealitySchemePure.cpp)
forward_add_test(StealthRegistryPure  StealthRegistryPure.cpp)
forward_add_test(VlessConnPure        VlessConnPure.cpp)
forward_add_test(AnytlsPaddingPure    AnytlsPaddingPure.cpp)
forward_add_test(TrustTunnelAuthPure  TrustTunnelAuthPure.cpp)
forward_add_test(TlsSignalParseExt    TlsSignalParseExt.cpp)
forward_add_test(DnsFormatPure        DnsFormatPure.cpp)
forward_add_test(H2muxCraftPure      H2muxCraftPure.cpp)
forward_add_test(SmuxCraftPure       SmuxCraftPure.cpp)
forward_add_test(YamuxCraftPure      YamuxCraftPure.cpp)
forward_add_test(TrojanProcessPure      TrojanProcessPure.cpp)
forward_add_test(VlessProcessPure       VlessProcessPure.cpp)
forward_add_test(ShadowsocksProcessPure  ShadowsocksProcessPure.cpp)
forward_add_test(RacerPure            RacerPure.cpp)
forward_add_test(MuxCorePure          MuxCorePure.cpp)
forward_add_test(MuxBootstrapPure      MuxBootstrapPure.cpp)
forward_add_test(NativeSchemePure      NativeSchemePure.cpp)
forward_add_test(ExecutorPure          ExecutorPure.cpp)
forward_add_test(ResolverPure          ResolverPure.cpp)
forward_add_test(LaunchPure            LaunchPure.cpp)
forward_add_test(PoolExtendedPure      PoolExtendedPure.cpp)
forward_add_test(ResolverPure2         ResolverPure2.cpp)
forward_add_test(RealityKeygenPure2    RealityKeygenPure2.cpp)
forward_add_test(RestlsHandshakePure2  RestlsHandshakePure2.cpp)
forward_add_test(ShadowtlsHandshakePure2 ShadowtlsHandshakePure2.cpp)
forward_add_test(RestlsHandshakeParse2  RestlsHandshakeParse2.cpp)
forward_add_test(ShadowsocksDatagramPure2 ShadowsocksDatagramPure.cpp)
forward_add_test(DnsRulesPure2            DnsRulesPure.cpp)
forward_add_test(DnsUpstreamPure2         DnsUpstreamPure2.cpp)

# ─── Phase 5: Stats/Trace/Account/Seal/Preview ─────────
forward_add_test(PreviewTransport      PreviewTransport.cpp)
forward_add_test(StatsRuntimePure      StatsRuntimePure.cpp)
forward_add_test(AccountDirectoryPure  AccountDirectoryPure.cpp)
forward_add_test(TraceSpdlogPure       TraceSpdlogPure.cpp)
forward_add_test(StealthSealPure       StealthSealPure.cpp)
forward_add_test(StealthExecutorPure2  StealthExecutorPure2.cpp)

# ─── Phase 6: 深度同步逻辑测试 ──────────────────────
forward_add_test(DnsCacheDeep         DnsCacheDeep.cpp)
forward_add_test(DnsRulesDeep         DnsRulesDeep.cpp)
forward_add_test(RealityParseDest     RealityParseDest.cpp)
forward_add_test(TrafficStateDeep     TrafficStateDeep.cpp)
forward_add_test(DatagramUtilPure     DatagramUtilPure.cpp)
forward_add_test(TrojanConnPure2      TrojanConnPure2.cpp)
forward_add_test(VlessConnPure2       VlessConnPure2.cpp)
forward_add_test(AnytlsSchemeDeep     AnytlsSchemeDeep.cpp)
forward_add_test(UpstreamSettersPure  UpstreamSettersPure.cpp)
forward_add_test(RealityKeygenDeep    RealityKeygenDeep.cpp)
forward_add_test(TlsHelloDeep         TlsHelloDeep.cpp)
forward_add_test(HttpParserDeep       HttpParserDeep.cpp)
forward_add_test(RealityAuthDeep      RealityAuthDeep.cpp)
forward_add_test(ShadowtlsAuthDeep   ShadowtlsAuthDeep.cpp)
forward_add_test(RealityResponseDeep  RealityResponseDeep.cpp)
forward_add_test(ShadowtlsTransportPure ShadowtlsTransportPure.cpp)
forward_add_test(RestlsTransportPure    RestlsTransportPure.cpp)

# ─── Phase 7: 深度纯函数覆盖 ──────────────────────
forward_add_test(ShadowtlsTransportPure2 ShadowtlsTransportPure2.cpp)
forward_add_test(ListenerMakeAffinity    ListenerMakeAffinity.cpp)
forward_add_test(AnytlsSchemeDeep2       AnytlsSchemeDeep2.cpp)
forward_add_test(ShadowsocksConnDeep     ShadowsocksConnDeep.cpp)
forward_add_test(SmuxCraftDeep           SmuxCraftDeep.cpp)
forward_add_test(PoolDeep               PoolDeep.cpp)
forward_add_test(TrafficDeep            TrafficDeep.cpp)
forward_add_test(RuntimeDeep            RuntimeDeep.cpp)
forward_add_test(StealthRegistryDeep    StealthRegistryDeep.cpp)
forward_add_test(HealthDeep             HealthDeep.cpp)
forward_add_test(StealthExecutorDeep    StealthExecutorDeep.cpp)
forward_add_test(BalancerDeep           BalancerDeep.cpp)
forward_add_test(LaunchDeep             LaunchDeep.cpp)
forward_add_test(WorkerTlsDeep          WorkerTlsDeep.cpp)
forward_add_test(TrustTunnelSchemeDeep  TrustTunnelSchemeDeep.cpp)
forward_add_test(PreviewDeep           PreviewDeep.cpp)
forward_add_test(PoolDeep2             PoolDeep2.cpp)
forward_add_test(ResolverBlacklistDeep ResolverBlacklistDeep.cpp)
forward_add_test(RouterDeep              RouterDeep.cpp)
forward_add_test(DialPure                DialPure.cpp)
forward_add_test(TraceSpdlogDeep         TraceSpdlogDeep.cpp)
forward_add_test(MuxCoreDeep             MuxCoreDeep.cpp)
forward_add_test(YamuxCraftDeep          YamuxCraftDeep.cpp)
forward_add_test(H2muxCraftDeep          H2muxCraftDeep.cpp)
forward_add_test(DuctDeep                DuctDeep.cpp)
forward_add_test(ParcelDeep              ParcelDeep.cpp)
forward_add_test(DnsFormatDeep           DnsFormatDeep.cpp)
forward_add_test(SmuxFrameDeep           SmuxFrameDeep.cpp)
forward_add_test(ShadowsocksDatagramDeep  ShadowsocksDatagramDeep.cpp)
forward_add_test(ShadowtlsHandshakeDeep  ShadowtlsHandshakeDeep.cpp)
forward_add_test(RealityHandshakeDeep2    RealityHandshakeDeep2.cpp)
forward_add_test(ShadowsocksConnUtil      ShadowsocksConnUtil.cpp)
forward_add_test(YamuxCraftDeep2         YamuxCraftDeep2.cpp)
forward_add_test(H2muxCraftDeep2         H2muxCraftDeep2.cpp)
forward_add_test(PoolDeep3              PoolDeep3.cpp)
forward_add_test(SmuxCraftDeep2         SmuxCraftDeep2.cpp)
forward_add_test(AnytlsSessionDeep      AnytlsSessionDeep.cpp)
forward_add_test(DnsRulesDeep3         DnsRulesDeep3.cpp)
forward_add_test(AeadDeep              AeadDeep.cpp)
forward_add_test(BlockDeep             BlockDeep.cpp)
forward_add_test(RuntimeStatsDeep      RuntimeStatsDeep.cpp)
forward_add_test(PoolDeep4             PoolDeep4.cpp)
forward_add_test(UpstreamDeep          UpstreamDeep.cpp)
forward_add_test(RestlsTransportDeep   RestlsTransportDeep.cpp)
forward_add_test(ShadowtlsTransportDeep ShadowtlsTransportDeep.cpp)
forward_add_test(StealthExecutorDeep2   StealthExecutorDeep2.cpp)

add_subdirectory(concurrency)

if(MINGW)
    foreach(t IN ITEMS
        Session Connection Transmission Trace
        Http Socks5 Trojan Vless Shadowsocks Regression
        HttpParser Smux SmuxCraft Yamux YamuxCraft MultiplexDuct Crypto Hkdf Block Aead Reality Blake3 X25519 DnsPacket DnsRules Fault Exception ProtocolAnalysis ProtocolToString
        Balancer DnsCache AccountDirectory Shadowtls ShadowTlsE2E Restls Base64Encode MemoryArena Config PipelinePrimitives Recognition Executor FaultHandling E2E
        SchemeRouteTable FeatureBitmap H2muxCraft H2mux TransportLayer GracefulShutdown MuxParcel HandshakeTimeout YamuxWindow MuxBootstrap MuxStressTest MuxLifecycle MuxMaxStreams
        ConcurrencyServer ConcurrencyClient
        TlsSignal TlsHello TlsRecord RealityAuth RestlsScript AnytlsPadding Target TrustTunnel Stats
        TrojanFraming VlessFraming CryptoPure AeadHkdf RealityKeygen ShadowsocksDatagram SmuxFrameExtra DnsFormat RealityResponse
        EchDecrypt NativeScheme DetectionPipeline HttpParserAuth ListenerPure
        PoolPure DnsUpstreamPure DnsResolverPure RestlsHandshakePure RealityHandshakePure AnytlsScheme ShadowtlsHandshakePure
        StealthCommonPure ShadowsocksConnPure
        CryptoErrorPaths SmuxFrameError YamuxFrameError
        AnytlsFrameParse TrustTunnelPure
        StealthFacadeSchemes AnytlsSchemeExtended
        StatsExtended DnsCacheExtended ConnectPure
        ProbeAnalyzerPure TargetResolvePure
        TlsSignalParse FeatureBitmapExtended BalancerPure TrafficStatePure Socks5BuildResp
        ShadowsocksFramingPure RouteTablePure RuntimeStatePure
        VlessFramingPure TrojanFramingPure HttpParserPure TlsRecordPure
        TlsHelloPure
        TrojanConnPure ShadowtlsSchemePure RealitySchemePure
        StealthRegistryPure VlessConnPure AnytlsPaddingPure TrustTunnelAuthPure
        TlsSignalParseExt
        DnsFormatPure
        H2muxCraftPure
        SmuxCraftPure
        YamuxCraftPure
        TrojanProcessPure
        VlessProcessPure
        ShadowsocksProcessPure
        RacerPure
        MuxCorePure
        MuxBootstrapPure
        NativeSchemePure
        ExecutorPure
        ResolverPure
        LaunchPure
        PoolExtendedPure
        ShadowsocksDatagramPure2 DnsRulesPure2 DnsUpstreamPure2
        ResolverPure2 RealityKeygenPure2
        RestlsHandshakePure2
        ShadowtlsHandshakePure2
        RestlsHandshakeParse2
        PreviewTransport StatsRuntimePure AccountDirectoryPure TraceSpdlogPure StealthSealPure StealthExecutorPure2
        DnsCacheDeep DnsRulesDeep RealityParseDest TrafficStateDeep
        DatagramUtilPure TrojanConnPure2 VlessConnPure2 AnytlsSchemeDeep UpstreamSettersPure RealityKeygenDeep TlsHelloDeep HttpParserDeep RealityAuthDeep ShadowtlsAuthDeep RealityResponseDeep
        ShadowtlsTransportPure RestlsTransportPure
        ShadowtlsTransportPure2 ListenerMakeAffinity
        AnytlsSchemeDeep2
        ShadowsocksConnDeep
        SmuxCraftDeep
        PoolDeep
        TrafficDeep
        RuntimeDeep
        StealthRegistryDeep
        HealthDeep
        StealthExecutorDeep
        BalancerDeep
        LaunchDeep
        WorkerTlsDeep
        TrustTunnelSchemeDeep
        PreviewDeep
        PoolDeep2
        ResolverBlacklistDeep
        RouterDeep
        DialPure
        TraceSpdlogDeep
        MuxCoreDeep
        YamuxCraftDeep
        H2muxCraftDeep
        DuctDeep
        ParcelDeep
        DnsFormatDeep
        SmuxFrameDeep
        ShadowsocksDatagramDeep
        ShadowtlsHandshakeDeep
        RealityHandshakeDeep2
        ShadowsocksConnUtil
        YamuxCraftDeep2
        H2muxCraftDeep2
        PoolDeep3
        SmuxCraftDeep2
        AnytlsSessionDeep
        DnsRulesDeep3
        AeadDeep
        BlockDeep
        RuntimeStatsDeep
        PoolDeep4 UpstreamDeep
        RestlsTransportDeep ShadowtlsTransportDeep StealthExecutorDeep2)
        if(TARGET ${t})
            target_compile_options(${t} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
