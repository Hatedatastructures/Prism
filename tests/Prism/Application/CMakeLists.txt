AddPrismTest(ApplicationAssemblyLifecycleTest.cpp)
add_subdirectory(Storage)
AddPrismTest(Storage/UsagePersistenceTest.cpp)
AddPrismTest(Storage/CommandJournalTest.cpp)
AddPrismTest(Storage/HistoryStoreTest.cpp)
AddPrismTest(ShutdownGenerationRetirementTest.cpp)
AddPrismTest(ApplicationStartupLifecycleTest.cpp)
AddPrismTest(AccountPersistenceStartupTest.cpp)
AddPrismTest(ApplicationProtocolConfigurationTest.cpp)
AddPrismTest(ApplicationNativeTlsTest.cpp)
AddPrismTest(ApplicationRequestPathTest.cpp)
AddPrismTest(Socks5AccountIngressBasicTest.cpp)
AddPrismTest(Socks5AccountIngressCancellationTest.cpp)
AddPrismTest(HttpForwardBasicTest.cpp)
AddPrismTest(HttpForwardOperationsTest.cpp)
AddPrismTest(RealityCarrierStartupTest.cpp)
AddPrismTest(TrustTunnelStartupTest.cpp)
AddPrismTest(TuicStartupTest.cpp)
AddPrismTest(RestlsStartupTest.cpp)
target_link_libraries(ApplicationAssemblyLifecycleTest PRIVATE
    PrismApplication PrismComposition PrismFoundation PrismRuntime PrismNet PrismTransport
    PrismProtocolMux PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan PrismProtocolVmess
    PrismProtocolSocks5)
target_sources(ApplicationAssemblyLifecycleTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(UsagePersistenceTest PRIVATE PrismApplication)
target_sources(UsagePersistenceTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(CommandJournalTest PRIVATE PrismApplication)
target_sources(CommandJournalTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(HistoryStoreTest PRIVATE PrismApplication PrismStatistics)
target_sources(HistoryStoreTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(ShutdownGenerationRetirementTest PRIVATE
    PrismApplication PrismComposition PrismFoundation PrismRuntime PrismNet PrismTransport PrismAccount
    PrismIngressContract PrismProtocolMux PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan
    PrismProtocolVmess PrismProtocolSocks5)
target_sources(ShutdownGenerationRetirementTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(ApplicationStartupLifecycleTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(ApplicationStartupLifecycleTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(AccountPersistenceStartupTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(AccountPersistenceStartupTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(ApplicationProtocolConfigurationTest PRIVATE
    PrismApplication PrismComposition PrismAccount PrismNet PrismRuntime PrismProtocolMux
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolHttp PrismProtocolVless PrismProtocolTrojan
    PrismProtocolVmess PrismProtocolShadowsocks2022)
target_sources(ApplicationProtocolConfigurationTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(ApplicationNativeTlsTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition PrismNet PrismProtocolEch PrismProtocolMux
    PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(ApplicationNativeTlsTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(ApplicationRequestPathTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(ApplicationRequestPathTest PRIVATE ApplicationTestSupport.hpp)
target_link_libraries(Socks5AccountIngressBasicTest PRIVATE PrismApplication PrismProtocolSocks5)
target_sources(Socks5AccountIngressBasicTest PRIVATE
    Socks5AccountIngressCore.hpp
    Socks5AccountIngressClient.hpp
    Socks5AccountIngressOperations.hpp
    Socks5AccountIngressTestSupport.hpp)
target_link_libraries(Socks5AccountIngressCancellationTest PRIVATE PrismApplication PrismProtocolSocks5)
target_sources(Socks5AccountIngressCancellationTest PRIVATE
    Socks5AccountIngressCore.hpp
    Socks5AccountIngressClient.hpp
    Socks5AccountIngressOperations.hpp
    Socks5AccountIngressTestSupport.hpp)
target_link_libraries(HttpForwardBasicTest PRIVATE PrismApplication)
target_sources(HttpForwardBasicTest PRIVATE
    HttpForwardApplicationFixture.hpp
    HttpForwardOriginFixture.hpp
    HttpForwardProtocolFixture.hpp
    HttpForwardTestSupport.hpp)
target_link_libraries(HttpForwardOperationsTest PRIVATE PrismApplication PrismDiagnoseBackend PrismFoundation)
target_sources(HttpForwardOperationsTest PRIVATE
    HttpForwardApplicationFixture.hpp
    HttpForwardOriginFixture.hpp
    HttpForwardProtocolFixture.hpp
    HttpForwardTestSupport.hpp)
target_link_libraries(RealityCarrierStartupTest PRIVATE PrismApplication)
target_link_libraries(TrustTunnelStartupTest PRIVATE PrismApplication)
target_link_libraries(TuicStartupTest PRIVATE PrismApplication)
target_link_libraries(RestlsStartupTest PRIVATE PrismApplication)
foreach(PrismApplicationWhiteboxTarget IN ITEMS
        ApplicationAssemblyLifecycleTest
        UsagePersistenceTest
        ShutdownGenerationRetirementTest
        ApplicationStartupLifecycleTest
        AccountPersistenceStartupTest
        ApplicationProtocolConfigurationTest
        ApplicationNativeTlsTest
        ApplicationRequestPathTest)
    target_include_directories(${PrismApplicationWhiteboxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Debug 测试与未启用 fortify 的生产对象保持一致；Release 必须保留默认宏，
        # 因为 Boost.Asio endpoint 的对象布局会随 _FORTIFY_SOURCE 改变。
        target_compile_options(ApplicationAssemblyLifecycleTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ShutdownGenerationRetirementTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationStartupLifecycleTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(AccountPersistenceStartupTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationProtocolConfigurationTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationNativeTlsTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationRequestPathTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(Socks5AccountIngressBasicTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(Socks5AccountIngressCancellationTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(HttpForwardBasicTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(HttpForwardOperationsTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(RealityCarrierStartupTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(TrustTunnelStartupTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(TuicStartupTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(RestlsStartupTest PRIVATE -U_FORTIFY_SOURCE)
    endif()
endif()

# 启动事务、真实入口和 Mux 生命周期的统一构建门禁，复用唯一 build 目录。
add_custom_target(PrismStartupValidation)
add_dependencies(PrismStartupValidation
    ApplicationAssemblyLifecycleTest ShutdownGenerationRetirementTest ApplicationStartupLifecycleTest AccountPersistenceStartupTest ApplicationProtocolConfigurationTest ApplicationNativeTlsTest ApplicationRequestPathTest ConfigurationStageOrderTest ProviderAcceptPathTest
    Socks5AccountIngressBasicTest Socks5AccountIngressCancellationTest HttpForwardBasicTest HttpForwardOperationsTest RealityCarrierStartupTest
    TrustTunnelStartupTest TuicStartupTest TuicUdpAdmissionTest RestlsStartupTest
    SessionRecognitionAdmissionTest SessionRecognitionCancellationTest ProfileBootstrapTest SessionOrchestrationTest
    SessionServicesTest SessionControlLifecycleTest SessionDeliveryLifecycleTest SessionModuleContractTest MuxServiceTest MuxE2ETest
    AdapterMuxLeaseTest H2MuxStreamReadLifetimeTest H2MuxStreamWriteLifetimeTest)
