AddPrismTest(Startup/AppAssemblyLifecycleTest.cpp)
add_subdirectory(Storage)
AddPrismTest(Storage/UsagePersistenceTest.cpp)
AddPrismTest(Storage/CommandJournalTest.cpp)
AddPrismTest(Storage/HistoryStoreTest.cpp)
AddPrismTest(Startup/ShutdownRetirementTest.cpp)
AddPrismTest(Ingress/AppStartupLifecycleTest.cpp)
AddPrismTest(Ingress/AccountPersistenceTest.cpp)
AddPrismTest(Startup/AppProtocolConfigTest.cpp)
AddPrismTest(Startup/ApplicationNativeTlsTest.cpp)
AddPrismTest(Startup/ApplicationRequestPathTest.cpp)
AddPrismTest(Ingress/Socks5IngressTest.cpp)
AddPrismTest(Ingress/Socks5CancelIngressTest.cpp)
AddPrismTest(Ingress/HttpForwardBasicTest.cpp)
AddPrismTest(Ingress/HttpForwardOperationsTest.cpp)
AddPrismTest(Ingress/RealityCarrierStartupTest.cpp)
AddPrismTest(Ingress/TrustTunnelStartupTest.cpp)
AddPrismTest(Ingress/TuicStartupTest.cpp)
AddPrismTest(Ingress/RestlsStartupTest.cpp)
target_link_libraries(AppAssemblyLifecycleTest PRIVATE
    PrismApplication PrismComposition PrismFoundation PrismRuntime PrismNet PrismTransport
    PrismProtocolMux PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan PrismProtocolVmess
    PrismProtocolSocks5)
target_sources(AppAssemblyLifecycleTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(UsagePersistenceTest PRIVATE PrismApplication)
target_sources(UsagePersistenceTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(CommandJournalTest PRIVATE PrismApplication)
target_sources(CommandJournalTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(HistoryStoreTest PRIVATE PrismApplication PrismStatistics)
target_sources(HistoryStoreTest PRIVATE Storage/StorageTestSupport.hpp)
target_link_libraries(ShutdownRetirementTest PRIVATE
    PrismApplication PrismComposition PrismFoundation PrismRuntime PrismNet PrismTransport PrismAccount
    PrismIngressContract PrismProtocolMux PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan
    PrismProtocolVmess PrismProtocolSocks5)
target_sources(ShutdownRetirementTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(AppStartupLifecycleTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(AppStartupLifecycleTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(AccountPersistenceTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(AccountPersistenceTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(AppProtocolConfigTest PRIVATE
    PrismApplication PrismComposition PrismAccount PrismNet PrismRuntime PrismProtocolMux
    PrismProtocolAnytls PrismProtocolSocks5 PrismProtocolHttp PrismProtocolVless PrismProtocolTrojan
    PrismProtocolVmess PrismProtocolShadowsocks2022)
target_sources(AppProtocolConfigTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(ApplicationNativeTlsTest PRIVATE
    PrismApplication PrismConfiguration PrismComposition PrismNet PrismProtocolEch PrismProtocolMux
    PrismProtocolAnytls PrismProtocolVless PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(ApplicationNativeTlsTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(ApplicationRequestPathTest PRIVATE
    PrismApplication PrismComposition PrismNet PrismProtocolMux PrismProtocolAnytls PrismProtocolVless
    PrismProtocolTrojan PrismProtocolVmess PrismProtocolSocks5)
target_sources(ApplicationRequestPathTest PRIVATE Startup/ApplicationTestSupport.hpp)
target_link_libraries(Socks5IngressTest PRIVATE PrismApplication PrismProtocolSocks5)
target_sources(Socks5IngressTest PRIVATE
    Ingress/Socks5AccountIngressCore.hpp
    Ingress/Socks5AccountIngressClient.hpp
    Ingress/Socks5IngressOperations.hpp
    Ingress/Socks5IngressSupport.hpp)
target_link_libraries(Socks5CancelIngressTest PRIVATE PrismApplication PrismProtocolSocks5)
target_sources(Socks5CancelIngressTest PRIVATE
    Ingress/Socks5AccountIngressCore.hpp
    Ingress/Socks5AccountIngressClient.hpp
    Ingress/Socks5IngressOperations.hpp
    Ingress/Socks5IngressSupport.hpp)
target_link_libraries(HttpForwardBasicTest PRIVATE PrismApplication)
target_sources(HttpForwardBasicTest PRIVATE
    Ingress/HttpForwardAppFixture.hpp
    Ingress/HttpForwardOriginFixture.hpp
    Ingress/HttpForwardProtocolFixture.hpp
    Ingress/HttpForwardTestSupport.hpp)
target_link_libraries(HttpForwardOperationsTest PRIVATE PrismApplication PrismDiagnoseBackend PrismFoundation)
target_sources(HttpForwardOperationsTest PRIVATE
    Ingress/HttpForwardAppFixture.hpp
    Ingress/HttpForwardOriginFixture.hpp
    Ingress/HttpForwardProtocolFixture.hpp
    Ingress/HttpForwardTestSupport.hpp)
target_link_libraries(RealityCarrierStartupTest PRIVATE PrismApplication)
target_link_libraries(TrustTunnelStartupTest PRIVATE PrismApplication)
target_link_libraries(TuicStartupTest PRIVATE PrismApplication)
target_link_libraries(RestlsStartupTest PRIVATE PrismApplication)
foreach(PrismApplicationWhiteboxTarget IN ITEMS
        AppAssemblyLifecycleTest
        UsagePersistenceTest
        ShutdownRetirementTest
        AppStartupLifecycleTest
        AccountPersistenceTest
        AppProtocolConfigTest
        ApplicationNativeTlsTest
        ApplicationRequestPathTest)
    target_include_directories(${PrismApplicationWhiteboxTarget} PRIVATE
        "${PROJECT_SOURCE_DIR}/Src")
endforeach()
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Debug 测试与未启用 fortify 的生产对象保持一致；Release 必须保留默认宏，
        # 因为 Boost.Asio endpoint 的对象布局会随 _FORTIFY_SOURCE 改变。
        target_compile_options(AppAssemblyLifecycleTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ShutdownRetirementTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(AppStartupLifecycleTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(AccountPersistenceTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(AppProtocolConfigTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationNativeTlsTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(ApplicationRequestPathTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(Socks5IngressTest PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(Socks5CancelIngressTest PRIVATE -U_FORTIFY_SOURCE)
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
    AppAssemblyLifecycleTest ShutdownRetirementTest AppStartupLifecycleTest AccountPersistenceTest AppProtocolConfigTest ApplicationNativeTlsTest ApplicationRequestPathTest ConfigStageOrderTest ProviderAcceptPathTest
    Socks5IngressTest Socks5CancelIngressTest HttpForwardBasicTest HttpForwardOperationsTest RealityCarrierStartupTest
    TrustTunnelStartupTest TuicStartupTest TuicUdpAdmissionTest RestlsStartupTest
    SessionAdmissionTest SessionCancelTest ProfileBootstrapTest SessionOrchestrationTest
    SessionServicesTest SessionControlTest SessionDeliveryTest SessionModuleContractTest MuxServiceTest MuxE2ETest
    AdapterMuxLeaseTest H2MuxReadLifetimeTest H2MuxWriteLifetimeTest)
