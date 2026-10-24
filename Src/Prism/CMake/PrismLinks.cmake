# All internal module dependencies are declared after every module target exists.

LinkPrismTargets(PrismFoundation PUBLIC
    PrismSqlite
    OpenSSL::Crypto
    Blake3C
    BoostSystemHeaderOnly)
LinkPrismTargets(PrismDiagnoseBackend PUBLIC PrismFoundation)

LinkPrismTargets(PrismAccount PUBLIC PrismFoundation)
LinkPrismTargets(PrismLifecycle PUBLIC PrismFoundation)
LinkPrismTargets(PrismResource PUBLIC PrismFoundation PrismLifecycle)
LinkPrismTargets(PrismStatistics PUBLIC PrismFoundation)
LinkPrismTargets(PrismOperations PUBLIC PrismFoundation PrismStatistics glaze::glaze)
LinkPrismTargets(PrismOperations PRIVATE OpenSSL::Crypto)
LinkPrismTargets(PrismConfiguration PUBLIC
    PrismFoundation PrismAccount PrismIngressModel PrismComposition glaze::glaze)

LinkPrismTargets(PrismIoContracts INTERFACE PrismFoundation)
LinkPrismTargets(PrismIngressModel INTERFACE PrismFoundation PrismLifecycle)
LinkPrismTargets(PrismNetworkModel PUBLIC PrismFoundation)
LinkPrismTargets(PrismDatagramContract PUBLIC PrismFoundation PrismNetworkModel)
LinkPrismTargets(PrismStreamContract INTERFACE
    PrismNetworkModel PrismFoundation PrismAccount PrismTransport PrismIngressModel)
LinkPrismTargets(PrismIngressContract PUBLIC
    PrismFoundation PrismAccount PrismTransport PrismIngressModel PrismDatagramContract
    PrismStreamContract PrismIoContracts PrismNetworkModel)

LinkPrismTargets(PrismTransport PUBLIC PrismFoundation PrismLifecycle PrismIoContracts)
if(WIN32)
    target_link_libraries(PrismTransport PUBLIC ws2_32 mswsock crypt32)
endif()
target_link_libraries(PrismTransport PUBLIC OpenSSL::SSL)

LinkPrismTargets(PrismNet PUBLIC
    PrismTransport PrismFoundation PrismDatagramContract PrismNetworkModel PrismStreamContract
    OpenSSL::SSL)

LinkPrismTargets(PrismBoundary PUBLIC
    PrismDatagramContract PrismIngressContract PrismFoundation)
LinkPrismTargets(PrismRuntime PUBLIC
    PrismIngressModel PrismIngressContract PrismStatistics PrismNet PrismTransport PrismFoundation PrismLifecycle
    PrismAccount PrismResource PrismNetworkModel PrismIoContracts PrismStreamContract)

LinkPrismTargets(PrismProtocolsCommon PUBLIC
    PrismTransport PrismFoundation PrismIngressModel PrismIngressContract PrismLifecycle PrismNetworkModel PrismIoContracts
    PrismAccount PrismDatagramContract)
LinkPrismTargets(PrismProtocolHttp2 PUBLIC PrismFoundation)
LinkPrismTargets(PrismProtocolHttp2 PRIVATE PrismProtocolHttpCompression)
LinkPrismTargets(PrismProtocolHttp3Core PUBLIC PrismFoundation)
LinkPrismTargets(PrismProtocolHttp3Core PRIVATE PrismProtocolHttpCompression)
LinkPrismTargets(PrismProtocolQuic PUBLIC
    PrismProtocolsCommon PrismTransport PrismIoContracts PrismFoundation PrismIngressContract PrismLifecycle
    OpenSSL::SSL OpenSSL::Crypto
    ngtcp2_static ngtcp2_crypto_boringssl_static)
target_include_directories(PrismProtocolQuic PUBLIC
    "${ngtcp2_SOURCE_DIR}/lib/includes"
    "${ngtcp2_SOURCE_DIR}/crypto/includes")
LinkPrismTargets(PrismProtocolQuicNative PUBLIC
    PrismProtocolQuic PrismIngressContract PrismProtocolsCommon PrismLifecycle PrismFoundation)
LinkPrismTargets(PrismProtocolQuicNative PRIVATE
    OpenSSL::SSL OpenSSL::Crypto ngtcp2_static ngtcp2_crypto_boringssl_static)
target_include_directories(PrismProtocolQuicNative PRIVATE
    "${ngtcp2_SOURCE_DIR}/lib/includes"
    "${ngtcp2_SOURCE_DIR}/crypto/includes")

LinkPrismTargets(PrismProtocolHttp PRIVATE PrismProtocolsCommon)
LinkPrismTargets(PrismProtocolHttp PUBLIC
    PrismIngressModel PrismIngressContract PrismAccount PrismFoundation PrismLifecycle PrismTransport)
LinkPrismTargets(PrismProtocolHttp3 PUBLIC
    PrismProtocolHttp3Core PrismProtocolQuic PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolHttp3 PRIVATE
    PrismProtocolQuicNative
    OpenSSL::SSL OpenSSL::Crypto ngtcp2_static ngtcp2_crypto_boringssl_static nghttp3_static
    PrismIngressContract PrismLifecycle)
target_include_directories(PrismProtocolHttp3 PRIVATE
    "${ngtcp2_SOURCE_DIR}/lib/includes"
    "${ngtcp2_SOURCE_DIR}/crypto/includes"
    "${nghttp3_SOURCE_DIR}/lib/includes")

LinkPrismTargets(PrismProtocolProviderLifecycle INTERFACE
    PrismProtocolsCommon PrismProtocolMux PrismFoundation PrismLifecycle PrismAccount)
LinkPrismTargets(PrismProtocolMux PUBLIC
    PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolHttp2 PrismFoundation
    PrismNetworkModel PrismStreamContract PrismTransport)
LinkPrismTargets(PrismProtocolAnytls PUBLIC
    PrismIngressModel PrismIngressContract PrismStreamContract PrismAccount PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolAnytls PRIVATE PrismLifecycle PrismProtocolMux)
LinkPrismTargets(PrismProtocolShadowsocks2022 PUBLIC
    PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismAccount PrismLifecycle PrismProtocolMux
    PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolShadowsocks2022 PRIVATE PrismNetworkModel)
LinkPrismTargets(PrismProtocolSocks5 PUBLIC
    PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismAccount PrismLifecycle PrismProtocolMux
    PrismIoContracts PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolSocks5 PRIVATE PrismNetworkModel)
LinkPrismTargets(PrismProtocolTrojan PUBLIC
    PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle PrismAccount PrismProtocolMux
    PrismProtocolProviderLifecycle PrismIoContracts PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolTrojan PRIVATE PrismNetworkModel)
LinkPrismTargets(PrismProtocolVless PUBLIC
    PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle PrismAccount PrismNetworkModel PrismProtocolMux
    PrismProtocolProviderLifecycle PrismIoContracts PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolVmess PUBLIC
    PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle PrismAccount PrismNetworkModel PrismProtocolMux
    PrismProtocolProviderLifecycle PrismIoContracts PrismFoundation PrismTransport)

LinkPrismTargets(PrismProtocolHysteria2 PUBLIC
    PrismProtocolsCommon PrismProtocolHttp3Core PrismProtocolHttp3 PrismProtocolQuic
    PrismTransport PrismFoundation PrismAccount PrismIngressContract
    PrismIngressModel PrismLifecycle PrismNetworkModel)
LinkPrismTargets(PrismProtocolHysteria2 PRIVATE PrismProtocolQuicNative)
LinkPrismTargets(PrismProtocolTuic PUBLIC
    PrismProtocolsCommon PrismProtocolQuic PrismAccount PrismFoundation
    PrismTransport PrismIngressModel PrismIngressContract PrismLifecycle)
LinkPrismTargets(PrismProtocolTuic PRIVATE
    PrismProtocolQuicNative PrismIoContracts PrismNetworkModel OpenSSL::SSL)

LinkPrismTargets(PrismProtocolEch PUBLIC PrismFoundation OpenSSL::SSL)
LinkPrismTargets(PrismProtocolGun PUBLIC PrismFoundation PrismTransport PrismProtocolHttp2)
LinkPrismTargets(PrismProtocolGun PRIVATE PrismIoContracts PrismIngressContract PrismLifecycle)
LinkPrismTargets(PrismProtocolNative PUBLIC PrismFoundation PrismTransport OpenSSL::SSL)
LinkPrismTargets(PrismProtocolNative PRIVATE PrismIngressContract)
LinkPrismTargets(PrismProtocolReality PRIVATE PrismProtocolsCommon PrismFoundation)
LinkPrismTargets(PrismProtocolReality PUBLIC PrismTransport)
LinkPrismTargets(PrismProtocolReality PRIVATE PrismIngressContract OpenSSL::Crypto)
LinkPrismTargets(PrismProtocolRestls PRIVATE PrismProtocolsCommon)
LinkPrismTargets(PrismProtocolRestls PUBLIC PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolRestls PRIVATE PrismIngressContract)
LinkPrismTargets(PrismProtocolShadowtls PRIVATE PrismProtocolsCommon)
LinkPrismTargets(PrismProtocolShadowtls PUBLIC PrismFoundation PrismTransport)
LinkPrismTargets(PrismProtocolShadowtls PRIVATE PrismIngressContract OpenSSL::Crypto)
LinkPrismTargets(PrismProtocolTrusttunnel PUBLIC
    PrismIngressModel PrismIngressContract PrismAccount PrismFoundation PrismTransport PrismIoContracts OpenSSL::SSL)
LinkPrismTargets(PrismProtocolTrusttunnel PRIVATE PrismProtocolHttp2)
LinkPrismTargets(PrismProtocolWs PUBLIC PrismFoundation PrismTransport PrismIoContracts)
LinkPrismTargets(PrismProtocolWs PRIVATE PrismIngressContract)
LinkPrismTargets(PrismProtocolXhttp PUBLIC PrismTransport PrismFoundation)
LinkPrismTargets(PrismProtocolXhttp PRIVATE
    PrismProtocolHttp2 PrismIoContracts PrismIngressContract OpenSSL::SSL)

LinkPrismTargets(PrismComposition PUBLIC
    PrismAccount PrismFoundation PrismNetworkModel PrismIngressModel PrismIngressContract
    PrismDatagramContract PrismStreamContract PrismTransport PrismRuntime
    BoostSystemHeaderOnly
    PrismProtocolHttp PrismProtocolSocks5 PrismProtocolVmess PrismProtocolVless
    PrismProtocolTrojan PrismProtocolShadowsocks2022 PrismProtocolAnytls PrismProtocolRestls
    PrismProtocolTrusttunnel PrismProtocolShadowtls PrismProtocolWs
    PrismProtocolHysteria2 PrismProtocolTuic
    PrismProtocolMux PrismProtocolXhttp PrismProtocolGun PrismProtocolReality PrismProtocolHttp3)
LinkPrismTargets(PrismComposition PRIVATE PrismProtocolsCommon PrismProtocolNative)
LinkPrismTargets(PrismApplication PUBLIC
    PrismFoundation PrismLifecycle PrismRuntime PrismNet PrismNetworkModel PrismIngressContract
    PrismDatagramContract PrismIngressModel PrismAccount PrismResource PrismStatistics PrismConfiguration
    PrismOperations PrismComposition
    BoostSystemHeaderOnly glaze::glaze)
LinkPrismTargets(PrismApplication PRIVATE PrismBoundary)
LinkPrismTargets(PrismApplication PRIVATE PrismProtocolEch)
LinkPrismTargets(PrismApplication PRIVATE PrismDiagnoseBackend)
LinkPrismTargets(PrismApplication PRIVATE PrismProtocolHttp3)
LinkPrismTargets(PrismApplication PRIVATE OpenSSL::SSL OpenSSL::Crypto)
LinkPrismTargets(Prism PRIVATE PrismApplication)
