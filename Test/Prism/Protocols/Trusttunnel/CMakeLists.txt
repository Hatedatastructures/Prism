# trusttunnel 子模块
AddPrismTest(Datagram/TrusttunnelDgramSession.cpp)
target_link_libraries(TrusttunnelDgramSession PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrusttunnel)

AddPrismTest(Datagram/TrustTunnelDgramEndTest.cpp)
target_link_libraries(TrustTunnelDgramEndTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolTrusttunnel)

AddPrismTest(Codec/TrusttunnelCodecDeep.cpp)
target_link_libraries(TrusttunnelCodecDeep PRIVATE PrismProtocolTrusttunnel)

AddPrismTest(Datagram/TrusttunnelBasicAuthTest.cpp)
target_link_libraries(TrusttunnelBasicAuthTest PRIVATE PrismProtocolTrusttunnel)

AddPrismTest(Datagram/TrusttunnelHttp2Transport.cpp)
target_include_directories(TrusttunnelHttp2Transport PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(TrusttunnelHttp2Transport PRIVATE
    PrismFoundation PrismAccount PrismIoContracts PrismIngressContract PrismTransport
    PrismProtocolHttp PrismProtocolHttp2 PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismProtocolTrusttunnel OpenSSL::SSL OpenSSL::Crypto)
AddPrismTest(Datagram/TrustTunnelReadTest.cpp)
target_include_directories(TrustTunnelReadTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(TrustTunnelReadTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolHttp2 PrismProtocolTrusttunnel)
AddPrismTest(Datagram/TrustTunnelIngressTest.cpp)
target_include_directories(TrustTunnelIngressTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_sources(TrustTunnelIngressTest PRIVATE Datagram/TrustTunnelHalfCloseTest.cpp)
target_link_libraries(TrustTunnelIngressTest PRIVATE
    PrismFoundation PrismAccount PrismIngressContract PrismIoContracts PrismTransport PrismProtocolHttp2
    PrismProtocolHttp PrismProtocolShadowsocks2022 PrismProtocolSocks5 PrismRuntime
    PrismProtocolTrusttunnel
    OpenSSL::SSL OpenSSL::Crypto)
