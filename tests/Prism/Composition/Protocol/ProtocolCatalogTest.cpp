/**
 * @file ProtocolCatalogTest.cpp
 * @brief Prism 静态协议/carrier descriptor contract。
 */
#include <gtest/gtest.h>

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

#include <algorithm>
#include <array>
#include <string_view>

TEST(PrismProtocolCatalog, CoversTcpUdpQuicAndCarrierDescriptors)
{
    const auto Descriptors = Prism::Composition::Protocol::ProtocolCatalog::All();
    EXPECT_EQ(Descriptors.size(), 17U);
    EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
        "socks5", Prism::Composition::Recognition::OperationScope::TcpRecognition));
    EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
        "socks5", Prism::Composition::Recognition::OperationScope::DatagramAssociation));
    EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
        "hysteria2", Prism::Composition::Recognition::OperationScope::QuicBinding));
    EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
        "hysteria2", Prism::Composition::Recognition::OperationScope::TcpRecognition));
    EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Find("ss2022").has_value());
    EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Find("shadowsocks2022").has_value());
    EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Find("shadowsocks").has_value());
    EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Find("native").has_value());
}

TEST(PrismProtocolCatalog, DoesNotExposeUnknownOrCrossScopeDescriptors)
{
    EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Find("unknown").has_value());
    EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
        "native", Prism::Composition::Recognition::OperationScope::QuicBinding));
}

TEST(PrismProtocolCatalog, SeparatesStackProtocolsFromTlsCarriers)
{
    using Catalog = Prism::Composition::Protocol::ProtocolCatalog;
    using DescriptorKind = Prism::Composition::Protocol::DescriptorKind;
    using ProtocolType = Prism::Contract::ProtocolType;
    namespace Protocol = Prism::Composition::Protocol;

    const auto AnyTls = Catalog::Find("anytls");
    const auto TrustTunnel = Catalog::Find("trusttunnel");
    const auto Socks = Catalog::Find("socks5");
    const auto Hysteria = Catalog::Find("hysteria2");
    const auto Native = Catalog::Find(Protocol::CarrierKind::Native);
    const auto WebSocket = Catalog::Find("websocket");
    const auto CanonicalWebSocket = Catalog::Find("ws");
    ASSERT_TRUE(AnyTls.has_value());
    ASSERT_TRUE(TrustTunnel.has_value());
    ASSERT_TRUE(Socks.has_value());
    ASSERT_TRUE(Hysteria.has_value());
    ASSERT_TRUE(Native.has_value());
    ASSERT_TRUE(WebSocket.has_value());
    ASSERT_TRUE(CanonicalWebSocket.has_value());

    EXPECT_EQ(AnyTls->Kind, DescriptorKind::Protocol);
    EXPECT_EQ(TrustTunnel->Kind, DescriptorKind::Protocol);
    EXPECT_NE(AnyTls->Id, ProtocolType::Tls);
    EXPECT_NE(TrustTunnel->Id, ProtocolType::Tls);
    EXPECT_NE(AnyTls->Id, TrustTunnel->Id);
    EXPECT_EQ(Prism::Contract::ToStringView(AnyTls->Id), "anytls");
    EXPECT_EQ(Prism::Contract::ToStringView(TrustTunnel->Id), "trusttunnel");

    const auto AnyTlsById = Catalog::Find(AnyTls->Id);
    const auto TrustTunnelById = Catalog::Find(TrustTunnel->Id);
    ASSERT_TRUE(AnyTlsById.has_value());
    ASSERT_TRUE(TrustTunnelById.has_value());
    EXPECT_EQ(AnyTlsById->Name, "anytls");
    EXPECT_EQ(TrustTunnelById->Name, "trusttunnel");

    EXPECT_TRUE(AnyTls->SupportsTcp);
    EXPECT_FALSE(AnyTls->SupportsUdp);
    EXPECT_FALSE(AnyTls->SupportsQuic);
    EXPECT_TRUE(TrustTunnel->SupportsTcp);
    EXPECT_TRUE(TrustTunnel->SupportsUdp);
    EXPECT_FALSE(TrustTunnel->SupportsQuic);

    constexpr std::array<std::string_view, 7> CarrierNames{
        "native", "reality", "shadowtls", "restls", "ws", "xhttp", "gun"};
    for (const auto CarrierName : CarrierNames)
    {
        const auto Carrier = Catalog::Find(CarrierName);
        ASSERT_TRUE(Carrier.has_value()) << CarrierName;
        EXPECT_EQ(Carrier->Kind, DescriptorKind::Carrier) << CarrierName;
    }
    EXPECT_EQ(Socks->Slot(), (Protocol::ProviderKey{
        Protocol::ProviderCategory::TcpProxy, ProtocolType::Socks5}));
    EXPECT_EQ(Hysteria->Slot(), (Protocol::ProviderKey{
        Protocol::ProviderCategory::QuicProxy, ProtocolType::Hysteria2}));
    EXPECT_EQ(Hysteria->TlsResource, Protocol::TlsResourceRequirement::NativeCertificateOrCarrier);
    EXPECT_EQ(Native->Slot(), (Protocol::ProviderKey{
        Protocol::ProviderCategory::TlsCarrier, Protocol::CarrierKind::Native}));
    EXPECT_NE(Native->Slot(), (Protocol::ProviderKey{
        Protocol::ProviderCategory::TlsCarrier, Protocol::CarrierKind::Reality}));
    EXPECT_EQ(WebSocket->Name, CanonicalWebSocket->Name);
    EXPECT_EQ(Protocol::ProtocolCatalog::CarrierName(Protocol::CarrierKind::WebSocket), "ws");
    const auto Vless=Protocol::ProtocolCatalog::Find(ProtocolType::Vless);
    const auto Shadowsocks=Protocol::ProtocolCatalog::Find(ProtocolType::Shadowsocks);
    ASSERT_TRUE(Vless.has_value());ASSERT_TRUE(Shadowsocks.has_value());
    EXPECT_EQ(Vless->AccountKey,"Vless");
    EXPECT_EQ(Shadowsocks->AccountKey,"Shadowsocks2022");
    EXPECT_FALSE(Protocol::ProtocolCatalog::Find(ProtocolType::Tls).has_value());
    EXPECT_FALSE(Protocol::ProtocolCatalog::Find(Protocol::ProviderKey{
        Protocol::ProviderCategory::Mux, Protocol::MuxSlot::Binding}).has_value());
    EXPECT_FALSE(Protocol::ProtocolCatalog::Find(Protocol::ProviderKey{
        Protocol::ProviderCategory::Ech, Protocol::EchSlot::ServerKeys}).has_value());
    EXPECT_FALSE(Protocol::ProtocolCatalog::Find(Protocol::CarrierKind::TrustTunnel).has_value());
}

TEST(PrismProtocolCatalog, DeclaresStackProtocolWireCapabilities)
{
    using Catalog = Prism::Composition::Protocol::ProtocolCatalog;
    using Capability = Prism::Composition::Builtin::Capability;

    const auto AnyTls = Catalog::Find("anytls");
    const auto TrustTunnel = Catalog::Find("trusttunnel");
    ASSERT_TRUE(AnyTls.has_value());
    ASSERT_TRUE(TrustTunnel.has_value());

    EXPECT_TRUE(AnyTls->Requires.Declares(Capability::Transport));
    EXPECT_TRUE(AnyTls->Requires.Declares(Capability::Tls));
    EXPECT_FALSE(AnyTls->Requires.Declares(Capability::Alpn));
    EXPECT_FALSE(AnyTls->Requires.Declares(Capability::Core));
    EXPECT_FALSE(AnyTls->Requires.Declares(Capability::Request));
    EXPECT_TRUE(AnyTls->Provides.Declares(Capability::Stream));
    EXPECT_TRUE(AnyTls->Provides.Declares(Capability::Multiplex));
    EXPECT_FALSE(AnyTls->Provides.Declares(Capability::Datagram));
    EXPECT_EQ(AnyTls->TlsResource,
        Prism::Composition::Protocol::TlsResourceRequirement::NativeCertificateOrCarrier);

    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Transport));
    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Tls));
    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Alpn));
    EXPECT_FALSE(TrustTunnel->Requires.Declares(Capability::Core));
    EXPECT_FALSE(TrustTunnel->Requires.Declares(Capability::Request));
    EXPECT_TRUE(TrustTunnel->Provides.Declares(Capability::Stream));
    EXPECT_TRUE(TrustTunnel->Provides.Declares(Capability::Datagram));
    EXPECT_FALSE(TrustTunnel->Provides.Declares(Capability::Multiplex));
    EXPECT_EQ(TrustTunnel->TlsResource,
        Prism::Composition::Protocol::TlsResourceRequirement::NativeCertificate);
}
