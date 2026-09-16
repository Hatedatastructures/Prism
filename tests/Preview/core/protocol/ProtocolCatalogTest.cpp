/**
 * @file ProtocolCatalogTest.cpp
 * @brief Preview 静态协议/carrier descriptor contract。
 */
#include <gtest/gtest.h>

#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>

#include <algorithm>
#include <array>
#include <string_view>

TEST(PreviewProtocolCatalog, CoversTcpUdpQuicAndCarrierDescriptors)
{
    const auto Descriptors = Preview::Composition::Protocol::ProtocolCatalog::All();
    EXPECT_EQ(Descriptors.size(), 17U);
    EXPECT_TRUE(Preview::Composition::Protocol::ProtocolCatalog::Supports(
        "socks5", Preview::Composition::Recognition::OperationScope::TcpRecognition));
    EXPECT_TRUE(Preview::Composition::Protocol::ProtocolCatalog::Supports(
        "socks5", Preview::Composition::Recognition::OperationScope::UdpAssociation));
    EXPECT_TRUE(Preview::Composition::Protocol::ProtocolCatalog::Supports(
        "hysteria2", Preview::Composition::Recognition::OperationScope::QuicBinding));
    EXPECT_FALSE(Preview::Composition::Protocol::ProtocolCatalog::Supports(
        "hysteria2", Preview::Composition::Recognition::OperationScope::TcpRecognition));
    EXPECT_TRUE(Preview::Composition::Protocol::ProtocolCatalog::Find("shadowsocks2022").has_value());
    EXPECT_TRUE(Preview::Composition::Protocol::ProtocolCatalog::Find("native").has_value());
}

TEST(PreviewProtocolCatalog, DoesNotExposeUnknownOrCrossScopeDescriptors)
{
    EXPECT_FALSE(Preview::Composition::Protocol::ProtocolCatalog::Find("unknown").has_value());
    EXPECT_FALSE(Preview::Composition::Protocol::ProtocolCatalog::Supports(
        "native", Preview::Composition::Recognition::OperationScope::QuicBinding));
}

TEST(PreviewProtocolCatalog, SeparatesStackProtocolsFromTlsCarriers)
{
    using Catalog = Preview::Composition::Protocol::ProtocolCatalog;
    using DescriptorKind = Preview::Composition::Protocol::DescriptorKind;
    using ProtocolType = Preview::Recognition::ProtocolType;

    const auto AnyTls = Catalog::Find("anytls");
    const auto TrustTunnel = Catalog::Find("trusttunnel");
    ASSERT_TRUE(AnyTls.has_value());
    ASSERT_TRUE(TrustTunnel.has_value());

    EXPECT_EQ(AnyTls->Kind, DescriptorKind::Protocol);
    EXPECT_EQ(TrustTunnel->Kind, DescriptorKind::Protocol);
    EXPECT_NE(AnyTls->Id, ProtocolType::Tls);
    EXPECT_NE(TrustTunnel->Id, ProtocolType::Tls);
    EXPECT_NE(AnyTls->Id, TrustTunnel->Id);
    EXPECT_EQ(Preview::Recognition::ToStringView(AnyTls->Id), "anytls");
    EXPECT_EQ(Preview::Recognition::ToStringView(TrustTunnel->Id), "trusttunnel");

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
}

TEST(PreviewProtocolCatalog, DeclaresStackProtocolWireCapabilities)
{
    using Catalog = Preview::Composition::Protocol::ProtocolCatalog;
    using Capability = Preview::Composition::Builtin::Capability;

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

    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Transport));
    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Tls));
    EXPECT_TRUE(TrustTunnel->Requires.Declares(Capability::Alpn));
    EXPECT_FALSE(TrustTunnel->Requires.Declares(Capability::Core));
    EXPECT_FALSE(TrustTunnel->Requires.Declares(Capability::Request));
    EXPECT_TRUE(TrustTunnel->Provides.Declares(Capability::Stream));
    EXPECT_TRUE(TrustTunnel->Provides.Declares(Capability::Datagram));
    EXPECT_FALSE(TrustTunnel->Provides.Declares(Capability::Multiplex));
}
