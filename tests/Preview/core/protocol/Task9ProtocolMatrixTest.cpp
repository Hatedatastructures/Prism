/**
 * @file Task9ProtocolMatrixTest.cpp
 * @brief Task 9 TCP/UDP/QUIC binding matrix tests.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <string_view>

#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>

namespace
{

    using Preview::Composition::Recognition::ProtocolMatrix;
    using Preview::Composition::Recognition::OperationScope;
    using Preview::Recognition::ProtocolType;

    TEST(Task9ProtocolMatrix, TcpRecognitionExcludesQuicProtocols)
    {
        const auto Bindings = ProtocolMatrix::TcpRecognition();

        EXPECT_NE(std::find_if(Bindings.begin(), Bindings.end(), [](const auto &Binding)
                               { return Binding.Protocol == ProtocolType::Http; }),
                  Bindings.end());
        EXPECT_EQ(std::find_if(Bindings.begin(), Bindings.end(), [](const auto &Binding)
                               { return Binding.Protocol == ProtocolType::Hysteria2; }),
                  Bindings.end());
        EXPECT_EQ(std::find_if(Bindings.begin(), Bindings.end(), [](const auto &Binding)
                               { return Binding.Protocol == ProtocolType::Tuic; }),
                  Bindings.end());
    }

    TEST(Task9ProtocolMatrix, UdpAssociationsAreExplicitAndProtocolScoped)
    {
        const auto Bindings = ProtocolMatrix::UdpAssociations();

        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("socks5"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("vless"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("trojan"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("vmess"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("ss2022"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("hysteria2"));
        EXPECT_TRUE(ProtocolMatrix::SupportsUdp("tuic"));
        EXPECT_FALSE(ProtocolMatrix::SupportsUdp("http"));
        EXPECT_EQ(Bindings.size(), 7U);
    }

    TEST(Task9ProtocolMatrix, QuicBindingUsesAlpnAndConfiguredProtocol)
    {
        const auto Hysteria = ProtocolMatrix::FindQuic("h3", ProtocolType::Hysteria2);
        const auto Tuic = ProtocolMatrix::FindQuic("h3", ProtocolType::Tuic);

        ASSERT_TRUE(Hysteria.has_value());
        ASSERT_TRUE(Tuic.has_value());
        EXPECT_EQ(Hysteria->Alpn, "h3");
        EXPECT_EQ(Tuic->Alpn, "h3");
        EXPECT_FALSE(ProtocolMatrix::FindQuic("unknown", ProtocolType::Tuic).has_value());
    }

    TEST(Task9ProtocolMatrix, OperationScopesRemainDistinct)
    {
        EXPECT_NE(ProtocolMatrix::ScopeFor(ProtocolType::Http), ProtocolMatrix::ScopeFor(ProtocolType::Tuic));
        EXPECT_EQ(ProtocolMatrix::ScopeFor(ProtocolType::Http), OperationScope::TcpRecognition);
        EXPECT_EQ(ProtocolMatrix::ScopeFor(ProtocolType::Tuic), OperationScope::QuicBinding);
    }

    TEST(Task9ProtocolMatrix, CarrierNamesRemainSeparateFromProtocolRecognition)
    {
        const auto Carriers = ProtocolMatrix::Carriers();

        EXPECT_EQ(Carriers.size(), 9U);
        EXPECT_EQ(Carriers.front().Name, "native");
        EXPECT_EQ(Carriers.front().Scheme, "native");
        EXPECT_EQ(Carriers[6].Name, "ws");
        EXPECT_EQ(Carriers[6].Scheme, "ws");
        const auto Tcp = ProtocolMatrix::TcpRecognition();
        EXPECT_EQ(std::find_if(Tcp.begin(), Tcp.end(),
                               [](const auto &Binding) { return Binding.Name == "ws"; }),
                  Tcp.end());
    }

} // namespace
