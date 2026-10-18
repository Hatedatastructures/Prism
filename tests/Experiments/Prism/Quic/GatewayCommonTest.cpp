/**
 * @file GatewayCommonTest.cpp
 * @brief QUIC 实验连接级协议绑定与 drain 行为测试。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>

#include <Experiments/Prism/Quic/GatewayCommon.hpp>

namespace
{

    class RecordingGateway final : public Prism::Experiments::Quic::GatewayCommon
    {
    protected:
        auto OnH3Stream(ConnKey, std::span<const std::byte>) -> void override
        {
            ++H3Streams;
        }

        auto OnTuicStream(ConnKey, std::span<const std::byte>) -> void override
        {
            ++TuicStreams;
        }

    public:
        std::size_t H3Streams{0};
        std::size_t TuicStreams{0};
    };

    TEST(Task9Front, GatewayTypedRegistrationAndDrainAreExplicit)
    {
        Prism::Experiments::Quic::GatewayCommon Gateway;
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      0, Prism::Experiments::Quic::ConnectionProtocol::H3, "h3", 1),
                  Prism::Error::BadMessage);
        EXPECT_EQ(Gateway.RegisterTypedConnection(
                      21, Prism::Experiments::Quic::ConnectionProtocol::H3, "h3", 1),
                  Prism::Error::None);
        EXPECT_EQ(Gateway.BeginDrain(21), Prism::Error::None);
        EXPECT_EQ(Gateway.DispatchTyped(21, {}), Prism::Error::Canceled);
        EXPECT_EQ(Gateway.DispatchTyped(21, 7, {}), Prism::Error::Canceled);
        EXPECT_EQ(Gateway.BeginDrain(999), Prism::Error::NotOpen);
    }

    TEST(RecognitionQuicCarrier, DoesNotGuessProtocolFromStreamFirstByte)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(41));
        const std::array<std::byte, 1> H3Like{std::byte{0x01}};
        const std::array<std::byte, 1> TuicLike{std::byte{0x05}};

        EXPECT_FALSE(Gateway.Dispatch(41, H3Like));
        EXPECT_FALSE(Gateway.Dispatch(41, TuicLike));
        ASSERT_NE(Gateway.Lookup(41), nullptr);
        EXPECT_EQ(Gateway.Lookup(41)->Type, Prism::Experiments::Quic::ConnectionProtocol::Unknown);
        EXPECT_EQ(Gateway.Lookup(41)->StreamCount, 0U);
        EXPECT_EQ(Gateway.H3Streams, 0U);
        EXPECT_EQ(Gateway.TuicStreams, 0U);
    }

    TEST(RecognitionQuicCarrier, BoundConnectionOwnsProtocolAcrossInterleavedStreams)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(51, Prism::Experiments::Quic::ConnectionProtocol::H3, "h3"));
        const std::array<std::byte, 1> First{std::byte{0x05}};
        const std::array<std::byte, 1> Second{std::byte{0x01}};

        EXPECT_TRUE(Gateway.Dispatch(51, First));
        EXPECT_TRUE(Gateway.Dispatch(51, Second));
        ASSERT_NE(Gateway.Lookup(51), nullptr);
        EXPECT_EQ(Gateway.Lookup(51)->Type, Prism::Experiments::Quic::ConnectionProtocol::H3);
        EXPECT_EQ(Gateway.Lookup(51)->Alpn, "h3");
        EXPECT_EQ(Gateway.Lookup(51)->StreamCount, 2U);
        EXPECT_EQ(Gateway.H3Streams, 2U);
        EXPECT_EQ(Gateway.TuicStreams, 0U);
    }

    TEST(RecognitionQuicCarrier, UnknownCidAndSourceDoNotMutateBoundConnection)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(52, Prism::Experiments::Quic::ConnectionProtocol::Tuic, "tuic"));
        const std::array<std::byte, 2> Data{std::byte{0xA5}, std::byte{0x5A}};

        EXPECT_FALSE(Gateway.Dispatch(999, 7, Data));
        EXPECT_FALSE(Gateway.Dispatch(52, 0, Data));
        EXPECT_TRUE(Gateway.Dispatch(52, 101, Data));
        EXPECT_TRUE(Gateway.Dispatch(52, 202, Data));
        ASSERT_NE(Gateway.Lookup(52), nullptr);
        EXPECT_EQ(Gateway.Lookup(52)->PeerSource, 202U);
        EXPECT_EQ(Gateway.Lookup(52)->StreamCount, 2U);
        EXPECT_EQ(Gateway.Lookup(52)->Type, Prism::Experiments::Quic::ConnectionProtocol::Tuic);
        EXPECT_EQ(Gateway.H3Streams, 0U);
        EXPECT_EQ(Gateway.TuicStreams, 2U);
    }

    TEST(RecognitionQuicCarrier, ConnectionCleanupRemovesCidState)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(53, Prism::Experiments::Quic::ConnectionProtocol::H3, "h3"));
        EXPECT_EQ(Gateway.Size(), 1U);
        EXPECT_TRUE(Gateway.EraseConnection(53));
        EXPECT_EQ(Gateway.Size(), 0U);
        EXPECT_FALSE(Gateway.Dispatch(53, std::array<std::byte, 1>{std::byte{0x01}}));
    }

} // namespace
