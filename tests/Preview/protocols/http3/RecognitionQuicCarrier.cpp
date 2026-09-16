/**
 * @file RecognitionQuicCarrier.cpp
 * @brief QUIC 连接级协议绑定与 packet factory RED 测试
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Protocols/Quic/GatewayCommon.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>

namespace
{

    class RecordingGateway final : public Preview::Quic::GatewayCommon
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

    TEST(RecognitionQuicCarrier, DoesNotGuessProtocolFromStreamFirstByte)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(41));
        const std::array<std::byte, 1> H3Like{std::byte{0x01}};
        const std::array<std::byte, 1> TuicLike{std::byte{0x05}};

        EXPECT_FALSE(Gateway.Dispatch(41, H3Like));
        EXPECT_FALSE(Gateway.Dispatch(41, TuicLike));
        ASSERT_NE(Gateway.Lookup(41), nullptr);
        EXPECT_EQ(Gateway.Lookup(41)->Type, Preview::Quic::ProtocolGuess::Unknown);
        EXPECT_EQ(Gateway.Lookup(41)->StreamCount, 0U);
        EXPECT_EQ(Gateway.H3Streams, 0U);
        EXPECT_EQ(Gateway.TuicStreams, 0U);
    }

    TEST(RecognitionQuicCarrier, Hysteria2PacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Preview::Hysteria2::ClientConfig ClientConfig{};
        const auto Client = Preview::Hysteria2::ConnectPacketResult(
            Io.get_executor(), "127.0.0.1:1", ClientConfig);
        const auto Server = Preview::Hysteria2::AcceptPacketResult(
            Io.get_executor(), 0, Preview::Hysteria2::ServerConfig{});
        const auto Invalid = Preview::Hysteria2::ConnectPacketResult(
            Io.get_executor(), "invalid endpoint", ClientConfig);

        EXPECT_EQ(Client.Status, Preview::Error::None);
        EXPECT_EQ(Server.Status, Preview::Error::None);
        EXPECT_TRUE(Client.Datagram);
        EXPECT_TRUE(Server.Datagram);
        EXPECT_EQ(Invalid.Status, Preview::Error::BadAddress);
        EXPECT_FALSE(Invalid.Datagram);
        Client.Datagram->Close();
        Server.Datagram->Close();
    }

    TEST(RecognitionQuicCarrier, TuicPacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Preview::Tuic::ClientConfig ClientConfig{};
        const auto Client = Preview::Tuic::ConnectPacketResult(
            Io.get_executor(), "127.0.0.1:1", ClientConfig);
        const auto Server = Preview::Tuic::AcceptPacketResult(
            Io.get_executor(), 0, Preview::Tuic::ServerConfig{});
        const auto Invalid = Preview::Tuic::ConnectPacketResult(
            Io.get_executor(), "invalid endpoint", ClientConfig);

        EXPECT_EQ(Client.Status, Preview::Error::None);
        EXPECT_EQ(Server.Status, Preview::Error::None);
        EXPECT_TRUE(Client.Datagram);
        EXPECT_TRUE(Server.Datagram);
        EXPECT_EQ(Invalid.Status, Preview::Error::BadAddress);
        EXPECT_FALSE(Invalid.Datagram);
        Client.Datagram->Close();
        Server.Datagram->Close();
    }

    TEST(RecognitionQuicCarrier, BoundConnectionOwnsProtocolAcrossInterleavedStreams)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(51, Preview::Quic::ConnectionProtocol::H3, "h3"));
        const std::array<std::byte, 1> First{std::byte{0x05}};
        const std::array<std::byte, 1> Second{std::byte{0x01}};

        EXPECT_TRUE(Gateway.Dispatch(51, First));
        EXPECT_TRUE(Gateway.Dispatch(51, Second));
        ASSERT_NE(Gateway.Lookup(51), nullptr);
        EXPECT_EQ(Gateway.Lookup(51)->Type, Preview::Quic::ConnectionProtocol::H3);
        EXPECT_EQ(Gateway.Lookup(51)->Alpn, "h3");
        EXPECT_EQ(Gateway.Lookup(51)->StreamCount, 2U);
        EXPECT_EQ(Gateway.H3Streams, 2U);
        EXPECT_EQ(Gateway.TuicStreams, 0U);
    }

    TEST(RecognitionQuicCarrier, UnknownCidAndSourceDoNotMutateBoundConnection)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(52, Preview::Quic::ConnectionProtocol::Tuic, "tuic"));
        const std::array<std::byte, 2> Data{std::byte{0xA5}, std::byte{0x5A}};

        EXPECT_FALSE(Gateway.Dispatch(999, 7, Data));
        EXPECT_FALSE(Gateway.Dispatch(52, 0, Data));
        EXPECT_TRUE(Gateway.Dispatch(52, 101, Data));
        EXPECT_TRUE(Gateway.Dispatch(52, 202, Data));
        ASSERT_NE(Gateway.Lookup(52), nullptr);
        EXPECT_EQ(Gateway.Lookup(52)->PeerSource, 202U);
        EXPECT_EQ(Gateway.Lookup(52)->StreamCount, 2U);
        EXPECT_EQ(Gateway.Lookup(52)->Type, Preview::Quic::ConnectionProtocol::Tuic);
        EXPECT_EQ(Gateway.H3Streams, 0U);
        EXPECT_EQ(Gateway.TuicStreams, 2U);
    }

    TEST(RecognitionQuicCarrier, ConnectionCleanupRemovesCidState)
    {
        RecordingGateway Gateway;
        ASSERT_TRUE(Gateway.RegisterConnection(53, Preview::Quic::ConnectionProtocol::H3, "h3"));
        EXPECT_EQ(Gateway.Size(), 1U);
        EXPECT_TRUE(Gateway.EraseConnection(53));
        EXPECT_EQ(Gateway.Size(), 0U);
        EXPECT_FALSE(Gateway.Dispatch(53, std::array<std::byte, 1>{std::byte{0x01}}));
    }

    class FakeDatagramProvider final : public Preview::Quic::DatagramProvider
    {
    public:
        explicit FakeDatagramProvider(boost::asio::any_io_executor Executor) : Executor_(std::move(Executor)) {}

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Receive(std::span<std::byte> Buffer, std::error_code &Error)
            -> boost::asio::awaitable<std::size_t> override
        {
            Error.clear();
            if (Closed_)
            {
                co_return 0;
            }
            const auto Count = (std::min)(Buffer.size(), ReceiveBytes_);
            co_return Count;
        }

        [[nodiscard]] auto Send(std::span<const std::byte> Buffer, std::error_code &Error)
            -> boost::asio::awaitable<std::size_t> override
        {
            Error = SendError_;
            co_return (std::min)(Buffer.size(), SendBytes_);
        }

        void Close() override
        {
            Closed_ = true;
        }

        void Cancel() override
        {
            Cancelled_ = true;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        std::size_t ReceiveBytes_{0};
        std::size_t SendBytes_{0};
        std::error_code SendError_{};
        bool Cancelled_{false};

    private:
        boost::asio::any_io_executor Executor_;
        bool Closed_{false};
    };

    TEST(RecognitionQuicCarrier, DatagramAdapterRejectsShortWriteAndPropagatesLifecycle)
    {
        boost::asio::io_context Io;
        auto Provider = std::make_shared<FakeDatagramProvider>(Io.get_executor());
        Provider->SendBytes_ = 2;
        auto Adapter = std::make_shared<Preview::Quic::DatagramAdapter>(Provider);
        std::array<std::byte, 5> Data{};
        std::size_t Written = 0;
        std::error_code Error;
        boost::asio::co_spawn(
            Io,
            [&]() -> boost::asio::awaitable<void>
            {
                Written = co_await Adapter->async_write_some(Data, Error);
                Io.stop();
            },
            boost::asio::detached);
        Io.run();

        EXPECT_EQ(Written, 2U);
        EXPECT_EQ(Error, Preview::make_error_code(Preview::Error::IoError));
        Adapter->Cancel();
        EXPECT_TRUE(Provider->Cancelled_);
        Adapter->Close();
        EXPECT_TRUE(Provider->IsClosed());
        EXPECT_FALSE(Adapter->IsOpen());
    }

} // namespace
