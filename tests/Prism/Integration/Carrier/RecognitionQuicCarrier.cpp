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

#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>

namespace
{

    TEST(RecognitionQuicCarrier, Hysteria2PacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Prism::Hysteria2::ClientConfig ClientConfig{};
        const auto Client = Prism::Hysteria2::ConnectPacketResult(
            Io.get_executor(), "127.0.0.1:1", ClientConfig);
        const auto Server = Prism::Hysteria2::AcceptPacketResult(
            Io.get_executor(), 0, Prism::Hysteria2::ServerConfig{});
        const auto Invalid = Prism::Hysteria2::ConnectPacketResult(
            Io.get_executor(), "invalid endpoint", ClientConfig);

        EXPECT_EQ(Client.Status, Prism::Error::None);
        EXPECT_EQ(Server.Status, Prism::Error::None);
        EXPECT_TRUE(Client.Datagram);
        EXPECT_TRUE(Server.Datagram);
        EXPECT_EQ(Invalid.Status, Prism::Error::BadAddress);
        EXPECT_FALSE(Invalid.Datagram);
        (void)Client.Datagram->Close();
        (void)Server.Datagram->Close();
    }

    TEST(RecognitionQuicCarrier, TuicPacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Prism::Tuic::ClientConfig ClientConfig{};
        const auto Client = Prism::Tuic::ConnectPacketResult(
            Io.get_executor(), "127.0.0.1:1", ClientConfig);
        const auto Server = Prism::Tuic::AcceptPacketResult(
            Io.get_executor(), 0, Prism::Tuic::ServerConfig{});
        const auto Invalid = Prism::Tuic::ConnectPacketResult(
            Io.get_executor(), "invalid endpoint", ClientConfig);

        EXPECT_EQ(Client.Status, Prism::Error::None);
        EXPECT_EQ(Server.Status, Prism::Error::None);
        EXPECT_TRUE(Client.Datagram);
        EXPECT_TRUE(Server.Datagram);
        EXPECT_EQ(Invalid.Status, Prism::Error::BadAddress);
        EXPECT_FALSE(Invalid.Datagram);
        (void)Client.Datagram->Close();
        (void)Server.Datagram->Close();
    }

    class FakeDatagramProvider final : public Prism::Quic::DatagramProvider
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
        auto Adapter = std::make_shared<Prism::Quic::DatagramAdapter>(Provider);
        std::array<std::byte, 5> Data{};
        std::size_t Written = 0;
        std::error_code Error;
        boost::asio::co_spawn(
            Io,
            [&]() -> boost::asio::awaitable<void>
            {
                const auto Write = co_await Adapter->WriteSome(Data);
                Error = Prism::Fault::ToNative(Write.Failure);
                Written = Write.Bytes;
                Io.stop();
            },
            boost::asio::detached);
        Io.run();

        EXPECT_EQ(Written, 2U);
        EXPECT_EQ(Error, Prism::make_error_code(Prism::Error::IoError));
        (void)Adapter->Cancel();
        EXPECT_TRUE(Provider->Cancelled_);
        (void)Adapter->Close();
        EXPECT_TRUE(Provider->IsClosed());
        EXPECT_FALSE(Adapter->IsOpen());
    }

} // namespace
