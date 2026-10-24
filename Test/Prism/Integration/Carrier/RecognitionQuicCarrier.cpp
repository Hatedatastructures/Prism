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
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

#include <exception>
#include <expected>
#include <optional>
#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>

namespace
{
    namespace Net = boost::asio;

    template <typename Datagram>
    auto CloseAndDrainDatagram(Datagram DatagramValue) -> Net::awaitable<void>
    {
        EXPECT_TRUE(DatagramValue->Close());
        const auto Activity = DatagramValue->Activity();
        if (!Activity)
        {
            ADD_FAILURE() << "datagram has no activity owner";
            co_return;
        }
        EXPECT_TRUE(co_await Activity->Drain());
    }

    template <typename ClientResult, typename ServerResult>
    auto CloseAndDrainDatagrams(
        const ClientResult &ClientValue,
        const ServerResult &ServerValue) -> Net::awaitable<void>
    {
        if (ClientValue.has_value() && ClientValue.value())
            co_await CloseAndDrainDatagram(ClientValue.value());
        if (ServerValue.has_value() && ServerValue.value())
            co_await CloseAndDrainDatagram(ServerValue.value());
    }

    auto RunCoro(Net::io_context &Io, Net::awaitable<void> Operation)
        -> std::exception_ptr
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error)
                      { Failure = std::move(Error); });
        Io.run();
        return Failure;
    }

    struct DatagramAdapterOutcome final
    {
        std::size_t Written{0};
        std::error_code Error{};
        bool CancelAccepted{false};
        bool CloseAccepted{false};
        bool ActivityDrained{false};
    };

    auto RunDatagramAdapterScenario(
        const std::shared_ptr<Prism::Quic::DatagramAdapter> &Adapter,
        const std::span<const std::byte> Data) -> Net::awaitable<DatagramAdapterOutcome>
    {
        DatagramAdapterOutcome Outcome;
        const auto Write = co_await Adapter->WriteSome(Data);
        Outcome.Error = Prism::Fault::ToNative(Write.Failure);
        Outcome.Written = Write.Bytes;
        Outcome.CancelAccepted = static_cast<bool>(Adapter->Cancel());
        Outcome.CloseAccepted = static_cast<bool>(Adapter->Close());
        Outcome.ActivityDrained = static_cast<bool>(
            co_await Adapter->Activity()->Drain());
        co_return Outcome;
    }

    TEST(RecognitionQuicCarrier, Hysteria2PacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Prism::Hysteria2::ClientConfig ClientConfig{};
        std::optional<std::expected<Prism::Hysteria2::SharedDgram, Prism::Fault::Failure>> Client;
        std::optional<std::expected<Prism::Hysteria2::SharedDgram, Prism::Fault::Failure>> Server;
        std::optional<std::expected<Prism::Hysteria2::SharedDgram, Prism::Fault::Failure>> Invalid;

        const auto Failure = RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            Client.emplace(co_await Prism::Hysteria2::ConnectPacket(
                Io.get_executor(), "127.0.0.1:1", ClientConfig));
            Server.emplace(co_await Prism::Hysteria2::AcceptPacket(
                Io.get_executor(), 0, Prism::Hysteria2::ServerConfig{}));
            Invalid.emplace(co_await Prism::Hysteria2::ConnectPacket(
                Io.get_executor(), "invalid endpoint", ClientConfig));
            co_await CloseAndDrainDatagrams(*Client, *Server);
        }());

        ASSERT_FALSE(Failure);
        ASSERT_TRUE(Client.has_value());
        ASSERT_TRUE(Server.has_value());
        ASSERT_TRUE(Invalid.has_value());
        EXPECT_TRUE(Client->has_value());
        EXPECT_TRUE(Server->has_value());
        ASSERT_FALSE(Invalid->has_value());
        EXPECT_EQ(Invalid->error().Code, Prism::Fault::Code::InvalidArgument);
    }

    TEST(RecognitionQuicCarrier, TuicPacketFactoryUsesUdpAndReportsInvalidEndpoint)
    {
        boost::asio::io_context Io;
        const Prism::Tuic::ClientConfig ClientConfig{};
        std::optional<std::expected<Prism::Tuic::SharedDgram, Prism::Fault::Failure>> Client;
        std::optional<std::expected<Prism::Tuic::SharedDgram, Prism::Fault::Failure>> Server;
        std::optional<std::expected<Prism::Tuic::SharedDgram, Prism::Fault::Failure>> Invalid;

        const auto Failure = RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            Client.emplace(co_await Prism::Tuic::ConnectPacket(
                Io.get_executor(), "127.0.0.1:1", ClientConfig));
            Server.emplace(co_await Prism::Tuic::AcceptPacket(
                Io.get_executor(), 0, Prism::Tuic::ServerConfig{}));
            Invalid.emplace(co_await Prism::Tuic::ConnectPacket(
                Io.get_executor(), "invalid endpoint", ClientConfig));
            co_await CloseAndDrainDatagrams(*Client, *Server);
        }());

        ASSERT_FALSE(Failure);
        ASSERT_TRUE(Client.has_value());
        ASSERT_TRUE(Server.has_value());
        ASSERT_TRUE(Invalid.has_value());
        EXPECT_TRUE(Client->has_value());
        EXPECT_TRUE(Server->has_value());
        ASSERT_FALSE(Invalid->has_value());
        EXPECT_EQ(Invalid->error().Code, Prism::Fault::Code::InvalidArgument);
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
        DatagramAdapterOutcome Outcome;
        const auto Failure = RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            Outcome = co_await RunDatagramAdapterScenario(Adapter, Data);
        }());

        ASSERT_FALSE(Failure);
        EXPECT_EQ(Outcome.Written, 2U);
        EXPECT_EQ(Outcome.Error, Prism::make_error_code(Prism::Error::IoError));
        EXPECT_TRUE(Outcome.CancelAccepted);
        EXPECT_TRUE(Provider->Cancelled_);
        EXPECT_TRUE(Outcome.CloseAccepted);
        EXPECT_TRUE(Outcome.ActivityDrained);
        EXPECT_TRUE(Provider->IsClosed());
        EXPECT_FALSE(Adapter->IsOpen());
    }

} // namespace
