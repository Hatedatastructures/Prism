/**
 * @file TuicConnErrorMatrix.cpp
 * @brief TUIC Conn 错误矩阵测试
 * @details 覆盖 Connect 头截断和完整握手成功路径。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Tuic = Prism::Tuic;

    using Address = Tuic::Address;
    using Error = Prism::Error;
    using MemoryStream = Prism::MemoryStream;
    using SharedTransmission = Prism::SharedTransmission;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x55);
        return Uuid;
    }

    [[nodiscard]] auto TestExporter(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) -> bool
    {
        std::uint8_t State = 0x5A;
        for (const auto Byte : Label)
        {
            State = static_cast<std::uint8_t>((State * 33U) ^ Byte);
        }
        for (const auto Character : Context)
        {
            State = static_cast<std::uint8_t>(
                (State * 33U) ^ static_cast<std::uint8_t>(Character));
        }
        for (std::size_t Index = 0; Index < Output.size(); ++Index)
        {
            State = static_cast<std::uint8_t>(
                State * 33U + static_cast<std::uint8_t>(Index));
            Output[Index] = State;
        }
        return true;
    }

    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        if (!Closed)
        {
            co_return false;
        }
        const auto Activity = Carrier.Activity();
        if (!Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value() && Activity->IsRetired();
    }

    auto RunTruncatedServer(
        SharedTransmission Data,
        Tuic::ServerConfig Config) -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
            std::move(Data),
            Config);
        EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
        EXPECT_FALSE(Connection);
        (void)Request;
    }

    auto RunHandshakeServer(
        SharedTransmission Data,
        Tuic::ServerConfig Config,
        const std::shared_ptr<CompletionChannel> &Done)
        -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
            std::move(Data),
            Config);
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_TRUE(Connection);
        EXPECT_EQ(Request.Cmd, Tuic::CmdConnect);
        EXPECT_EQ(Request.dst.Host, "t.internal");
        EXPECT_EQ(Request.dst.Port, 443u);
        (void)co_await Done->async_send(
            boost::system::error_code{},
            Net::use_awaitable);
    }

    struct HandshakeStreams final
    {
        MemoryStream Client;
        MemoryStream Server;
        MemoryStream AuthClient;
        MemoryStream AuthServer;
    };

    auto RunTruncatedHeaderScenario(
        Net::io_context &IoContext,
        HandshakeStreams Streams) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Streams.Client));
        auto AuthClient = std::make_shared<MemoryStream>(
            std::move(Streams.AuthClient));
        Tuic::ServerConfig Config;
        Config.uuid = MakeUuid();
        Config.password = "pw";
        Config.AuthStream = std::make_shared<MemoryStream>(
            std::move(Streams.AuthServer));
        Config.Exporter = TestExporter;

        std::array<std::uint8_t, Tuic::TokenLen> Token{};
        const auto Exported = TestExporter(
            std::span<std::uint8_t>(Token),
            std::span<const std::uint8_t>(Config.uuid),
            Config.password);
        EXPECT_TRUE(Exported);
        if (!Exported)
        {
            co_return;
        }
        const auto AuthWire = Tuic::BuildAuthenticate(Config.uuid, Token);
        const auto AuthWrite = co_await AuthClient->WriteExact(
            std::as_bytes(std::span<const std::uint8_t>(AuthWire)));
        EXPECT_EQ(AuthWrite.Bytes, AuthWire.size());
        EXPECT_FALSE(AuthWrite.Failure.Failed());
        if (AuthWrite.Failure.Failed() || AuthWrite.Bytes != AuthWire.size())
        {
            co_return;
        }
        const auto AuthShutdown = co_await AuthClient->WriteShutdown();
        EXPECT_TRUE(AuthShutdown);
        if (!AuthShutdown)
        {
            co_return;
        }

        const std::array<std::uint8_t, 1> PartialHeader{Tuic::ProtocolVersion};
        const auto HeaderWrite = co_await Client->WriteExact(
            std::as_bytes(std::span<const std::uint8_t>(PartialHeader)));
        EXPECT_EQ(HeaderWrite.Bytes, PartialHeader.size());
        EXPECT_FALSE(HeaderWrite.Failure.Failed());
        if (HeaderWrite.Failure.Failed() ||
            HeaderWrite.Bytes != PartialHeader.size())
        {
            co_return;
        }
        const auto ClientShutdown = co_await Client->WriteShutdown();
        EXPECT_TRUE(ClientShutdown);
        if (!ClientShutdown)
        {
            co_return;
        }

        const auto Done = std::make_shared<CompletionChannel>(
            IoContext.get_executor(),
            1);
        auto Failure = std::make_shared<std::exception_ptr>();
        auto ServerCompletion = [Done, Failure](std::exception_ptr Exception) -> void
        {
            *Failure = Exception;
            (void)Done->try_send(boost::system::error_code{});
        };
        auto ServerOperation = RunTruncatedServer(
            std::make_shared<MemoryStream>(std::move(Streams.Server)),
            Config);
        Net::co_spawn(
            IoContext.get_executor(),
            std::move(ServerOperation),
            std::move(ServerCompletion));

        (void)co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*Failure);
        EXPECT_TRUE(co_await CloseAndDrain(*Client));
        EXPECT_TRUE(co_await CloseAndDrain(*AuthClient));
    }

    auto RunSuccessfulHandshakeScenario(
        Net::io_context &IoContext,
        HandshakeStreams Streams) -> Net::awaitable<void>
    {
        const auto Uuid = MakeUuid();
        const auto Done = std::make_shared<CompletionChannel>(
            IoContext.get_executor(),
            1);
        auto Failure = std::make_shared<std::exception_ptr>();
        auto ServerConfig = Tuic::ServerConfig{};
        ServerConfig.uuid = Uuid;
        ServerConfig.password = "pw";
        ServerConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(Streams.AuthServer));
        ServerConfig.Exporter = TestExporter;
        auto ServerOperation = RunHandshakeServer(
            std::make_shared<MemoryStream>(std::move(Streams.Server)),
            ServerConfig,
            Done);
        auto ServerCompletion = [Done, Failure](std::exception_ptr Exception) -> void
        {
            *Failure = Exception;
            (void)Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(
            IoContext.get_executor(),
            std::move(ServerOperation),
            std::move(ServerCompletion));

        Tuic::ClientConfig ClientConfig;
        ClientConfig.uuid = Uuid;
        ClientConfig.password = "pw";
        ClientConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(Streams.AuthClient));
        ClientConfig.Exporter = TestExporter;
        const auto Target = Address{
            Tuic::AddressType::Domain,
            "t.internal",
            443};
        auto [ErrorValue, Connection] = co_await Tuic::Connect(
            std::make_shared<MemoryStream>(std::move(Streams.Client)),
            ClientConfig,
            Target);
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_NE(Connection, nullptr);
        (void)co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*Failure);
        if (Connection)
        {
            Connection->Close();
        }
    }

    TEST(TuicConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        auto [AuthClient, AuthServer] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(
            IoContext,
            RunTruncatedHeaderScenario(
                IoContext,
                {std::move(ClientStream), std::move(ServerStream),
                 std::move(AuthClient), std::move(AuthServer)}));
    }

    TEST(TuicConnErrorMatrix, HandshakeOk)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        auto [AuthClient, AuthServer] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(
            IoContext,
            RunSuccessfulHandshakeScenario(
                IoContext,
                {std::move(ClientStream), std::move(ServerStream),
                 std::move(AuthClient), std::move(AuthServer)}));
    }
} // namespace
