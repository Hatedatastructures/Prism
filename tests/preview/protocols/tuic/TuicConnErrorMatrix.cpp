/**
 * @file TuicConnErrorMatrix.cpp
 * @brief TUIC Conn 错误矩阵测试
 * @details 覆盖认证输入提前关闭时的截断错误和完整握手成功路径。
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

#include <preview/Protocols/Tuic/Tuic.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Tuic = Preview::Tuic;

    using Address = Tuic::Address;
    using Error = Preview::Error;
    using MemoryStream = Preview::MemoryStream;
    using SharedTransmission = Preview::SharedTransmission;
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

    TEST(TuicConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto [AuthClient, AuthServer] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            Tuic::ServerConfig Config;
            Config.uuid = MakeUuid();
            Config.password = "pw";
            Config.AuthStream = std::make_shared<MemoryStream>(
                std::move(AuthServer));
            Config.Exporter = TestExporter;

            const auto Done =
                std::make_shared<CompletionChannel>(
                    IoContext.get_executor(),
                    1);
            auto Failure = std::make_shared<std::exception_ptr>();
            auto ServerCompletion =
                [Done, Failure](std::exception_ptr Exception) -> void
            {
                *Failure = Exception;
                (void)Done->try_send(boost::system::error_code{});
            };
            auto ServerOperation = RunTruncatedServer(
                std::make_shared<MemoryStream>(std::move(ServerStream)),
                Config);
            Net::co_spawn(
                IoContext.get_executor(),
                std::move(ServerOperation),
                std::move(ServerCompletion));

            (void)ClientStream;
            AuthClient.Close();
            (void)co_await Done->async_receive(Net::use_awaitable);
            EXPECT_FALSE(*Failure);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(TuicConnErrorMatrix, HandshakeOk)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto [AuthClient, AuthServer] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto Uuid = MakeUuid();
            const auto Done =
                std::make_shared<CompletionChannel>(
                    IoContext.get_executor(),
                    1);
            auto Failure = std::make_shared<std::exception_ptr>();
            auto Config = Tuic::ServerConfig{};
            Config.uuid = Uuid;
            Config.password = "pw";
            Config.AuthStream = std::make_shared<MemoryStream>(
                std::move(AuthServer));
            Config.Exporter = TestExporter;
            auto ServerOperation = RunHandshakeServer(
                std::make_shared<MemoryStream>(std::move(ServerStream)),
                Config,
                Done);
            auto ServerCompletion =
                [Done, Failure](std::exception_ptr Exception) -> void
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
                std::move(AuthClient));
            ClientConfig.Exporter = TestExporter;
            const auto Target = Address{
                Tuic::AddressType::Domain,
                "t.internal",
                443};
            auto [ErrorValue, Connection] = co_await Tuic::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                ClientConfig,
                Target);
            EXPECT_EQ(ErrorValue, Error::None);
            EXPECT_NE(Connection, nullptr);
            co_await Done->async_receive(Net::use_awaitable);
            EXPECT_FALSE(*Failure);
            if (Connection)
            {
                Connection->Close();
            }
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }
} // namespace
