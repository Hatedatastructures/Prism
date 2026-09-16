/**
 * @file TuicConnSession.cpp
 * @brief TUIC 流式连接会话测试（Conn 成功与错误路径）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Tuic = Preview::Tuic;

    using Address = Tuic::Address;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using Reliable = Preview::Transport::Reliable;
    using Tcp = Net::ip::tcp;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

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
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x40 + Index);
        }
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

    [[nodiscard]] auto SpawnTask(
        ExecutorType Executor,
        Net::awaitable<void> Coroutine)
        -> std::shared_ptr<CompletionChannel>
    {
        const auto Done =
            std::make_shared<CompletionChannel>(Executor, 1);
        auto Completion =
            [Done](std::exception_ptr Exception) -> void
        {
            (void)Done->try_send(
                boost::system::error_code{},
                Exception == nullptr);
        };
        Net::co_spawn(
            Executor,
            std::move(Coroutine),
            std::move(Completion));
        return Done;
    }

    TEST(TuicConnSession, ConnectAcceptRoundtrip)
    {
        Net::io_context IoContext;
        Tcp::acceptor Acceptor(
            IoContext,
            Tcp::endpoint(Tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        auto [AuthClient, AuthServer] =
            Preview::MakeMemoryPair(IoContext.get_executor());

        Tuic::ClientConfig ClientConfig;
        ClientConfig.uuid = MakeUuid();
        ClientConfig.password = "pw";
        ClientConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(AuthClient));
        ClientConfig.Exporter = TestExporter;
        Tuic::ServerConfig ServerConfig;
        ServerConfig.uuid = MakeUuid();
        ServerConfig.password = "pw";
        ServerConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(AuthServer));
        ServerConfig.Exporter = TestExporter;
        const auto Target = Address{
            Tuic::AddressType::Domain,
            "example.com",
            443};
        std::string Echoed;
        bool ServerAccepted = false;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto ServerOperation = [&]() -> Net::awaitable<void>
            {
                auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
                auto ServerTransport = std::make_shared<Reliable>(
                    std::move(Socket));
                auto [ErrorValue, Request, Connection] =
                    co_await Tuic::Accept(ServerTransport, ServerConfig);
                if (ErrorValue != Error::None || !Connection)
                {
                    co_return;
                }
                ServerAccepted = true;
                std::array<std::byte, 64> Buffer{};
                std::error_code ErrorCode;
                const auto Count = co_await Connection->async_read_some(
                    std::span<std::byte>(Buffer),
                    ErrorCode);
                if (!ErrorCode && Count > 0)
                {
                    const auto EchoBuffer = std::span<const std::byte>(
                        Buffer.data(),
                        Count);
                    (void)co_await Connection->async_write_some(
                        EchoBuffer,
                        ErrorCode);
                }
                Connection->Close();
                (void)Request;
            };
            const auto ServerDone = SpawnTask(
                IoContext.get_executor(),
                ServerOperation());

            Tcp::socket Socket(IoContext.get_executor());
            const auto Endpoint = Tcp::endpoint(
                Net::ip::address_v4::loopback(),
                Port);
            co_await Socket.async_connect(Endpoint, Net::use_awaitable);
            auto ClientTransport = std::make_shared<Reliable>(
                std::move(Socket));
            auto [ErrorValue, Connection] = co_await Tuic::Connect(
                ClientTransport,
                ClientConfig,
                Target);
            EXPECT_EQ(ErrorValue, Error::None);
            EXPECT_NE(Connection, nullptr);
            if (ErrorValue != Error::None || !Connection)
            {
                co_return;
            }
            const std::string Message = "tuic-Stream";
            std::error_code ErrorCode;
            const auto MessageBytes =
                Preview::AsBytes(Preview::AsU8Span(Message));
            (void)co_await Connection->async_write_some(
                MessageBytes,
                ErrorCode);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 64> Buffer{};
            const auto Count = co_await Connection->async_read_some(
                std::span<std::byte>(Buffer),
                ErrorCode);
            EXPECT_FALSE(ErrorCode);
            Echoed.assign(
                reinterpret_cast<const char *>(Buffer.data()),
                Count);
            Connection->Close();
            const auto ServerCompleted = co_await ServerDone->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        EXPECT_TRUE(ServerAccepted);
        EXPECT_EQ(Echoed, "tuic-Stream");
    }

    TEST(TuicConnSession, ExporterAuthenticationRejectsWrongPassword)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto [AuthClient, AuthServer] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        Tuic::ClientConfig ClientConfig;
        ClientConfig.uuid = MakeUuid();
        ClientConfig.password = "client-password";
        ClientConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(AuthClient));
        ClientConfig.Exporter = TestExporter;
        Tuic::ServerConfig ServerConfig;
        ServerConfig.uuid = MakeUuid();
        ServerConfig.password = "server-password";
        ServerConfig.AuthStream = std::make_shared<MemoryStream>(
            std::move(AuthServer));
        ServerConfig.Exporter = TestExporter;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto ServerOperation = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerStream)),
                    ServerConfig);
                EXPECT_EQ(ErrorValue, Error::BadAuth);
                EXPECT_FALSE(Connection);
                (void)Request;
            };
            const auto ServerDone = SpawnTask(
                IoContext.get_executor(),
                ServerOperation());
            auto [ErrorValue, Connection] = co_await Tuic::Connect(
                std::make_shared<MemoryStream>(std::move(ClientStream)),
                ClientConfig,
                Address{
                    Tuic::AddressType::Domain,
                    "example.com",
                    443});
            EXPECT_EQ(ErrorValue, Error::None);
            EXPECT_TRUE(Connection);
            if (Connection)
            {
                Connection->Close();
            }
            const auto ServerCompleted = co_await ServerDone->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(TuicConnSession, BadFrameRejected)
    {
        Net::io_context IoContext;
        Tcp::acceptor Acceptor(
            IoContext,
            Tcp::endpoint(Tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        Tuic::ServerConfig ServerConfig;
        ServerConfig.uuid = MakeUuid();
        ServerConfig.password = "pw";
        bool AcceptRejected = false;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto ServerOperation = [&]() -> Net::awaitable<void>
            {
                auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
                auto Transport = std::make_shared<Reliable>(std::move(Socket));
                auto [ErrorValue, Request, Connection] = co_await Tuic::Accept(
                    Transport,
                    ServerConfig);
                AcceptRejected = ErrorValue != Error::None;
                (void)Request;
                (void)Connection;
            };
            const auto ServerDone = SpawnTask(
                IoContext.get_executor(),
                ServerOperation());
            Tcp::socket Socket(IoContext.get_executor());
            const auto Endpoint = Tcp::endpoint(
                Net::ip::address_v4::loopback(),
                Port);
            co_await Socket.async_connect(Endpoint, Net::use_awaitable);
            const std::string Garbage = "\xff\xfe\xfd\xfc";
            const auto GarbageBuffer = Net::buffer(Garbage);
            co_await Socket.async_write_some(
                GarbageBuffer,
                Net::use_awaitable);
            Socket.close();
            const auto ServerCompleted = co_await ServerDone->async_receive(
                Net::use_awaitable);
            EXPECT_TRUE(ServerCompleted);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        EXPECT_TRUE(AcceptRejected);
    }
} // namespace
