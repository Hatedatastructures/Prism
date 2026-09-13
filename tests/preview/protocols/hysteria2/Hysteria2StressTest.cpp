/**
 * @file Hysteria2StressTest.cpp
 * @brief Hysteria2 协议会话压力测试
 * @details 生产级压力验证：
 * 1. 200 次连接循环（握手 + 回显，计数验证）
 * 2. 16 并发连接（并发正确性）
 * 3. 2MB 数据传输（64KB 分块，累积校验）
 * @note 使用 Hysteria2::Connect/Accept 自由函数 + MakeMemoryPair
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Hysteria2 = Preview::Hysteria2;

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;

    constexpr std::string_view Password = "stress-pw";
    constexpr std::size_t ConcurrentConnectionCount = 16;

    struct ServerOptions
    {
        MemoryStream Stream;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
        std::shared_ptr<CompletionChannel> Completion;
    };

    struct SessionState
    {
        ExecutorType Executor;
        MemoryStream ClientStream;
        MemoryStream ServerStream;
        std::vector<std::byte> Payload;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
    };

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

    [[nodiscard]] auto MakeAddress(
        std::string_view Host,
        const std::uint16_t Port) -> Hysteria2::Address
    {
        Hysteria2::Address AddressValue{};
        AddressValue.Type = Hysteria2::AddressType::Domain;
        AddressValue.Host = Host;
        AddressValue.Port = Port;
        return AddressValue;
    }

    [[nodiscard]] auto MakePayload(std::string_view Text)
        -> std::vector<std::byte>
    {
        const auto *Begin = reinterpret_cast<const std::byte *>(Text.data());
        return {Begin, Begin + Text.size()};
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        const auto AcceptResult = co_await Hysteria2::Accept(
            std::make_shared<MemoryStream>(std::move(Options.Stream)),
            Hysteria2::ServerConfig{std::string(Password)});
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Request = std::get<1>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        (void)Request;
        if (HandshakeError != Error::None || !Connection)
        {
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::error_code ReadError;
        std::size_t Received = 0;
        while (Received < Options.TotalBytes)
        {
            const auto ReadSize =
                std::min(Options.BlockSize, Options.TotalBytes - Received);
            const auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto Count = co_await Connection->async_read_some(
                ReadWindow,
                ReadError);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            if (Options.Echo)
            {
                std::error_code WriteError;
                const auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                const auto Written = co_await Connection->async_write_some(
                    WriteWindow,
                    WriteError);
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
            Received += Count;
        }

        Connection->Close();
        const bool Completed = Received == Options.TotalBytes;
        (void)Options.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    [[nodiscard]] auto RunSession(SessionState State) -> Net::awaitable<bool>
    {
        const auto Completion =
            std::make_shared<CompletionChannel>(State.Executor, 1);
        ServerOptions ServerState{
            std::move(State.ServerStream),
            State.TotalBytes,
            State.BlockSize,
            State.Echo,
            Completion};
        auto ServerCompletion =
            [Completion](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                (void)Completion->try_send(
                    boost::system::error_code{}, false);
            }
        };
        Net::co_spawn(
            State.Executor,
            RunServer(std::move(ServerState)),
            std::move(ServerCompletion));

        bool ClientCompleted = false;
        try
        {
            const auto ConnectResult = co_await Hysteria2::Connect(
                std::make_shared<MemoryStream>(std::move(State.ClientStream)),
                Hysteria2::ClientConfig{std::string(Password)},
                MakeAddress("example.com", 443));
            const auto HandshakeError = std::get<0>(ConnectResult);
            auto Client = std::get<1>(ConnectResult);
            ClientCompleted =
                HandshakeError == Error::None && Client != nullptr;
            if (ClientCompleted)
            {
                std::size_t Sent = 0;
                while (Sent < State.TotalBytes)
                {
                    const auto WriteSize =
                        std::min(State.Payload.size(), State.TotalBytes - Sent);
                    const auto WriteWindow = std::span<const std::byte>(
                        State.Payload.data(),
                        WriteSize);
                    std::error_code WriteError;
                    const auto Written = co_await Client->async_write_some(
                        WriteWindow,
                        WriteError);
                    if (WriteError || Written == 0 || Written > WriteSize)
                    {
                        ClientCompleted = false;
                        break;
                    }
                    Sent += Written;
                }
                if (Sent != State.TotalBytes)
                {
                    ClientCompleted = false;
                }

                if (ClientCompleted && State.Echo)
                {
                    std::vector<std::byte> EchoBuffer(State.BlockSize);
                    std::error_code ReadError;
                    std::size_t Received = 0;
                    while (Received < State.TotalBytes)
                    {
                        const auto ReadSize = std::min(
                            EchoBuffer.size(),
                            State.TotalBytes - Received);
                        const auto ReadWindow = std::span<std::byte>(
                            EchoBuffer.data(),
                            ReadSize);
                        const auto Count = co_await Client->async_read_some(
                            ReadWindow,
                            ReadError);
                        if (ReadError || Count == 0 || Count > ReadSize)
                        {
                            ClientCompleted = false;
                            break;
                        }
                        Received += Count;
                    }
                    if (Received != State.TotalBytes)
                    {
                        ClientCompleted = false;
                    }
                }
            }
            if (Client)
            {
                Client->Close();
            }
        }
        catch (...)
        {
            ClientCompleted = false;
        }

        const auto ServerCompleted =
            co_await Completion->async_receive(Net::use_awaitable);
        co_return ClientCompleted && ServerCompleted;
    }

    auto RunSessionAndReport(
        SessionState State,
        std::shared_ptr<CompletionChannel> ResultChannel)
        -> Net::awaitable<void>
    {
        bool Completed = false;
        try
        {
            Completed = co_await RunSession(std::move(State));
        }
        catch (...)
        {
            Completed = false;
        }
        (void)ResultChannel->try_send(
            boost::system::error_code{},
            Completed);
    }

    [[nodiscard]] auto RunSingle(
        Net::io_context &IoContext,
        SessionState State) -> bool
    {
        bool Completed = false;
        auto Coroutine =
            [&Completed, State = std::move(State)]() mutable
            -> Net::awaitable<void>
        {
            Completed = co_await RunSession(std::move(State));
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        return Completed;
    }

    [[nodiscard]] auto RunConcurrent(
        Net::io_context &IoContext,
        ExecutorType Executor,
        const std::vector<std::byte> &Payload)
        -> Net::awaitable<std::size_t>
    {
        const auto ResultChannel =
            std::make_shared<CompletionChannel>(
                Executor,
                ConcurrentConnectionCount);
        for (std::size_t Index = 0;
             Index < ConcurrentConnectionCount;
             ++Index)
        {
            auto [ClientStream, ServerStream] =
                Preview::MakeMemoryPair(Executor);
            auto State = SessionState{
                IoContext.get_executor(),
                std::move(ClientStream),
                std::move(ServerStream),
                Payload,
                Payload.size(),
                128,
                true};
            auto SessionCompletion =
                [ResultChannel](std::exception_ptr Exception) -> void
            {
                if (Exception)
                {
                    (void)ResultChannel->try_send(
                        boost::system::error_code{}, false);
                }
            };
            Net::co_spawn(
                Executor,
                RunSessionAndReport(std::move(State), ResultChannel),
                std::move(SessionCompletion));
        }

        std::size_t SuccessfulConnections = 0;
        for (std::size_t Index = 0;
             Index < ConcurrentConnectionCount;
             ++Index)
        {
            const auto Completed =
                co_await ResultChannel->async_receive(Net::use_awaitable);
            if (Completed)
            {
                ++SuccessfulConnections;
            }
        }
        co_return SuccessfulConnections;
    }

    TEST(Hysteria2Stress, ConnectLoop)
    {
        constexpr int Rounds = 200;
        const auto Payload = MakePayload("hysteria2-stress");
        int SuccessfulRounds = 0;
        for (int Round = 0; Round < Rounds; ++Round)
        {
            Net::io_context IoContext;
            auto [ClientStream, ServerStream] =
                Preview::MakeMemoryPair(IoContext.get_executor());
            const auto State = SessionState{
                IoContext.get_executor(),
                std::move(ClientStream),
                std::move(ServerStream),
                Payload,
                Payload.size(),
                4096,
                true};
            if (RunSingle(IoContext, std::move(State)))
            {
                ++SuccessfulRounds;
            }
        }
        EXPECT_EQ(SuccessfulRounds, Rounds);
    }

    TEST(Hysteria2Stress, Concurrent16)
    {
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        const auto Payload = MakePayload("concurrent-h2");
        std::size_t SuccessfulConnections = 0;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            SuccessfulConnections =
                co_await RunConcurrent(IoContext, Executor, Payload);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        EXPECT_EQ(SuccessfulConnections, ConcurrentConnectionCount);
    }

    TEST(Hysteria2Stress, Transfer2MB)
    {
        constexpr std::size_t TotalBytes = 2 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        const std::vector<std::byte> Payload(BlockSize, std::byte{0xAB});
        const auto State = SessionState{
            IoContext.get_executor(),
            std::move(ClientStream),
            std::move(ServerStream),
            Payload,
            TotalBytes,
            BlockSize,
            false};
        EXPECT_TRUE(RunSingle(IoContext, std::move(State)));
    }
} // namespace
