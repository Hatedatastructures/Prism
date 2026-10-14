/**
 * @file TrojanStressTest.cpp
 * @brief Trojan 协议会话压力测试（达标标准 C2）
 * @details 覆盖 200 次独立握手回环、16 并发连接和 2 MiB 分块传输；
 *          每条协程都有完成通知，异常不会被丢弃。
 * @note 使用 Trojan::Accept 服务端 + 原始 wire 客户端握手
 *       （Sha224 凭据 + CRLF 分隔请求头，无服务端响应字节）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
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
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Trojan = Preview::Trojan;

    using Address = Trojan::Address;
    using AddressType = Trojan::AddressType;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using SharedMemoryStream = std::shared_ptr<MemoryStream>;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    /// 测试密码（Sha224 哈希后作为凭据）
    constexpr const char *Password = "pw123456";

    /** @brief 在启动协程前将内存传输对交给共享 owner。 */
    [[nodiscard]] auto MakeOwnedMemoryPair(ExecutorType Executor)
        -> std::pair<SharedMemoryStream, SharedMemoryStream>
    {
        auto [Client, Server] = Preview::MakeMemoryPair(std::move(Executor));
        return {std::make_shared<MemoryStream>(std::move(Client)),
                std::make_shared<MemoryStream>(std::move(Server))};
    }

    struct ServerOptions
    {
        SharedMemoryStream Stream;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
    };

    struct SessionOptions final
    {
        SharedMemoryStream ClientStream;
        SharedMemoryStream ServerStream;
        std::vector<std::uint8_t> Payload;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
    };

    struct SessionState
    {
        Net::io_context &IoContext;
        ExecutorType Executor;
        SharedMemoryStream ClientStream;
        SharedMemoryStream ServerStream;
        std::vector<std::uint8_t> Payload;
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
        const AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> Address
    {
        Address Result;
        Result.Type = Type;
        Result.Host = std::move(Host);
        Result.Port = Port;
        return Result;
    }

    [[nodiscard]] auto BuildRawRequest(const Address &Target)
        -> std::vector<std::uint8_t>
    {
        const auto Credential = Trojan::Credential(Password);
        return Trojan::BuildRequest(
            Credential,
            Trojan::Command::Connect,
            Target);
    }

    [[nodiscard]] auto MakePayload(std::string_view Text)
        -> std::vector<std::uint8_t>
    {
        return {
            reinterpret_cast<const std::uint8_t *>(Text.data()),
            reinterpret_cast<const std::uint8_t *>(Text.data()) + Text.size()};
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<bool>
    {
        const auto AcceptResult = co_await Trojan::Accept(
            Options.Stream,
            Trojan::ServerConfig{Password});
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            const auto StreamClose = Options.Stream->Close();
            const auto StreamDrain = co_await Options.Stream->Activity()->Drain();
            EXPECT_TRUE(StreamClose);
            EXPECT_TRUE(StreamDrain);
            co_return false;
        }
        const auto &Connection = AcceptResult->Connection;

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        while (Received < Options.TotalBytes)
        {
            const auto ReadSize =
                std::min(Options.BlockSize, Options.TotalBytes - Received);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto Read = co_await Connection->ReadSome(ReadWindow);
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > ReadSize)
            {
                break;
            }
            if (Options.Echo)
            {
                auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Read.Bytes);
                const auto Written = co_await Connection->WriteExact(WriteWindow);
                if (Written.Failure.Failed() || Written.Bytes != Read.Bytes)
                {
                    break;
                }
            }
            Received += Read.Bytes;
        }

        const auto Close = Connection->Close();
        const auto Drain = co_await Connection->Activity()->Drain();
        const auto StreamClose = Options.Stream->Close();
        const auto StreamDrain = co_await Options.Stream->Activity()->Drain();
        const bool Completed = Received == Options.TotalBytes;
        if (!Close || !Drain || !StreamClose || !StreamDrain)
        {
            co_return false;
        }
        co_return Completed;
    }

    [[nodiscard]] auto RunClientTransfer(SessionState &State) -> Net::awaitable<bool>
    {
        const auto Target = MakeAddress(
            AddressType::Domain,
            "example.com",
            443);
        const auto Header = BuildRawRequest(Target);
        const auto HeaderBytes = std::span<const std::uint8_t>(Header);
        const auto HeaderBuffer = Preview::AsBytes(HeaderBytes);
        const auto HeaderWritten = co_await State.ClientStream->WriteExact(HeaderBuffer);
        bool ClientCompleted = !HeaderWritten.Failure.Failed() &&
                               HeaderWritten.Bytes == Header.size();

        if (State.Payload.empty() && State.TotalBytes > 0)
        {
            ClientCompleted = false;
        }

        std::size_t Sent = 0;
        while (ClientCompleted && Sent < State.TotalBytes)
        {
            const auto PayloadOffset = Sent % State.Payload.size();
            const auto RemainingPayload = State.Payload.size() - PayloadOffset;
            const auto WriteSize =
                std::min(RemainingPayload, State.TotalBytes - Sent);
            const auto PayloadBytes = std::span<const std::uint8_t>(
                State.Payload.data() + PayloadOffset,
                WriteSize);
            const auto PayloadBuffer = Preview::AsBytes(PayloadBytes);
            const auto Written = co_await State.ClientStream->WriteSome(PayloadBuffer);
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > WriteSize)
            {
                ClientCompleted = false;
                break;
            }
            Sent += Written.Bytes;
            if (State.BlockSize > 0 &&
                ((Sent / State.BlockSize) & 0x0F) == 0)
            {
                const auto PostToken = Net::use_awaitable;
                co_await Net::post(State.Executor, PostToken);
            }
        }
        if (Sent != State.TotalBytes)
        {
            ClientCompleted = false;
        }

        if (ClientCompleted)
        {
            const auto Shutdown = co_await State.ClientStream->WriteShutdown();
            if (!Shutdown)
            {
                ClientCompleted = false;
            }
        }

        if (ClientCompleted && State.Echo)
        {
            std::vector<std::byte> EchoBuffer(State.BlockSize);
            std::size_t Received = 0;
            while (Received < State.TotalBytes)
            {
                const auto ReadSize =
                    std::min(EchoBuffer.size(), State.TotalBytes - Received);
                auto ReadWindow = std::span<std::byte>(
                    EchoBuffer.data(),
                    ReadSize);
                const auto Read = co_await State.ClientStream->ReadSome(ReadWindow);
                if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > ReadSize)
                {
                    ClientCompleted = false;
                    break;
                }
                for (std::size_t Index = 0; Index < Read.Bytes; ++Index)
                {
                    const auto Expected =
                        State.Payload[(Received + Index) % State.Payload.size()];
                    if (EchoBuffer[Index] != static_cast<std::byte>(Expected))
                    {
                        ClientCompleted = false;
                        break;
                    }
                }
                if (!ClientCompleted)
                {
                    break;
                }
                Received += Read.Bytes;
            }
            if (Received != State.TotalBytes)
            {
                ClientCompleted = false;
            }
        }
        co_return ClientCompleted;
    }

    [[nodiscard]] auto RunSession(SessionState State) -> Net::awaitable<bool>
    {
        const auto Completion =
            std::make_shared<CompletionChannel>(State.Executor, 1);
        ServerOptions ServerState{
            std::move(State.ServerStream),
            State.TotalBytes,
            State.BlockSize,
            State.Echo};
        auto ServerCompletion =
            [Completion](std::exception_ptr Exception, const bool Completed) -> void
        {
            (void)Completion->try_send(
                boost::system::error_code{},
                Exception == nullptr && Completed);
        };
        Net::co_spawn(
            State.Executor,
            RunServer(std::move(ServerState)),
            std::move(ServerCompletion));

        bool ClientCompleted = false;
        try
        {
            ClientCompleted = co_await RunClientTransfer(State);
        }
        catch (...)
        {
            ClientCompleted = false;
        }
        if (!ClientCompleted)
        {
            const auto Shutdown = co_await State.ClientStream->WriteShutdown();
            if (!Shutdown)
            {
                const auto ClientClose = State.ClientStream->Close();
                (void)ClientClose;
            }
        }
        const auto ServerCompleted =
            co_await Completion->async_receive(Net::use_awaitable);
        const auto ClientClose = State.ClientStream->Close();
        const auto ClientDrain = co_await State.ClientStream->Activity()->Drain();
        if (!ClientClose || !ClientDrain)
        {
            co_return false;
        }
        const bool Completed = ClientCompleted && ServerCompleted;
        co_return Completed;
    }

    auto RunSessionAndReport(SessionState State) -> Net::awaitable<bool>
    {
        try
        {
            co_return co_await RunSession(std::move(State));
        }
        catch (...)
        {
            co_return false;
        }
    }

    [[nodiscard]] auto RunSingle(SessionState State) -> bool
    {
        auto &IoContext = State.IoContext;
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

    [[nodiscard]] auto MakeSessionState(
        Net::io_context &IoContext,
        SessionOptions Options) -> SessionState
    {
        return SessionState{
            IoContext,
            IoContext.get_executor(),
            std::move(Options.ClientStream),
            std::move(Options.ServerStream),
            std::move(Options.Payload),
            Options.TotalBytes,
            Options.BlockSize,
            Options.Echo};
    }

    struct ConcurrentSessionsRequest final
    {
        Net::io_context &IoContext;
        ExecutorType Executor;
        std::vector<std::uint8_t> Payload;
        std::shared_ptr<CompletionChannel> Results;
    };

    /** @brief 启动并等待固定数量的独立 Trojan 会话。 */
    auto RunConcurrentSessions(ConcurrentSessionsRequest Request) -> Net::awaitable<void>
    {
        constexpr std::size_t ConnectionCount = 16;
        for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
        {
            auto [ClientStream, ServerStream] =
                MakeOwnedMemoryPair(Request.Executor);
            auto State = MakeSessionState(
                Request.IoContext,
                SessionOptions{
                    std::move(ClientStream),
                    std::move(ServerStream),
                    Request.Payload,
                    Request.Payload.size(),
                    4096,
                    true});
            auto CompletionHandler =
                [Results = Request.Results](
                    std::exception_ptr Exception,
                    const bool Completed) -> void
            {
                (void)Results->try_send(
                    boost::system::error_code{},
                    Exception == nullptr && Completed);
            };
            Net::co_spawn(
                Request.Executor,
                RunSessionAndReport(std::move(State)),
                std::move(CompletionHandler));
        }
        std::size_t SuccessfulConnections = 0;
        for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
        {
            if (co_await Request.Results->async_receive(Net::use_awaitable))
            {
                ++SuccessfulConnections;
            }
        }
        EXPECT_EQ(SuccessfulConnections, ConnectionCount);
    }

    TEST(TrojanStress, ConnectLoopNoLeak)
    {
        constexpr int Rounds = 200;
        const auto Payload = MakePayload("stress-payload");
        int SuccessfulRounds = 0;
        for (int Round = 0; Round < Rounds; ++Round)
        {
            Net::io_context IoContext;
            auto [ClientStream, ServerStream] =
                MakeOwnedMemoryPair(IoContext.get_executor());
            auto State = MakeSessionState(
                IoContext,
                SessionOptions{
                    std::move(ClientStream),
                    std::move(ServerStream),
                    Payload,
                    Payload.size(),
                    4096,
                    true});
            if (RunSingle(std::move(State)))
            {
                ++SuccessfulRounds;
            }
        }
        EXPECT_EQ(SuccessfulRounds, Rounds);
    }

    TEST(TrojanStress, Concurrent16)
    {
        constexpr std::size_t ConnectionCount = 16;
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        const auto Payload = MakePayload("concurrent-payload");
        const auto ResultChannel =
            std::make_shared<CompletionChannel>(Executor, ConnectionCount);
        RunCoroutine(IoContext, RunConcurrentSessions(ConcurrentSessionsRequest{
            IoContext,
            Executor,
            Payload,
            ResultChannel}));
    }

    TEST(TrojanStress, Transfer2MB)
    {
        constexpr std::size_t TotalBytes = 2 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            MakeOwnedMemoryPair(IoContext.get_executor());
        const std::vector<std::uint8_t> Payload(BlockSize, 0xAB);
        auto State = MakeSessionState(
            IoContext,
            SessionOptions{
                std::move(ClientStream),
                std::move(ServerStream),
                Payload,
                TotalBytes,
                BlockSize,
                false});
        EXPECT_TRUE(RunSingle(std::move(State)));
    }
} // namespace
