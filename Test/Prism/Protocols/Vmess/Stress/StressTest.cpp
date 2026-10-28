/**
 * @file StressTest.cpp
 * @brief VMess 协议会话压力测试（达标标准 C2）
 * @details 覆盖 200 次独立握手回环、16 并发连接和 2 MiB 分块传输；
 *          每条协程都有完成通知，异常不会被 detached 任务吞掉。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
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
#include <variant>
#include <vector>

#include <gtest/gtest.h>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Vmess = Prism::Vmess;

    using Address = Vmess::Address;
    using AddressType = Vmess::AddressType;
    using ClientConfig = Vmess::ClientConfig;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Prism::MemoryStream;
    using ServerConfig = Vmess::ServerConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct ServerOptions
    {
        ExecutorType Executor;
        MemoryStream Stream;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        bool Echo;
        std::shared_ptr<CompletionChannel> Completion;
    };

    struct SessionState
    {
        Net::io_context &IoContext;
        ExecutorType Executor;
        MemoryStream ClientStream;
        MemoryStream ServerStream;
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

    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        return Uuid;
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

    [[nodiscard]] auto MakePayload(std::string_view Text)
        -> std::vector<std::uint8_t>
    {
        return {
            reinterpret_cast<const std::uint8_t *>(Text.data()),
            reinterpret_cast<const std::uint8_t *>(Text.data()) + Text.size()};
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        ServerConfig Config;
        Config.uuid = MakeUuid();
        const auto AcceptResult = co_await Vmess::AcceptSession(
            std::make_shared<MemoryStream>(std::move(Options.Stream)),
            Config);
        EXPECT_TRUE(AcceptResult);
        auto* Accepted = AcceptResult
            ? std::get_if<Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult)
            {
                if (auto* Datagram = std::get_if<Vmess::AcceptedDatagram>(&*AcceptResult))
                {
                    auto Carrier = Datagram->Connection;
                    auto Stream = Carrier->Stream();
                    (void)Carrier->Close();
                    (void)Stream->Close();
                    (void)co_await Carrier->Activity()->Drain();
                    (void)co_await Stream->Activity()->Drain();
                }
            }
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }
        const auto &Connection = Accepted->Connection;

        std::vector<std::byte> Buffer(Options.BlockSize);
        std::size_t Received = 0;
        bool Failed = false;
        while (Received < Options.TotalBytes)
        {
            const auto ReadSize =
                std::min(Options.BlockSize, Options.TotalBytes - Received);
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto ReadResult =
                co_await Connection->ReadSome(ReadWindow);
            const auto Count = ReadResult.Bytes;
            if (Count > ReadSize)
            {
                Failed = true;
                break;
            }
            Received += Count;
            if (Options.Echo && Count > 0)
            {
                auto WriteWindow = std::span<const std::byte>(
                    Buffer.data(),
                    Count);
                std::size_t Written = 0;
                while (Written < Count)
                {
                    const auto Remaining = WriteWindow.subspan(Written);
                    const auto WriteResult = co_await Connection->WriteSome(Remaining);
                    if (WriteResult.Bytes > Remaining.size())
                    {
                        Failed = true;
                        break;
                    }
                    Written += WriteResult.Bytes;
                    if (WriteResult.Failure.Failed() || WriteResult.Bytes == 0)
                    {
                        Failed = true;
                        break;
                    }
                }
                if (Failed || Written != Count)
                {
                    Failed = true;
                    break;
                }
            }
            if (ReadResult.Failure.Failed() || Count == 0)
            {
                Failed = true;
                break;
            }
        }

        (void)Connection->Close();
        const bool Completed = !Failed && Received == Options.TotalBytes;
        (void)Options.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    /** @brief 发送压力输入并保留每次部分写的字节进度与首个 Failure。 */
    [[nodiscard]] auto SendVmessStressPayload(
        Prism::Vmess::SharedConn Client,
        const SessionState& State) -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Progress{};
        while (Progress.Bytes < State.TotalBytes)
        {
            const auto WriteSize =
                std::min(State.Payload.size(), State.TotalBytes - Progress.Bytes);
            if (WriteSize == 0)
            {
                Progress.Failure = {Prism::Fault::Code::InvalidArgument};
                co_return Progress;
            }
            const auto WriteWindow = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(State.Payload.data()), WriteSize);
            std::size_t BlockWritten = 0;
            while (BlockWritten < WriteSize)
            {
                const auto Remaining = WriteWindow.subspan(BlockWritten);
                const auto WriteResult = co_await Client->WriteSome(Remaining);
                if (WriteResult.Bytes > Remaining.size())
                {
                    Progress.Failure = {
                        Prism::Fault::Code::InvalidArgument, WriteResult.Failure.Native};
                    co_return Progress;
                }
                BlockWritten += WriteResult.Bytes;
                Progress.Bytes += WriteResult.Bytes;
                Progress.Failure = WriteResult.Failure;
                if (Progress.Failure.Failed())
                {
                    co_return Progress;
                }
                if (WriteResult.Bytes == 0)
                {
                    Progress.Failure = {Prism::Fault::Code::WouldBlock};
                    co_return Progress;
                }
            }
            if (((Progress.Bytes / State.BlockSize) & 0x0F) == 0)
            {
                co_await Net::post(State.Executor, Net::use_awaitable);
            }
        }
        co_return Progress;
    }

    [[nodiscard]] auto RunSession(SessionState State) -> Net::awaitable<bool>
    {
        const auto Completion =
            std::make_shared<CompletionChannel>(State.Executor, 1);
        ServerOptions ServerState{
            State.Executor,
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

        ClientConfig Config;
        Config.uuid = MakeUuid();
        const auto Target = MakeAddress(
            AddressType::Domain,
            "example.com",
            443);
        auto ClientResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            std::make_shared<MemoryStream>(std::move(State.ClientStream)),
            Config,
            Target});
        EXPECT_TRUE(ClientResult);
        if (ClientResult) EXPECT_TRUE(*ClientResult);
        bool ClientCompleted = ClientResult.has_value() && static_cast<bool>(*ClientResult);
        Vmess::SharedConn Client;
        if (ClientResult && *ClientResult) Client = std::move(*ClientResult);
        if (ClientCompleted)
        {
            const auto Sent = co_await SendVmessStressPayload(Client, State);
            const bool SendCompleted =
                !Sent.Failure.Failed() && Sent.Bytes == State.TotalBytes;
            bool EchoCompleted = true;
            if (State.Echo && Sent.Bytes > 0)
            {
                std::vector<std::byte> EchoBuffer(State.BlockSize);
                std::size_t Received = 0;
                while (Received < Sent.Bytes)
                {
                    const auto ReadSize =
                        std::min(EchoBuffer.size(), Sent.Bytes - Received);
                    auto ReadWindow = std::span<std::byte>(
                        EchoBuffer.data(),
                        ReadSize);
                    const auto ReadResult = co_await Client->ReadSome(ReadWindow);
                    const auto Count = ReadResult.Bytes;
                    if (Count > ReadSize)
                    {
                        EchoCompleted = false;
                        break;
                    }
                    const auto ReceivedBeforeRead = Received;
                    Received += Count;
                    for (std::size_t Index = 0; Index < Count; ++Index)
                    {
                        const auto Expected =
                            State.Payload[(ReceivedBeforeRead + Index) % State.Payload.size()];
                        if (EchoBuffer[Index] != static_cast<std::byte>(Expected))
                        {
                            EchoCompleted = false;
                            break;
                        }
                    }
                    if (!EchoCompleted || ReadResult.Failure.Failed() || Count == 0)
                    {
                        EchoCompleted = false;
                        break;
                    }
                }
                EchoCompleted = EchoCompleted && Received == Sent.Bytes;
            }
            ClientCompleted = SendCompleted && EchoCompleted;
            (void)Client->Close();
        }

        const auto ServerCompleted =
            co_await Completion->async_receive(Net::use_awaitable);
        co_return ClientCompleted && ServerCompleted;
    }

    auto RunSessionAndReport(
        SessionState State,
        const std::shared_ptr<CompletionChannel> &ResultChannel)
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

    struct VmessSessionInput final
    {
        MemoryStream ClientStream;
        MemoryStream ServerStream;
        std::vector<std::uint8_t> Payload;
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        bool Echo{false};
    };

    struct VmessConcurrentRequest final
    {
        std::shared_ptr<CompletionChannel> Results;
        std::vector<std::uint8_t> Payload;
        std::size_t Connections{0};
    };

    [[nodiscard]] auto MakeSessionState(
        Net::io_context& IoContext,
        VmessSessionInput Input) -> SessionState
    {
        return SessionState{
            IoContext,
            IoContext.get_executor(),
            std::move(Input.ClientStream),
            std::move(Input.ServerStream),
            std::move(Input.Payload),
            Input.TotalBytes,
            Input.BlockSize,
            Input.Echo};
    }

    TEST(VmessStress, ConnectLoopNoLeak)
    {
        constexpr int Rounds = 200;
        const auto Payload = MakePayload("stress-payload");
        int SuccessfulRounds = 0;
        for (int Round = 0; Round < Rounds; ++Round)
        {
            Net::io_context IoContext;
            auto [ClientStream, ServerStream] =
                Prism::MakeMemoryPair(IoContext.get_executor());
            auto State = MakeSessionState(IoContext, VmessSessionInput{
                std::move(ClientStream), std::move(ServerStream), Payload,
                Payload.size(), 4096, true});
            if (RunSingle(std::move(State)))
            {
                ++SuccessfulRounds;
            }
        }
        EXPECT_EQ(SuccessfulRounds, Rounds);
    }

    [[nodiscard]] auto RunConcurrentVmessSessions(
        Net::io_context& IoContext,
        VmessConcurrentRequest Request) -> Net::awaitable<std::size_t>
    {
        const auto Executor = IoContext.get_executor();
        std::size_t SuccessfulConnections = 0;
        for (std::size_t Index = 0; Index < Request.Connections; ++Index)
        {
            auto [ClientStream, ServerStream] = Prism::MakeMemoryPair(Executor);
            auto State = MakeSessionState(IoContext, VmessSessionInput{
                std::move(ClientStream), std::move(ServerStream), Request.Payload,
                Request.Payload.size(), 4096, true});
            const auto Results = Request.Results;
            auto SessionCompletion = [Results](std::exception_ptr Exception) -> void
            {
                if (Exception)
                {
                    (void)Results->try_send(boost::system::error_code{}, false);
                }
            };
            Net::co_spawn(
                Executor,
                RunSessionAndReport(std::move(State), Results),
                std::move(SessionCompletion));
        }
        for (std::size_t Index = 0; Index < Request.Connections; ++Index)
        {
            const auto Completed =
                co_await Request.Results->async_receive(Net::use_awaitable);
            if (Completed)
            {
                ++SuccessfulConnections;
            }
        }
        co_return SuccessfulConnections;
    }

    TEST(VmessStress, Concurrent16)
    {
        constexpr std::size_t ConnectionCount = 16;
        Net::io_context IoContext;
        VmessConcurrentRequest Request{
            std::make_shared<CompletionChannel>(
                IoContext.get_executor(), ConnectionCount),
            MakePayload("concurrent-payload"),
            ConnectionCount};
        std::size_t SuccessfulConnections = 0;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            SuccessfulConnections = co_await RunConcurrentVmessSessions(
                IoContext, std::move(Request));
        });
        EXPECT_EQ(SuccessfulConnections, ConnectionCount);
    }

    TEST(VmessStress, Transfer2MB)
    {
        constexpr std::size_t TotalBytes = 2 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        const std::vector<std::uint8_t> Payload(
            BlockSize,
            0xAB);
        auto State = MakeSessionState(IoContext, VmessSessionInput{
            std::move(ClientStream), std::move(ServerStream), Payload,
            TotalBytes, BlockSize, false});
        EXPECT_TRUE(RunSingle(std::move(State)));
    }
} // namespace
