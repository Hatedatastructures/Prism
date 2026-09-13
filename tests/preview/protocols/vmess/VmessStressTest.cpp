/**
 * @file VmessStressTest.cpp
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
#include <vector>

#include <gtest/gtest.h>
#include <preview/Protocols/Vmess/Vmess.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Vmess = Preview::Vmess;

    using Address = Vmess::Address;
    using AddressType = Vmess::AddressType;
    using ClientConfig = Vmess::ClientConfig;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
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
        const auto AcceptResult = co_await Vmess::Accept(
            std::make_shared<MemoryStream>(std::move(Options.Stream)),
            Config);
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
            auto ReadWindow = std::span<std::byte>(
                Buffer.data(),
                ReadSize);
            const auto Count =
                co_await Connection->async_read_some(ReadWindow, ReadError);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            if (Options.Echo)
            {
                std::error_code WriteError;
                auto WriteWindow = std::span<const std::byte>(
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
        auto ClientResult = co_await Vmess::Connect(
            std::make_shared<MemoryStream>(std::move(State.ClientStream)),
            Config,
            Target);
        const auto HandshakeError = std::get<0>(ClientResult);
        auto Client = std::get<1>(std::move(ClientResult));
        bool ClientCompleted =
            HandshakeError == Error::None && Client != nullptr;
        if (ClientCompleted)
        {
            std::size_t Sent = 0;
            while (Sent < State.TotalBytes)
            {
                const auto WriteSize =
                    std::min(State.Payload.size(), State.TotalBytes - Sent);
                auto WriteWindow = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(State.Payload.data()),
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
                if (((Sent / State.BlockSize) & 0x0F) == 0)
                {
                    const auto PostToken = Net::use_awaitable;
                    co_await Net::post(
                        State.Executor,
                        PostToken);
                }
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
                    const auto ReadSize =
                        std::min(EchoBuffer.size(), State.TotalBytes - Received);
                    auto ReadWindow = std::span<std::byte>(
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
                    for (std::size_t Index = 0; Index < Count; ++Index)
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
                    Received += Count;
                }
                if (Received != State.TotalBytes)
                {
                    ClientCompleted = false;
                }
            }
            Client->Close();
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

    [[nodiscard]] auto MakeSessionState(
        Net::io_context &IoContext,
        MemoryStream ClientStream,
        MemoryStream ServerStream,
        std::vector<std::uint8_t> Payload,
        const std::size_t TotalBytes,
        const std::size_t BlockSize,
        const bool Echo) -> SessionState
    {
        return SessionState{
            IoContext,
            IoContext.get_executor(),
            std::move(ClientStream),
            std::move(ServerStream),
            std::move(Payload),
            TotalBytes,
            BlockSize,
            Echo};
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
                Preview::MakeMemoryPair(IoContext.get_executor());
            auto State = MakeSessionState(
                IoContext,
                std::move(ClientStream),
                std::move(ServerStream),
                Payload,
                Payload.size(),
                4096,
                true);
            if (RunSingle(std::move(State)))
            {
                ++SuccessfulRounds;
            }
        }
        EXPECT_EQ(SuccessfulRounds, Rounds);
    }

    TEST(VmessStress, Concurrent16)
    {
        constexpr std::size_t ConnectionCount = 16;
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        const auto Payload = MakePayload("concurrent-payload");
        const auto ResultChannel =
            std::make_shared<CompletionChannel>(Executor, ConnectionCount);
        std::size_t SuccessfulConnections = 0;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
            {
                auto [ClientStream, ServerStream] =
                    Preview::MakeMemoryPair(Executor);
                auto State = MakeSessionState(
                    IoContext,
                    std::move(ClientStream),
                    std::move(ServerStream),
                    Payload,
                    Payload.size(),
                    4096,
                    true);
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
            for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
            {
                const auto Completed =
                    co_await ResultChannel->async_receive(Net::use_awaitable);
                if (Completed)
                {
                    ++SuccessfulConnections;
                }
            }
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        EXPECT_EQ(SuccessfulConnections, ConnectionCount);
    }

    TEST(VmessStress, Transfer2MB)
    {
        constexpr std::size_t TotalBytes = 2 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        const std::vector<std::uint8_t> Payload(
            BlockSize,
            0xAB);
        auto State = MakeSessionState(
            IoContext,
            std::move(ClientStream),
            std::move(ServerStream),
            Payload,
            TotalBytes,
            BlockSize,
            false);
        EXPECT_TRUE(RunSingle(std::move(State)));
    }
} // namespace
