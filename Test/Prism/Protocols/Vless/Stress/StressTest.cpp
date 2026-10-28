/**
 * @file StressTest.cpp
 * @brief VLESS 协议会话压力测试（达标标准 C2）
 * @details 覆盖 200 次独立握手回环、16 并发连接和 2 MiB 分块传输；
 *          客户端使用真实 VLESS request/response wire，所有协程都有完成通知。
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
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Vless = Prism::Vless;

    using Address = Vless::Address;
    using AddressType = Vless::AddressType;
    using Command = Vless::Command;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Prism::MemoryStream;
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

    struct SessionRequest final
    {
        Net::io_context &IoContext;
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

    [[nodiscard]] auto TestUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x10 + Index);
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

    [[nodiscard]] auto BuildRawRequest(
        const std::array<std::uint8_t, Vless::UuidLen> &Uuid,
        const Command CommandValue,
        const Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire;
        Wire.push_back(Vless::ProtocolVersion);
        Wire.insert(Wire.end(), Uuid.begin(), Uuid.end());
        Wire.push_back(0x00);
        Wire.push_back(static_cast<std::uint8_t>(CommandValue));
        Wire.push_back(static_cast<std::uint8_t>(Target.Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Target.Port & 0xFF));
        Wire.push_back(static_cast<std::uint8_t>(Target.Type));
        if (Target.Type == AddressType::Domain)
        {
            Wire.push_back(static_cast<std::uint8_t>(Target.Host.size()));
            Wire.insert(Wire.end(), Target.Host.begin(), Target.Host.end());
        }
        else if (Target.Type == AddressType::Ipv4)
        {
            const auto AddressValue = Net::ip::make_address_v4(Target.Host);
            const auto Bytes = AddressValue.to_bytes();
            Wire.insert(Wire.end(), Bytes.begin(), Bytes.end());
        }
        else
        {
            const auto AddressValue = Net::ip::make_address_v6(Target.Host);
            const auto Bytes = AddressValue.to_bytes();
            Wire.insert(Wire.end(), Bytes.begin(), Bytes.end());
        }
        return Wire;
    }

    auto RunServer(ServerOptions Options) -> Net::awaitable<void>
    {
        Vless::ServerConfig Config;
        Config.uuid = TestUuid();
        const auto AcceptResult = co_await Vless::Accept(
            std::make_shared<MemoryStream>(std::move(Options.Stream)),
            Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection)
        {
            (void)Options.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }
        const auto &Connection = AcceptResult->Connection;

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
            const auto Read = co_await Connection->ReadSome(ReadWindow);
            ReadError = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
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
                const auto Write = co_await Connection->WriteSome(WriteWindow);
                WriteError = Prism::Fault::ToNative(Write.Failure);
                const auto Written = Write.Bytes;
                if (WriteError || Written != Count)
                {
                    break;
                }
            }
            Received += Count;
        }
        (void)Connection->Close();
        const bool Completed = Received == Options.TotalBytes;
        (void)Options.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    [[nodiscard]] auto SendHandshake(SessionState &State) -> Net::awaitable<bool>
    {
        const auto Target = MakeAddress(
            AddressType::Domain,
            "example.com",
            443);
        const auto Header = BuildRawRequest(
            TestUuid(),
            Command::Tcp,
            Target);
        std::error_code WriteError;
        auto HeaderBytes = std::span<const std::uint8_t>(Header);
        auto HeaderBuffer = Prism::AsBytes(HeaderBytes);
        const auto HeaderWrite = co_await State.ClientStream.WriteSome(HeaderBuffer);
        WriteError = Prism::Fault::ToNative(HeaderWrite.Failure);
        const auto HeaderWritten = HeaderWrite.Bytes;
        bool ClientCompleted =
            !WriteError && HeaderWritten == Header.size();

        std::array<std::uint8_t, 2> Response{};
        std::size_t ResponseSize = 0;
        while (ClientCompleted && ResponseSize < Response.size())
        {
            auto ResponseBytes = std::span<std::uint8_t>(Response).subspan(ResponseSize);
            auto ResponseBuffer = Prism::AsBytes(ResponseBytes);
            const auto Read = co_await State.ClientStream.ReadSome(ResponseBuffer);
            WriteError = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (WriteError || Count == 0 || Count > ResponseBytes.size())
            {
                ClientCompleted = false;
                break;
            }
            ResponseSize += Count;
        }
        if (ClientCompleted &&
            (ResponseSize != Response.size() ||
             Response[0] != Vless::ProtocolVersion))
        {
            ClientCompleted = false;
        }
        co_return ClientCompleted;
    }

    [[nodiscard]] auto SendPayload(SessionState &State) -> Net::awaitable<bool>
    {
        bool ClientCompleted = true;
        std::error_code WriteError;
        std::size_t Sent = 0;
        while (ClientCompleted && Sent < State.TotalBytes)
        {
            const auto WriteSize =
                std::min(State.Payload.size(), State.TotalBytes - Sent);
            auto PayloadBytes = std::span<const std::uint8_t>(
                State.Payload.data(),
                WriteSize);
            auto PayloadBuffer = Prism::AsBytes(PayloadBytes);
            const auto Write = co_await State.ClientStream.WriteSome(PayloadBuffer);
            WriteError = Prism::Fault::ToNative(Write.Failure);
            const auto Written = Write.Bytes;
            if (WriteError || Written == 0 || Written > WriteSize)
            {
                ClientCompleted = false;
                break;
            }
            Sent += Written;
            if (((Sent / State.BlockSize) & 0x0F) == 0)
            {
                const auto PostToken = Net::use_awaitable;
                co_await Net::post(State.Executor, PostToken);
            }
        }
        if (Sent != State.TotalBytes)
        {
            ClientCompleted = false;
        }
        co_return ClientCompleted;
    }

    [[nodiscard]] auto ReceiveAndVerifyEcho(SessionState &State) -> Net::awaitable<bool>
    {
        bool ClientCompleted = true;
        std::vector<std::byte> EchoBuffer(State.BlockSize);
        std::error_code ReadError;
        std::size_t Received = 0;
        while (Received < State.TotalBytes)
        {
            const auto ReadSize = std::min(EchoBuffer.size(), State.TotalBytes - Received);
            const auto ReadWindow = std::span<std::byte>(EchoBuffer.data(), ReadSize);
            const auto Read = co_await State.ClientStream.ReadSome(ReadWindow);
            ReadError = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                ClientCompleted = false;
                break;
            }
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                const auto Expected = State.Payload[(Received + Index) % State.Payload.size()];
                if (EchoBuffer[Index] != static_cast<std::byte>(Expected))
                {
                    ClientCompleted = false;
                    break;
                }
            }
            if (!ClientCompleted) break;
            Received += Count;
        }
        if (Received != State.TotalBytes) ClientCompleted = false;
        co_return ClientCompleted;
    }

    [[nodiscard]] auto RunSession(SessionState State) -> Net::awaitable<bool>
    {
        const auto Completion = std::make_shared<CompletionChannel>(State.Executor, 1);
        ServerOptions ServerState{
            State.Executor, std::move(State.ServerStream), State.TotalBytes,
            State.BlockSize, State.Echo, Completion};
        auto ServerCompletion = [Completion](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                (void)Completion->try_send(boost::system::error_code{}, false);
            }
        };
        Net::co_spawn(State.Executor, RunServer(std::move(ServerState)), std::move(ServerCompletion));

        bool ClientCompleted = co_await SendHandshake(State);
        if (ClientCompleted) ClientCompleted = co_await SendPayload(State);
        if (ClientCompleted && State.Echo)
        {
            ClientCompleted = co_await ReceiveAndVerifyEcho(State);
        }

        (void)State.ClientStream.Close();
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

    struct ConcurrentSessionState final
    {
        std::shared_ptr<CompletionChannel> ResultChannel;
        std::size_t SuccessfulConnections{0};
    };

    struct ConcurrentSessionRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<ConcurrentSessionState> State;
        std::vector<std::uint8_t> Payload;
    };

    [[nodiscard]] auto MakeSessionState(SessionRequest Request) -> SessionState;

    struct SessionCompletionHandler final
    {
        std::shared_ptr<CompletionChannel> ResultChannel;

        auto operator()(std::exception_ptr Exception) const -> void
        {
            if (Exception)
            {
                (void)ResultChannel->try_send(boost::system::error_code{}, false);
            }
        }
    };

    auto RunConcurrentSessions(ConcurrentSessionRequest Request) -> Net::awaitable<void>
    {
        constexpr std::size_t ConnectionCount = 16;
        const auto Executor = Request.IoContext.get_executor();
        std::size_t SuccessfulConnections = 0;
        for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
        {
            auto [ClientStream, ServerStream] = Prism::MakeMemoryPair(Executor);
            auto State = MakeSessionState(SessionRequest{
                Request.IoContext, std::move(ClientStream), std::move(ServerStream),
                Request.Payload, Request.Payload.size(), 4096, true});
            const auto Completion = SessionCompletionHandler{Request.State->ResultChannel};
            Net::co_spawn(
                Executor,
                RunSessionAndReport(std::move(State), Request.State->ResultChannel),
                Completion);
        }
        for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
        {
            const auto Completed = co_await Request.State->ResultChannel->async_receive(
                Net::use_awaitable);
            if (Completed)
            {
                ++SuccessfulConnections;
            }
        }
        Request.State->SuccessfulConnections = SuccessfulConnections;
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

    [[nodiscard]] auto MakePayload(std::string_view Text)
        -> std::vector<std::uint8_t>
    {
        return {
            reinterpret_cast<const std::uint8_t *>(Text.data()),
            reinterpret_cast<const std::uint8_t *>(Text.data()) + Text.size()};
    }

    [[nodiscard]] auto MakeSessionState(SessionRequest Request) -> SessionState
    {
        return SessionState{
            Request.IoContext,
            Request.IoContext.get_executor(),
            std::move(Request.ClientStream),
            std::move(Request.ServerStream),
            std::move(Request.Payload),
            Request.TotalBytes,
            Request.BlockSize,
            Request.Echo};
    }

    TEST(VlessStress, ConnectLoopNoLeak)
    {
        constexpr int Rounds = 200;
        const auto Payload = MakePayload("stress-payload");
        int SuccessfulRounds = 0;
        for (int Round = 0; Round < Rounds; ++Round)
        {
            Net::io_context IoContext;
            auto [ClientStream, ServerStream] =
                Prism::MakeMemoryPair(IoContext.get_executor());
            auto State = MakeSessionState(SessionRequest{
                IoContext, std::move(ClientStream), std::move(ServerStream),
                Payload, Payload.size(), 4096, true});
            if (RunSingle(std::move(State)))
            {
                ++SuccessfulRounds;
            }
        }
        EXPECT_EQ(SuccessfulRounds, Rounds);
    }

    TEST(VlessStress, Concurrent16)
    {
        constexpr std::size_t ConnectionCount = 16;
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        const auto Payload = MakePayload("concurrent-payload");
        auto State = std::make_shared<ConcurrentSessionState>();
        State->ResultChannel = std::make_shared<CompletionChannel>(Executor, ConnectionCount);
        RunCoroutine(IoContext, RunConcurrentSessions(
            ConcurrentSessionRequest{IoContext, State, Payload}));
        EXPECT_EQ(State->SuccessfulConnections, ConnectionCount);
    }

    TEST(VlessStress, Transfer2MB)
    {
        constexpr std::size_t TotalBytes = 2 * 1024 * 1024;
        constexpr std::size_t BlockSize = 64 * 1024;
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] =
            Prism::MakeMemoryPair(IoContext.get_executor());
        const std::vector<std::uint8_t> Payload(BlockSize, 0xAB);
        auto State = MakeSessionState(SessionRequest{
            IoContext, std::move(ClientStream), std::move(ServerStream),
            Payload, TotalBytes, BlockSize, false});
        EXPECT_TRUE(RunSingle(std::move(State)));
    }
} // namespace
