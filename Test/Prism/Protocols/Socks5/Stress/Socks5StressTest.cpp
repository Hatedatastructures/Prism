/**
 * @file Socks5StressTest.cpp
 * @brief SOCKS5 会话压力测试。
 * @details 覆盖 300 次连接、32 路并发和 4MB 分块传输，并等待所有 owning task。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Prism::AsBytes;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct EagerTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        std::shared_ptr<std::atomic<bool>> Completed;
    };

    /** @brief 立即启动 owning stress operation 并记录 completion。 */
    auto SpawnEager(Net::any_io_executor Executor,
                    Net::awaitable<void> Operation) -> EagerTask
    {
        EagerTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>(),
            std::make_shared<std::atomic<bool>>(false)};
        Net::co_spawn(
            Executor,
            std::move(Operation),
            [State](std::exception_ptr ErrorValue)
            {
                *State.Failure = ErrorValue;
                State.Completed->store(true);
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    /** @brief 等待 owning operation 的真实完成并传播异常。 */
    auto WaitEager(EagerTask State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    /** @brief 关闭双方载体并等待全部真实 I/O drain。 */
    auto CloseAndDrainPair(
        std::shared_ptr<MemoryStream> Client,
        std::shared_ptr<MemoryStream> Server) -> Net::awaitable<void>
    {
        const auto ClientClose = Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = Server->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
    }

    template <typename Awaitable>
    auto RunCoro(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /** @brief 服务端完成 SOCKS5 Accept 并回显任意分块。 */
    auto RunEchoServer(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Conn] =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_TRUE(Conn);
        if (!Conn)
        {
            co_return;
        }
        EXPECT_EQ(Request.Target.Host, "example.com");
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            const auto Read = co_await Conn->ReadSome(Buffer);
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            const auto Written = co_await Conn->WriteExact(
                std::span<const std::byte>(Buffer.data(), Read.Bytes));
            if (Written.Failure.Failed() || Written.Bytes != Read.Bytes)
            {
                break;
            }
        }
        const auto Close = Conn->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Conn->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    struct RoundtripRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::string Payload;
        std::shared_ptr<bool> Success;
    };

    /** @brief 运行一次原始 wire 握手和完整回显。 */
    auto RunLoopRoundtrip(RoundtripRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEager(Request.Server->Executor(),
                                     RunEchoServer(Request.Server));
        std::exception_ptr ParentFailure;
        try
        {
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            const std::string Host = "example.com";
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                     static_cast<std::uint8_t>(Host.size())});
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(0x01);
            Wire.push_back(0xBB);
            Wire.insert(Wire.end(), Request.Payload.begin(), Request.Payload.end());
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Wire.size());
            const auto Shutdown = co_await Request.Client->WriteShutdown();
            EXPECT_TRUE(Shutdown);
            if (!Write.Failure.Failed() && Shutdown)
            {
                std::array<std::uint8_t, 12> Response{};
                std::size_t Received = 0;
                while (Received < Response.size())
                {
                    const auto Read = co_await Request.Client->ReadSome(
                        AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
                    if (Read.Failure.Failed() || Read.Bytes == 0)
                    {
                        break;
                    }
                    Received += Read.Bytes;
                }
                if (Received == Response.size() &&
                    Response[0] == Socks5::Version)
                {
                    std::array<std::byte, 4096> Echo{};
                    Received = 0;
                    while (Received < Request.Payload.size())
                    {
                        const auto Read = co_await Request.Client->ReadSome(
                            std::span<std::byte>(Echo.data() + Received,
                                                 Echo.size() - Received));
                        if (Read.Failure.Failed() || Read.Bytes == 0)
                        {
                            break;
                        }
                        Received += Read.Bytes;
                    }
                    *Request.Success = Received == Request.Payload.size();
                }
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await WaitEager(std::move(ServerTask));
        co_await CloseAndDrainPair(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 运行循环压力场景的一次 owning client/server pair。 */
    auto RunOneRound(Net::io_context &IoContext, const std::string &Payload)
        -> bool
    {
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Success = std::make_shared<bool>(false);
        RunCoro(IoContext, RunLoopRoundtrip(
                               RoundtripRequest{Client, Server, Payload, Success}));
        return *Success;
    }

    /** @brief 并发服务端完成单次短回显。 */
    auto RunConcurrentServer(std::shared_ptr<MemoryStream> Server,
                             std::string Payload) -> Net::awaitable<void>
    {
        auto [ErrorValue, Request, Conn] =
            co_await Socks5::Accept(Server, Socks5::ServerConfig{});
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_TRUE(Conn);
        (void)Request;
        if (!Conn)
        {
            co_return;
        }
        std::array<std::byte, 128> Buffer{};
        const auto Read = co_await Conn->ReadExact(
            std::span<std::byte>(Buffer.data(), Payload.size()));
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, Payload.size());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes),
                  Payload);
        const auto Written = co_await Conn->WriteExact(
            std::span<const std::byte>(Buffer.data(), Read.Bytes));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Read.Bytes);
        const auto Close = Conn->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Conn->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    struct ConcurrentClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::string Payload;
        std::shared_ptr<std::atomic<int>> Success;
    };

    /** @brief 并发客户端完成一次 raw wire 握手和回显。 */
    auto RunConcurrentClient(ConcurrentClientRequest Request)
        -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
        const std::string Host = "example.com";
        Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                 static_cast<std::uint8_t>(Host.size())});
        Wire.insert(Wire.end(), Host.begin(), Host.end());
        Wire.push_back(0x01);
        Wire.push_back(0xBB);
        Wire.insert(Wire.end(), Request.Payload.begin(), Request.Payload.end());
        const auto Write = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        if (Write.Failure.Failed() || Write.Bytes != Wire.size() || !Shutdown)
        {
            co_return;
        }
        std::array<std::uint8_t, 12> Response{};
        std::size_t Received = 0;
        while (Received < Response.size())
        {
            const auto Read = co_await Request.Client->ReadSome(
                AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            Received += Read.Bytes;
        }
        if (Received != Response.size())
        {
            co_return;
        }
        std::array<std::byte, 128> Echo{};
        Received = 0;
        while (Received < Request.Payload.size())
        {
            const auto Read = co_await Request.Client->ReadSome(
                std::span<std::byte>(Echo.data() + Received,
                                     Echo.size() - Received));
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            Received += Read.Bytes;
        }
        if (Received == Request.Payload.size())
        {
            Request.Success->fetch_add(1);
        }
    }

    struct ConcurrentTask final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        EagerTask ServerTask;
        EagerTask ClientTask;
    };

    struct ConcurrentRunRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<std::atomic<int>> Success;
        std::string Payload;
    };

    /** @brief 运行 32 路并发并在 10 秒预算内回收全部 task。 */
    auto RunConcurrent32(ConcurrentRunRequest Request) -> Net::awaitable<void>
    {
        std::vector<ConcurrentTask> Tasks;
        Tasks.reserve(32);
        for (int Index = 0; Index < 32; ++Index)
        {
            auto [ClientMemory, ServerMemory] =
                MakeMemoryPair(Request.IoContext.get_executor());
            auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
            auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
            auto ServerTask = SpawnEager(
                Server->Executor(), RunConcurrentServer(Server, Request.Payload));
            auto ClientTask = SpawnEager(
                Client->Executor(), RunConcurrentClient(
                    ConcurrentClientRequest{Client, Request.Payload, Request.Success}));
            Tasks.push_back(ConcurrentTask{
                std::move(Client), std::move(Server),
                std::move(ServerTask), std::move(ClientTask)});
        }

        Net::steady_timer Timer(Request.IoContext);
        const auto Deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (Request.Success->load() < 32 &&
               std::chrono::steady_clock::now() < Deadline)
        {
            Timer.expires_after(std::chrono::milliseconds(1));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        EXPECT_EQ(Request.Success->load(), 32);
        for (auto &Task : Tasks)
        {
            co_await WaitEager(std::move(Task.ClientTask));
            co_await WaitEager(std::move(Task.ServerTask));
            co_await CloseAndDrainPair(Task.Client, Task.Server);
        }
    }

    struct TransferState final
    {
        std::atomic<std::size_t> ReceivedBytes{0};
        std::atomic<bool> ClientWriteShutdown{false};
        std::atomic<bool> ServerReadEof{false};
        std::atomic<bool> ServerReadError{false};
    };

    struct TransferRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::size_t Total;
        std::size_t Chunk;
        std::shared_ptr<TransferState> State;
    };

    struct TransferServerRequest final
    {
        std::shared_ptr<MemoryStream> Server;
        std::size_t Total;
        std::size_t Chunk;
        std::shared_ptr<TransferState> State;
    };

    /** @brief 服务端接收 4MB 并发布真实字节计数。 */
    auto RunTransferServer(TransferServerRequest Transfer)
        -> Net::awaitable<void>
    {
        auto [ErrorValue, HandshakeRequest, Conn] =
            co_await Socks5::Accept(Transfer.Server, Socks5::ServerConfig{});
        EXPECT_EQ(ErrorValue, Error::None);
        EXPECT_TRUE(Conn);
        (void)HandshakeRequest;
        if (!Conn)
        {
            co_return;
        }
        std::vector<std::byte> Buffer(Transfer.Chunk);
        std::size_t ReceivedTotal = 0;
        bool ReadEof = false;
        bool ReadError = false;
        while (true)
        {
            const auto Read = co_await Conn->ReadSome(Buffer);
            ReceivedTotal += Read.Bytes;
            if (Read.Failure.Failed())
            {
                ReadEof = Read.Failure.Code == Prism::Fault::Code::Eof;
                ReadError = !ReadEof;
                break;
            }
            if (ReceivedTotal > Transfer.Total)
            {
                ReadError = true;
                break;
            }
            if (Read.Bytes == 0)
            {
                ReadError = true;
                break;
            }
        }
        Transfer.State->ReceivedBytes.store(ReceivedTotal);
        Transfer.State->ServerReadEof.store(ReadEof);
        Transfer.State->ServerReadError.store(ReadError);
        const auto Close = Conn->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Conn->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    /** @brief 驱动 4MB 分块发送并等待 server completion。 */
    auto RunTransfer4Mb(TransferRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEager(
            Request.Server->Executor(), RunTransferServer(
                TransferServerRequest{Request.Server, Request.Total,
                                      Request.Chunk, Request.State}));
        std::exception_ptr ParentFailure;
        try
        {
            std::vector<std::uint8_t> Wire{0x05, 0x01, 0x00};
            const std::string Host = "example.com";
            Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                     static_cast<std::uint8_t>(Host.size())});
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(0x01);
            Wire.push_back(0xBB);
            const auto HandshakeWrite = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Wire)));
            EXPECT_EQ(HandshakeWrite.Bytes, Wire.size());
            EXPECT_FALSE(HandshakeWrite.Failure.Failed());
            std::array<std::uint8_t, 12> Response{};
            std::size_t Received = 0;
            while (Received < Response.size())
            {
                const auto Read = co_await Request.Client->ReadSome(
                    AsBytes(std::span<std::uint8_t>(Response).subspan(Received)));
                Received += Read.Bytes;
                if (Read.Failure.Failed() || Read.Bytes == 0)
                {
                    break;
                }
            }
            std::vector<std::byte> ChunkBuffer(Request.Chunk, std::byte{0xAB});
            for (std::size_t Sent = 0; Sent < Request.Total; Sent += Request.Chunk)
            {
                const auto Write = co_await Request.Client->WriteExact(
                    std::span<const std::byte>(ChunkBuffer));
                if (Write.Failure.Failed() || Write.Bytes != ChunkBuffer.size())
                {
                    break;
                }
            }
            const auto Shutdown = co_await Request.Client->WriteShutdown();
            Request.State->ClientWriteShutdown.store(static_cast<bool>(Shutdown));
            EXPECT_TRUE(Shutdown);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }

        Net::steady_timer Timer(Request.IoContext);
        const auto Deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!ServerTask.Completed->load() &&
               std::chrono::steady_clock::now() < Deadline)
        {
            Timer.expires_after(std::chrono::milliseconds(1));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        EXPECT_TRUE(ServerTask.Completed->load());
        if (!ServerTask.Completed->load())
        {
            const auto ClientClose = Request.Client->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = Request.Server->Close();
            EXPECT_TRUE(ServerClose);
        }
        co_await WaitEager(std::move(ServerTask));
        co_await CloseAndDrainPair(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    TEST(Socks5Stress, ConnectLoopNoLeak)
    {
        constexpr int Rounds = 300;
        const std::string Payload = "stress-payload";
        int OkCount = 0;
        for (int Index = 0; Index < Rounds; ++Index)
        {
            Net::io_context IoContext;
            if (RunOneRound(IoContext, Payload))
            {
                ++OkCount;
            }
        }
        EXPECT_EQ(OkCount, Rounds);
    }

    TEST(Socks5Stress, Concurrent32)
    {
        Net::io_context IoContext;
        auto Success = std::make_shared<std::atomic<int>>(0);
        RunCoro(IoContext, RunConcurrent32(
                               ConcurrentRunRequest{IoContext, Success,
                                                    "concurrent-payload"}));
        EXPECT_EQ(Success->load(), 32);
    }

    TEST(Socks5Stress, Transfer4MB)
    {
        Net::io_context IoContext;
        constexpr std::size_t Total = 4 * 1024 * 1024;
        constexpr std::size_t Chunk = 64 * 1024;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto State = std::make_shared<TransferState>();
        RunCoro(IoContext, RunTransfer4Mb(
                               TransferRequest{IoContext, Client, Server, Total,
                                               Chunk, State}));
        EXPECT_EQ(State->ReceivedBytes.load(), Total);
        EXPECT_TRUE(State->ClientWriteShutdown.load());
        EXPECT_TRUE(State->ServerReadEof.load());
        EXPECT_FALSE(State->ServerReadError.load());
    }
}
