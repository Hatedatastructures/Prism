/**
 * @file VmessMultiThread.cpp
 * @brief VMess 多线程并行测试（Release）
 * @details 对比单线程、双线程和四线程驱动同一个 io_context，确认数据面
 *          在不同调度并发度下都能完整传输。
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <thread>
#include <tuple>
#include <vector>

#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace Net = boost::asio;

namespace
{
    using Clock = std::chrono::steady_clock;
    using Error = Preview::Error;
    using Reliable = Preview::Transport::Reliable;
    using VmessAddress = Preview::Vmess::Address;
    using VmessAddressType = Preview::Vmess::AddressType;
    using VmessClientConfig = Preview::Vmess::ClientConfig;
    using VmessServerConfig = Preview::Vmess::ServerConfig;
    using ExecutorType = Net::any_io_executor;
    using ServerDoneChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using ServerExitedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;
    using ClientExitedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct BenchResources
    {
        std::atomic<std::shared_ptr<Net::ip::tcp::socket>> ServerSocket;
        std::atomic<Preview::SharedTransmission> ServerTransport;
        std::atomic<Preview::SharedTransmission> ServerConnection;
    };

    struct BenchState
    {
        ExecutorType Executor;
        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        Net::io_context *IoContext{nullptr};
        std::size_t Total;
        std::size_t Block;
        std::array<std::uint8_t, 16> Uuid;
        std::shared_ptr<std::atomic_bool> Completed;
        std::shared_ptr<ServerDoneChannel> ServerDone;
        std::shared_ptr<ServerExitedChannel> ServerExited;
        std::shared_ptr<ClientExitedChannel> ClientExited;
        std::shared_ptr<BenchResources> Resources;
        std::shared_ptr<std::atomic_bool> ServerReported;
        std::shared_ptr<std::atomic_bool> ClientFinished;
        std::shared_ptr<std::atomic_bool> TimedOut;
    };

    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    auto CloseBenchResources(const BenchState &State) -> void
    {
        if (!State.Resources)
        {
            return;
        }
        const auto ServerConnection =
            State.Resources->ServerConnection.load(std::memory_order_acquire);
        const auto ServerTransport =
            State.Resources->ServerTransport.load(std::memory_order_acquire);
        const auto ServerSocket =
            State.Resources->ServerSocket.load(std::memory_order_acquire);
        if (ServerConnection)
        {
            ServerConnection->Cancel();
            ServerConnection->Close();
        }
        if (ServerTransport)
        {
            ServerTransport->Cancel();
            ServerTransport->Close();
        }
        if (ServerSocket)
        {
            boost::system::error_code ErrorCode;
            ServerSocket->cancel(ErrorCode);
            ServerSocket->close(ErrorCode);
        }
        if (State.Acceptor)
        {
            boost::system::error_code ErrorCode;
            State.Acceptor->cancel(ErrorCode);
            State.Acceptor->close(ErrorCode);
        }
    }

    auto SignalServer(BenchState State, const bool Completed) -> void
    {
        if (State.ServerReported->exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        (void)State.ServerDone->try_send(boost::system::error_code{}, Completed);
    }

    [[nodiscard]] auto WaitForServer(BenchState State) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(State.Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        auto DoneRace = co_await (State.ServerDone->async_receive(Net::use_awaitable) ||
                                  Watchdog.async_wait(Net::use_awaitable));
        if (DoneRace.index() != 0U)
        {
            CloseBenchResources(State);
            co_return false;
        }

        const auto Completed = std::get<0>(DoneRace);
        Watchdog.expires_after(std::chrono::seconds(1));
        auto ExitRace = co_await (State.ServerExited->async_receive(Net::use_awaitable) ||
                                  Watchdog.async_wait(Net::use_awaitable));
        if (ExitRace.index() != 0U)
        {
            CloseBenchResources(State);
            co_return false;
        }
        co_return Completed;
    }

    auto RunServer(BenchState State) -> Net::awaitable<void>
    {
        auto Socket = std::make_shared<Net::ip::tcp::socket>(State.Executor);
        State.Resources->ServerSocket.store(Socket, std::memory_order_release);
        boost::system::error_code AcceptError;
        auto AcceptToken =
            Net::redirect_error(Net::use_awaitable, AcceptError);
        co_await State.Acceptor->async_accept(*Socket, AcceptToken);
        if (AcceptError)
        {
            SignalServer(State, false);
            co_return;
        }

        auto Stream = std::make_shared<Reliable>(std::move(*Socket));
        Preview::SharedTransmission SharedStream = Stream;
        State.Resources->ServerTransport.store(std::move(SharedStream),
                                               std::memory_order_release);
        VmessServerConfig ServerConfig;
        ServerConfig.uuid = State.Uuid;
        auto AcceptResult = co_await Preview::Vmess::Accept(
            std::move(Stream), ServerConfig);
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        if (HandshakeError != Error::None || !Connection)
        {
            SignalServer(State, false);
            CloseBenchResources(State);
            co_return;
        }
        Preview::SharedTransmission SharedConnection = Connection;
        State.Resources->ServerConnection.store(std::move(SharedConnection),
                                                std::memory_order_release);

        std::vector<std::uint8_t> Buffer(State.Block);
        std::error_code ReadError;
        std::size_t Done = 0;
        while (Done < State.Total)
        {
            const auto ReadSize = std::min(Buffer.size(), State.Total - Done);
            auto ReadWindow = std::span<std::byte>(
                reinterpret_cast<std::byte *>(Buffer.data()), ReadSize);
            const auto Count =
                co_await Connection->async_read_some(ReadWindow, ReadError);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            Done += Count;
        }

        Connection->Close();
        State.Resources->ServerConnection.store(Preview::SharedTransmission{},
                                                std::memory_order_release);
        CloseBenchResources(State);
        const bool Completed = Done == State.Total;
        State.Completed->store(Completed, std::memory_order_release);
        SignalServer(State, Completed);
    }

    auto RunClient(
        BenchState State,
        const std::uint16_t Port) -> Net::awaitable<void>
    {
        auto ServerCompletion =
            [ServerDone = State.ServerDone,
             ServerExited = State.ServerExited,
             State](std::exception_ptr Exception)
            -> void
        {
            if (Exception)
            {
                SignalServer(State, false);
            }
            (void)ServerExited->try_send(boost::system::error_code{});
        };
        Net::co_spawn(
            State.Executor,
            RunServer(State),
            std::move(ServerCompletion));

        auto Stream = std::make_shared<Reliable>(State.Executor);
        const auto Endpoint = Net::ip::tcp::endpoint(
            Net::ip::address_v4::loopback(), Port);
        const auto ConnectError = co_await Stream->Connect(Endpoint);
        if (ConnectError)
        {
            CloseBenchResources(State);
            (void)co_await WaitForServer(State);
            co_return;
        }

        VmessClientConfig ClientConfig;
        ClientConfig.uuid = State.Uuid;
        const auto Target = VmessAddress{
            VmessAddressType::Domain,
            "t.internal",
            443};
        auto ConnectResult = co_await Preview::Vmess::Connect(
            std::move(Stream), ClientConfig, Target);
        const auto HandshakeError = std::get<0>(ConnectResult);
        auto Connection = std::get<1>(std::move(ConnectResult));
        if (HandshakeError != Error::None || !Connection)
        {
            CloseBenchResources(State);
            const auto ServerCompleted = co_await WaitForServer(State);
            State.Completed->store(
                ServerCompleted, std::memory_order_release);
            co_return;
        }

        const std::vector<std::uint8_t> Chunk(State.Block, 0x5A);
        std::error_code WriteError;
        std::size_t Done = 0;
        while (Done < State.Total)
        {
            const auto WriteSize =
                std::min(Chunk.size(), State.Total - Done);
            auto WriteWindow = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Chunk.data()),
                WriteSize);
            const auto Count = co_await Connection->async_write_some(
                WriteWindow, WriteError);
            if (WriteError || Count == 0 || Count > WriteSize)
            {
                State.Completed->store(false, std::memory_order_release);
                break;
            }
            Done += Count;
        }

        Connection->Close();
        const auto ServerCompleted = co_await WaitForServer(State);
        State.Completed->store(
            Done == State.Total && ServerCompleted,
            std::memory_order_release);
    }

    [[nodiscard]] auto Bench(
        const std::size_t Total,
        const std::size_t Block,
        const int ThreadCount) -> std::int64_t
    {
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        auto Acceptor = std::make_shared<Net::ip::tcp::acceptor>(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor->local_endpoint().port();
        const auto Uuid = std::array<std::uint8_t, 16>{
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0x00};
        const auto Completed = std::make_shared<std::atomic_bool>(false);
        const auto ServerDone =
            std::make_shared<ServerDoneChannel>(Executor, 1);
        const auto ServerExited =
            std::make_shared<ServerExitedChannel>(Executor, 1);
        const auto ClientExited =
            std::make_shared<ClientExitedChannel>(Executor, 1);
        BenchState State{
            Executor,
            Acceptor,
            &IoContext,
            Total,
            Block,
            Uuid,
            Completed,
            ServerDone,
            ServerExited,
            ClientExited};
        State.Resources = std::make_shared<BenchResources>();
        State.ServerReported = std::make_shared<std::atomic_bool>(false);
        State.ClientFinished = std::make_shared<std::atomic_bool>(false);
        State.TimedOut = std::make_shared<std::atomic_bool>(false);
        const auto Start = NowNs();
        auto ClientCompletion =
            [State](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                State.Completed->store(false, std::memory_order_release);
            }
            State.ClientFinished->store(true, std::memory_order_release);
            (void)State.ClientExited->try_send(boost::system::error_code{});
        };

        auto WatchdogCoroutine = [State]() -> Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator||;
            Net::steady_timer Timer(State.Executor);
            Timer.expires_after(std::chrono::seconds(30));
            auto Race = co_await (State.ClientExited->async_receive(Net::use_awaitable) ||
                                  Timer.async_wait(Net::use_awaitable));
            if (Race.index() == 0U ||
                State.ClientFinished->load(std::memory_order_acquire))
            {
                co_return;
            }
            State.TimedOut->store(true, std::memory_order_release);
            CloseBenchResources(State);
            Net::steady_timer Grace(State.Executor);
            Grace.expires_after(std::chrono::seconds(1));
            boost::system::error_code ErrorCode;
            co_await Grace.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!State.ClientFinished->load(std::memory_order_acquire) && State.IoContext)
            {
                State.IoContext->stop();
            }
        };
        auto WatchdogCompletion = [](std::exception_ptr) -> void {};
        Net::co_spawn(Executor, std::move(WatchdogCoroutine),
                      std::move(WatchdogCompletion));
        Net::co_spawn(
            Executor,
            RunClient(State, Port),
            std::move(ClientCompletion));

        std::vector<std::thread> WorkerThreads;
        WorkerThreads.reserve(
            static_cast<std::size_t>(std::max(ThreadCount, 1)));
        for (int ThreadIndex = 0;
             ThreadIndex < ThreadCount;
             ++ThreadIndex)
        {
            WorkerThreads.emplace_back([&IoContext]() -> void
            {
                IoContext.run();
            });
        }
        for (auto &WorkerThread : WorkerThreads)
        {
            WorkerThread.join();
        }
        if (!State.ClientFinished->load(std::memory_order_acquire))
        {
            CloseBenchResources(State);
        }
        if (!Completed->load(std::memory_order_acquire))
        {
            return 0;
        }
        return NowNs() - Start;
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t Total = 256ULL * 1024 * 1024;

    for (const auto Block : {16384UL, 65535UL})
    {
        for (const auto ThreadCount : {1, 2, 4})
        {
            std::array<std::int64_t, 3> Samples{};
            for (std::size_t SampleIndex = 0;
                 SampleIndex < Samples.size();
                 ++SampleIndex)
            {
                Samples[SampleIndex] =
                    Bench(Total, Block, ThreadCount);
            }
            std::sort(Samples.begin(), Samples.end());
            const auto MedianNs = Samples[1];
            if (MedianNs <= 0)
            {
                std::printf(
                    "FAIL vmess chunk=%zu 线程=%d: 数据面未完成运行\n",
                    Block,
                    ThreadCount);
                return 1;
            }
            const double MegabytesPerSecond =
                (Total / 1024.0 / 1024.0) /
                (static_cast<double>(MedianNs) / 1e9);
            std::printf(
                "vmess chunk=%6zu 线程=%d: med=%7.2f ms  => %8.1f MB/s\n",
                Block,
                ThreadCount,
                static_cast<double>(MedianNs) / 1e6,
                MegabytesPerSecond);
            if (MegabytesPerSecond < 50.0)
            {
                std::printf(
                    "FAIL vmess chunk=%zu 线程=%d: 吞吐低于门槛\n",
                    Block,
                    ThreadCount);
                return 1;
            }
        }
    }
    std::printf("VmessMultiThread: ALL PASS\n");
    return 0;
}
