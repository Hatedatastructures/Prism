/**
 * @file VmessMultiThread.cpp
 * @brief VMess 多线程并行测试（Release）
 * @details 对比单线程、双线程和四线程驱动同一个 io_context，确认数据面
 *          在不同调度并发度下都能完整传输。
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
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

#include <preview/Protocols/Vmess/Vmess.hpp>
#include <preview/Transport/Reliable.hpp>

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

    struct BenchState
    {
        ExecutorType Executor;
        Net::ip::tcp::acceptor &Acceptor;
        std::size_t Total;
        std::size_t Block;
        std::array<std::uint8_t, 16> Uuid;
        std::shared_ptr<std::atomic_bool> Completed;
        std::shared_ptr<ServerDoneChannel> ServerDone;
        std::shared_ptr<ServerExitedChannel> ServerExited;
    };

    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    [[nodiscard]] auto WaitForServer(BenchState State) -> Net::awaitable<bool>
    {
        const auto Completed =
            co_await State.ServerDone->async_receive(Net::use_awaitable);
        co_await State.ServerExited->async_receive(Net::use_awaitable);
        co_return Completed;
    }

    auto RunServer(BenchState State) -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Socket(State.Executor);
        boost::system::error_code AcceptError;
        auto AcceptToken =
            Net::redirect_error(Net::use_awaitable, AcceptError);
        co_await State.Acceptor.async_accept(Socket, AcceptToken);
        if (AcceptError)
        {
            (void)State.ServerDone->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

        auto Stream = std::make_shared<Reliable>(std::move(Socket));
        VmessServerConfig ServerConfig;
        ServerConfig.uuid = State.Uuid;
        auto AcceptResult = co_await Preview::Vmess::Accept(
            std::move(Stream), ServerConfig);
        const auto HandshakeError = std::get<0>(AcceptResult);
        const auto &Connection = std::get<2>(AcceptResult);
        if (HandshakeError != Error::None || !Connection)
        {
            (void)State.ServerDone->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

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
        const bool Completed = Done == State.Total;
        State.Completed->store(Completed, std::memory_order_release);
        (void)State.ServerDone->try_send(
            boost::system::error_code{}, Completed);
    }

    auto RunClient(
        BenchState State,
        const std::uint16_t Port) -> Net::awaitable<void>
    {
        auto ServerCompletion =
            [ServerDone = State.ServerDone,
             ServerExited = State.ServerExited](std::exception_ptr Exception)
            -> void
        {
            if (Exception)
            {
                (void)ServerDone->try_send(
                    boost::system::error_code{}, false);
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
            boost::system::error_code CloseError;
            State.Acceptor.close(CloseError);
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
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
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
        const BenchState State{
            Executor,
            Acceptor,
            Total,
            Block,
            Uuid,
            Completed,
            ServerDone,
            ServerExited};
        const auto Start = NowNs();
        auto ClientCompletion =
            [Completed](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                Completed->store(false, std::memory_order_release);
            }
        };
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
