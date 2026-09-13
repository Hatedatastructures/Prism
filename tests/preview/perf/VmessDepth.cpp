/**
 * @file VmessDepth.cpp
 * @brief VMess 单连接与四连接传输基准（Release）
 * @details 每次运行都验证客户端写入和服务端读取的完整字节数，避免
 *          未执行的并发路径被标记为通过。
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
#include <tuple>
#include <vector>

#include <preview/Protocols/Vmess/Vmess.hpp>
#include <preview/Transport/Reliable.hpp>

namespace Net = boost::asio;

namespace
{
    using Clock = std::chrono::steady_clock;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using Reliable = Preview::Transport::Reliable;
    using VmessAddress = Preview::Vmess::Address;
    using VmessAddressType = Preview::Vmess::AddressType;
    using VmessClientConfig = Preview::Vmess::ClientConfig;
    using VmessServerConfig = Preview::Vmess::ServerConfig;
    using ServerDoneChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using ServerExitedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct SessionState
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

    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        return {
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
    }

    [[nodiscard]] auto WaitForServer(SessionState State) -> Net::awaitable<bool>
    {
        const auto Completed =
            co_await State.ServerDone->async_receive(Net::use_awaitable);
        co_await State.ServerExited->async_receive(Net::use_awaitable);
        co_return Completed;
    }

    auto RunServer(SessionState State) -> Net::awaitable<void>
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
        const auto AcceptResult = co_await Preview::Vmess::Accept(
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
        SessionState State,
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
            "Target.internal",
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

    [[nodiscard]] auto BenchSingle(
        const std::size_t Total,
        const std::size_t Block) -> std::int64_t
    {
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        const auto Completed = std::make_shared<std::atomic_bool>(false);
        const auto ServerDone =
            std::make_shared<ServerDoneChannel>(Executor, 1);
        const auto ServerExited =
            std::make_shared<ServerExitedChannel>(Executor, 1);
        const SessionState State{
            Executor,
            Acceptor,
            Total,
            Block,
            MakeUuid(),
            Completed,
            ServerDone,
            ServerExited};
        const auto Start = NowNs();
        auto ClientCompletion =
            [Completed, &IoContext](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                Completed->store(false, std::memory_order_release);
            }
            IoContext.stop();
        };
        Net::co_spawn(
            Executor,
            RunClient(State, Port),
            std::move(ClientCompletion));
        IoContext.run();
        if (!Completed->load(std::memory_order_acquire))
        {
            return 0;
        }
        return NowNs() - Start;
    }

    [[nodiscard]] auto BenchParallel(
        const std::size_t Total,
        const std::size_t Block) -> std::int64_t
    {
        constexpr std::size_t ConnectionCount = 4;
        const auto PerConnection = Total / ConnectionCount;
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        const auto Uuid = MakeUuid();
        std::vector<std::unique_ptr<Net::ip::tcp::acceptor>> Acceptors;
        std::vector<SessionState> States;
        std::vector<std::shared_ptr<std::atomic_bool>> Completed;
        Acceptors.reserve(ConnectionCount);
        States.reserve(ConnectionCount);
        Completed.reserve(ConnectionCount);
        const auto Start = NowNs();
        const auto CompletedCount =
            std::make_shared<std::atomic_size_t>(0);

        for (std::size_t Index = 0; Index < ConnectionCount; ++Index)
        {
            auto Acceptor = std::make_unique<Net::ip::tcp::acceptor>(
                IoContext,
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            const auto Port = Acceptor->local_endpoint().port();
            const auto StateCompleted =
                std::make_shared<std::atomic_bool>(false);
            const auto ServerDone =
                std::make_shared<ServerDoneChannel>(Executor, 1);
            const auto ServerExited =
                std::make_shared<ServerExitedChannel>(Executor, 1);
            Acceptors.push_back(std::move(Acceptor));
            States.push_back(SessionState{
                Executor,
                *Acceptors.back(),
                PerConnection,
                Block,
                Uuid,
                StateCompleted,
                ServerDone,
                ServerExited});
            Completed.push_back(StateCompleted);

            auto ClientCompletion =
                [StateCompleted,
                 CompletedCount,
                 &IoContext](std::exception_ptr Exception) -> void
            {
                if (Exception)
                {
                    StateCompleted->store(
                        false, std::memory_order_release);
                }
                const auto Finished = CompletedCount->fetch_add(
                    1, std::memory_order_acq_rel) + 1;
                if (Finished == ConnectionCount)
                {
                    IoContext.stop();
                }
            };
            Net::co_spawn(
                Executor,
                RunClient(States.back(), Port),
                std::move(ClientCompletion));
        }

        IoContext.run();
        for (const auto &StateCompleted : Completed)
        {
            if (!StateCompleted->load(std::memory_order_acquire))
            {
                return 0;
            }
        }
        return NowNs() - Start;
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t Total = 256ULL * 1024 * 1024;

    for (const auto Block : {16384UL, 262144UL})
    {
        std::array<std::int64_t, 3> SingleSamples{};
        std::array<std::int64_t, 3> ParallelSamples{};
        for (std::size_t SampleIndex = 0;
             SampleIndex < SingleSamples.size();
             ++SampleIndex)
        {
            SingleSamples[SampleIndex] = BenchSingle(Total, Block);
            ParallelSamples[SampleIndex] = BenchParallel(Total, Block);
        }
        std::sort(SingleSamples.begin(), SingleSamples.end());
        std::sort(ParallelSamples.begin(), ParallelSamples.end());
        const auto SingleMedianNs = SingleSamples[1];
        const auto ParallelMedianNs = ParallelSamples[1];
        if (SingleMedianNs <= 0 || ParallelMedianNs <= 0)
        {
            std::printf(
                "FAIL vmess block=%zu: 数据面未完成运行\n",
                Block);
            return 1;
        }

        const double SingleMegabytesPerSecond =
            (Total / 1024.0 / 1024.0) /
            (static_cast<double>(SingleMedianNs) / 1e9);
        const double ParallelMegabytesPerSecond =
            (Total / 1024.0 / 1024.0) /
            (static_cast<double>(ParallelMedianNs) / 1e9);
        std::printf(
            "vmess block=%6zu 单连接=%8.1f MB/s 四连接=%8.1f MB/s\n",
            Block,
            SingleMegabytesPerSecond,
            ParallelMegabytesPerSecond);
        if (SingleMegabytesPerSecond < 50.0 ||
            ParallelMegabytesPerSecond < 50.0)
        {
            std::printf(
                "FAIL vmess block=%zu: 吞吐低于门槛\n",
                Block);
            return 1;
        }
    }
    std::printf("VmessDepth: ALL PASS\n");
    return 0;
}
