/**
 * @file VmessDepth.cpp
 * @brief VMess 单连接与四连接传输基准（Release）
 * @details 每次运行都验证客户端写入和服务端读取的完整字节数，避免
 *          未执行的并发路径被标记为通过。
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
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
#include <variant>
#include <vector>

#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace Net = boost::asio;

namespace
{
    using Clock = std::chrono::steady_clock;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using Reliable = Prism::Transport::Reliable;
    using VmessAddress = Prism::Vmess::Address;
    using VmessAddressType = Prism::Vmess::AddressType;
    using VmessClientConfig = Prism::Vmess::ClientConfig;
    using VmessServerConfig = Prism::Vmess::ServerConfig;
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

    struct ParallelCompletionState final
    {
        std::shared_ptr<std::atomic_bool> Completed;
        std::shared_ptr<std::atomic_size_t> Remaining;
        Net::io_context *IoContext;
        Net::ip::tcp::acceptor *Acceptor;
    };

    auto CloseDepthAcceptor(const SessionState &State) -> void
    {
        boost::system::error_code Error;
        State.Acceptor.cancel(Error);
        State.Acceptor.close(Error);
    }

    auto CompleteDepthClient(SessionState State, Net::io_context *IoContext,
                             std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            CloseDepthAcceptor(State);
            State.Completed->store(false, std::memory_order_release);
        }
        IoContext->stop();
    }

    auto CompleteDepthServer(SessionState State, std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            CloseDepthAcceptor(State);
            State.Completed->store(false, std::memory_order_release);
            (void)State.ServerDone->try_send(boost::system::error_code{}, false);
        }
        (void)State.ServerExited->try_send(boost::system::error_code{});
    }

    auto CompleteDepthParallel(ParallelCompletionState State,
                               std::exception_ptr Exception) -> void
    {
        if (Exception) State.Completed->store(false, std::memory_order_release);
        if (Exception)
        {
            boost::system::error_code Error;
            State.Acceptor->cancel(Error);
            State.Acceptor->close(Error);
        }
        if (State.Remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
            State.IoContext->stop();
        }
    }

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
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(State.Executor);
        Watchdog.expires_after(std::chrono::seconds(30));
        auto DoneRace = co_await (State.ServerDone->async_receive(Net::use_awaitable) ||
                                  Watchdog.async_wait(Net::use_awaitable));
        if (DoneRace.index() != 0U)
        {
            CloseDepthAcceptor(State);
            co_return false;
        }
        const auto Completed = std::get<0>(DoneRace);
        Watchdog.expires_after(std::chrono::seconds(1));
        auto ExitRace = co_await (State.ServerExited->async_receive(Net::use_awaitable) ||
                                  Watchdog.async_wait(Net::use_awaitable));
        if (ExitRace.index() != 0U)
        {
            CloseDepthAcceptor(State);
            co_return false;
        }
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
        const auto AcceptResult = co_await Prism::Vmess::AcceptSession(
            std::move(Stream), ServerConfig);
        EXPECT_TRUE(AcceptResult);
        auto *Accepted = AcceptResult
            ? std::get_if<Prism::Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult && std::holds_alternative<Prism::Vmess::AcceptedDatagram>(*AcceptResult))
            {
                auto Datagram = std::move(
                    std::get<Prism::Vmess::AcceptedDatagram>(*AcceptResult).Connection);
                auto Underlying = Datagram->Stream();
                (void)Datagram->Close();
                (void)Underlying->Close();
                (void)co_await Datagram->Activity()->Drain();
                (void)co_await Underlying->Activity()->Drain();
            }
            (void)State.ServerDone->try_send(
                boost::system::error_code{}, false);
            co_return;
        }
        const auto &Connection = Accepted->Connection;

        std::vector<std::uint8_t> Buffer(State.Block);
        std::size_t Done = 0;
        bool Failed = false;
        while (Done < State.Total)
        {
            const auto ReadSize = std::min(Buffer.size(), State.Total - Done);
            auto ReadWindow = std::span<std::byte>(
                reinterpret_cast<std::byte *>(Buffer.data()), ReadSize);
            const auto ReadResult = co_await Connection->ReadSome(ReadWindow);
            if (ReadResult.Bytes > ReadSize)
            {
                Failed = true;
                break;
            }
            Done += ReadResult.Bytes;
            if (ReadResult.Failure.Failed() || ReadResult.Bytes == 0)
            {
                Failed = true;
                break;
            }
        }

        Connection->Close();
        const bool Completed = !Failed && Done == State.Total;
        State.Completed->store(Completed, std::memory_order_release);
        (void)State.ServerDone->try_send(
            boost::system::error_code{}, Completed);
    }

    auto RunClient(
        SessionState State,
        const std::uint16_t Port) -> Net::awaitable<void>
    {
        Net::co_spawn(
            State.Executor,
            RunServer(State),
            [State](std::exception_ptr Exception)
            { CompleteDepthServer(State, std::move(Exception)); });

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
        auto ConnectResult = co_await Prism::Vmess::Connect(
            Prism::Vmess::ConnectParameters{std::move(Stream), ClientConfig, Target});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            const auto ServerCompleted = co_await WaitForServer(State);
            State.Completed->store(
                ServerCompleted, std::memory_order_release);
            co_return;
        }
        auto Connection = std::move(*ConnectResult);

        const std::vector<std::uint8_t> Chunk(State.Block, 0x5A);
        std::size_t Done = 0;
        bool Failed = false;
        while (Done < State.Total)
        {
            const auto WriteSize =
                std::min(Chunk.size(), State.Total - Done);
            const auto WriteWindow = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Chunk.data()),
                WriteSize);
            std::size_t BlockWritten = 0;
            while (BlockWritten < WriteSize)
            {
                const auto Remaining = WriteWindow.subspan(BlockWritten);
                const auto WriteResult = co_await Connection->WriteSome(Remaining);
                if (WriteResult.Bytes > Remaining.size())
                {
                    Failed = true;
                    break;
                }
                BlockWritten += WriteResult.Bytes;
                Done += WriteResult.Bytes;
                if (WriteResult.Failure.Failed() || WriteResult.Bytes == 0)
                {
                    Failed = true;
                    break;
                }
            }
            if (Failed)
            {
                break;
            }
        }

        Connection->Close();
        const auto ServerCompleted = co_await WaitForServer(State);
        State.Completed->store(
            !Failed && Done == State.Total && ServerCompleted,
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
            [State, &IoContext](std::exception_ptr Exception)
            { CompleteDepthClient(State, &IoContext, std::move(Exception)); };
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

            const ParallelCompletionState CompletionState{
                StateCompleted, CompletedCount, &IoContext, Acceptors.back().get()};
            Net::co_spawn(
                Executor,
                RunClient(States.back(), Port),
                [CompletionState](std::exception_ptr Exception)
                { CompleteDepthParallel(CompletionState, std::move(Exception)); });
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
