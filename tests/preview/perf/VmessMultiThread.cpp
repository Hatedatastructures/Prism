/**
 * @file VmessMultiThread.cpp
 * @brief vmess 多线程并行测试（Release）
 * @details 单线程 vs 2/4 线程 ioc：验证"性能低"是否因读写串行化
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
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
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <preview/Transport/Reliable.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>

using clk = std::chrono::steady_clock;
namespace net = boost::asio;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    struct BenchState
    {
        net::io_context &Ioc;
        net::ip::tcp::acceptor &Acceptor;
        std::size_t Total;
        std::size_t Block;
        std::array<std::uint8_t, 16> Uuid;
        std::shared_ptr<std::atomic_bool> Completed;
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code, bool)>> ServerDone;
    };

    auto RunServer(BenchState State) -> net::awaitable<void>
    {
        using namespace Preview;
        net::ip::tcp::socket Socket(State.Ioc);
        boost::system::error_code AcceptError;
        co_await State.Acceptor.async_accept(
            Socket, net::redirect_error(net::use_awaitable, AcceptError));
        if (AcceptError)
        {
            (void)State.ServerDone->try_send(boost::system::error_code{}, false);
            co_return;
        }

        auto Stream = std::make_shared<Transport::Reliable>(std::move(Socket));
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = State.Uuid;
        auto [HandshakeError, Request, Conn] = co_await Vmess::Accept(Stream, ServerConfig);
        (void)Request;
        if (HandshakeError != Error::None || !Conn)
        {
            (void)State.ServerDone->try_send(boost::system::error_code{}, false);
            co_return;
        }

        std::vector<std::uint8_t> Buffer(State.Block);
        std::error_code ReadError;
        std::size_t Done = 0;
        while (Done < State.Total)
        {
            const auto ReadSize = std::min(Buffer.size(), State.Total - Done);
            const auto Count = co_await Conn->async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), ReadSize), ReadError);
            if (ReadError || Count == 0)
            {
                break;
            }
            Done += Count;
        }
        Conn->Close();
        const bool Completed = Done == State.Total;
        State.Completed->store(Completed, std::memory_order_release);
        (void)State.ServerDone->try_send(boost::system::error_code{}, Completed);
    }

    auto RunClient(BenchState State, const std::uint16_t Port) -> net::awaitable<void>
    {
        using namespace Preview;
        net::co_spawn(State.Ioc.get_executor(), RunServer(State), net::detached);

        auto Stream = std::make_shared<Transport::Reliable>(State.Ioc.get_executor());
        const auto ConnectError = co_await Stream->Connect(
            net::ip::tcp::endpoint(net::ip::address_v4::loopback(), Port));
        if (ConnectError)
        {
            (void)State.ServerDone->try_send(boost::system::error_code{}, false);
            co_return;
        }

        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = State.Uuid;
        auto [HandshakeError, Conn] = co_await Vmess::Connect(
            Stream, ClientConfig, Vmess::Address{Vmess::AddressType::Domain, "t.internal", 443});
        if (HandshakeError != Error::None || !Conn)
        {
            (void)State.ServerDone->try_send(boost::system::error_code{}, false);
            co_return;
        }

        const std::vector<std::uint8_t> Chunk(State.Block, 0x5A);
        std::error_code WriteError;
        std::size_t Done = 0;
        while (Done < State.Total)
        {
            const auto WriteSize = std::min(Chunk.size(), State.Total - Done);
            const auto Count = co_await Conn->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Chunk.data()), WriteSize),
                WriteError);
            if (WriteError || Count == 0)
            {
                State.Completed->store(false, std::memory_order_release);
                break;
            }
            Done += Count;
        }
        Conn->Close();
        const auto ServerCompleted = co_await State.ServerDone->async_receive(net::use_awaitable);
        State.Completed->store(ServerCompleted, std::memory_order_release);
    }

    auto bench(const std::size_t Total, const std::size_t Block, const int Threads) -> std::int64_t
    {
        net::io_context Ioc;
        net::ip::tcp::acceptor Acceptor(Ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        const auto Uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        const auto Completed = std::make_shared<std::atomic_bool>(false);
        const auto ServerDone = std::make_shared<net::experimental::channel<void(boost::system::error_code, bool)>>(
            Ioc.get_executor(), 1);
        const BenchState State{Ioc, Acceptor, Total, Block, Uuid, Completed, ServerDone};
        const std::int64_t Start = now_ns();
        net::co_spawn(
            Ioc, RunClient(State, Port),
            [Completed, &Ioc](std::exception_ptr Error)
            {
                if (Error)
                {
                    Completed->store(false, std::memory_order_release);
                }
                Ioc.stop();
            });

        // 多线程跑 ioc
        std::vector<std::thread> ts;
        for (int t = 0; t < Threads; ++t)
        {
            ts.emplace_back([&Ioc]() { Ioc.run(); });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        if (!Completed->load(std::memory_order_acquire))
        {
            return 0;
        }
        return now_ns() - Start;
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t kTotal = 256ULL * 1024 * 1024;

    for (const auto block : {16384UL, 65535UL})
    {
        for (const auto threads : {1, 2, 4})
        {
            std::array<std::int64_t, 3> s{};
            for (int i = 0; i < 3; ++i)
            {
                s[i] = bench(kTotal, block, threads);
            }
            std::sort(s.begin(), s.end());
            const double mbps = (kTotal / 1024.0 / 1024.0) / (s[1] / 1e9);
            std::printf("vmess chunk=%6zu 线程=%d: med=%7.2f ms  => %8.1f MB/s\n", block, threads,
                        s[1] / 1e6, mbps);
            if (std::any_of(s.begin(), s.end(), [](std::int64_t v) { return v <= 0; }) || mbps < 50.0)
            {
                std::printf("FAIL vmess chunk=%zu 线程=%d: 存在数据面未完成运行或吞吐过低\n", block, threads);
                return 1;
            }
        }
    }
    std::printf("VmessMultiThread: ALL PASS\n");
    return 0;
}
