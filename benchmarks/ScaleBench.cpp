/**
 * @file ScaleBench.cpp
 * @brief 连接建立和线程扩展性基准测试
 * @details 测量连接建立速率和单线程吞吐量。
 *          避免多线程共享 socket，改为测试单连接性能和多线程独立连接。
 */

#include <benchmark/benchmark.h>
#include <boost/asio.hpp>
#include <atomic>
#include <cstddef>
#include <thread>
#include <vector>

namespace net = boost::asio;

namespace
{
    struct pipe_pair
    {
        net::io_context io;
        net::ip::tcp::socket client;
        net::ip::tcp::socket server;

        explicit pipe_pair()
            : client(io), server(io)
        {
            net::ip::tcp::acceptor acceptor(io,
                net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
            auto ep = acceptor.local_endpoint();

            client.open(net::ip::tcp::v4());
            client.connect(ep);
            server = acceptor.accept();
            acceptor.close();

            client.set_option(net::ip::tcp::no_delay(true));
            server.set_option(net::ip::tcp::no_delay(true));
        }
    };
} // namespace

// ============================================================
// 连接建立时间测试（单连接）
// ============================================================

static void BM_ConnectionEstablishTime(benchmark::State &state)
{
    for (auto _ : state)
    {
        pipe_pair pipe;
        benchmark::DoNotOptimize(pipe.client);
    }
    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// 连接建立速率测试（连续建立多个连接）
// ============================================================

static void BM_ConnectionRate_100(benchmark::State &state)
{
    net::io_context io;
    net::ip::tcp::acceptor acceptor(io,
        net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
    auto port = acceptor.local_endpoint().port();

    // 服务端 accept 循环
    std::thread accept_thread([&]()
    {
        boost::system::error_code ec;
        while (true)
        {
            auto sock = acceptor.accept(ec);
            if (ec)
                break;
            sock.close(ec);
        }
    });

    for (auto _ : state)
    {
        // 建立 100 个连接
        for (int i = 0; i < 100; ++i)
        {
            net::ip::tcp::socket client(io);
            client.connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            client.close();
        }
    }

    acceptor.close();
    accept_thread.join();

    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()) * 100);
}

// ============================================================
// 单连接吞吐量基准
// ============================================================

static void BM_SingleConnectionThroughput(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload_size = static_cast<std::size_t>(state.range(0));

    std::vector<std::byte> payload(payload_size);
    for (std::size_t i = 0; i < payload_size; ++i)
        payload[i] = static_cast<std::byte>(i & 0xFF);

    std::vector<std::byte> response(payload_size);

    std::thread server_thread([&pipe, payload_size]()
    {
        std::vector<std::byte> buf(payload_size);
        boost::system::error_code ec;
        while (true)
        {
            std::size_t n = pipe.server.read_some(net::buffer(buf), ec);
            if (ec)
                break;
            net::write(pipe.server, net::buffer(buf, n), ec);
            if (ec)
                break;
        }
    });

    boost::system::error_code ec;
    for (auto _ : state)
    {
        net::write(pipe.client, net::buffer(payload), ec);
        if (ec)
            break;
        net::read(pipe.client, net::buffer(response), ec);
        if (ec)
            break;
        benchmark::DoNotOptimize(response.data());
    }

    pipe.client.close(ec);
    pipe.server.close(ec);
    server_thread.join();

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(payload_size * 2));
}

// ============================================================
// 多独立连接吞吐量（每个线程有自己的连接，无共享）
// ============================================================

static void BM_MultiIndependentConnections_4(benchmark::State &state)
{
    net::io_context io;
    net::ip::tcp::acceptor acceptor(io,
        net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
    auto port = acceptor.local_endpoint().port();

    // 4 个独立的 accept 线程
    std::vector<std::thread> server_threads;
    for (int i = 0; i < 4; ++i)
    {
        server_threads.emplace_back([&acceptor, port]()
        {
            // 每个线程有自己的 io_context 和 socket
            net::io_context server_io;
            std::vector<std::byte> buf(16 * 1024);
            boost::system::error_code ec;

            // 每个 accept 线程处理一个连接
            while (true)
            {
                try
                {
                    auto sock = acceptor.accept();
                    while (true)
                    {
                        auto n = sock.read_some(net::buffer(buf), ec);
                        if (ec)
                            break;
                        net::write(sock, net::buffer(buf, n), ec);
                        if (ec)
                            break;
                    }
                    sock.close();
                }
                catch (...)
                {
                    break;
                }
            }
        });
    }

    // 4 个独立客户端线程，各自有自己的连接
    std::vector<std::thread> client_threads;
    std::atomic<bool> running{true};
    std::atomic<std::size_t> total_bytes{0};

    for (int i = 0; i < 4; ++i)
    {
        client_threads.emplace_back([&]()
        {
            net::io_context client_io;
            net::ip::tcp::socket sock(client_io);
            sock.connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            sock.set_option(net::ip::tcp::no_delay(true));

            std::vector<std::byte> payload(16 * 1024);
            std::vector<std::byte> response(16 * 1024);
            boost::system::error_code ec;

            while (running.load())
            {
                net::write(sock, net::buffer(payload), ec);
                if (ec)
                    break;
                net::read(sock, net::buffer(response), ec);
                if (ec)
                    break;
                total_bytes.fetch_add(16 * 1024 * 2);
            }
            sock.close();
        });
    }

    for (auto _ : state)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    running.store(false);
    acceptor.close();

    for (auto &t : client_threads)
        t.join();
    for (auto &t : server_threads)
        t.join();

    state.SetBytesProcessed(static_cast<std::int64_t>(total_bytes.load()));
}

static void BM_MultiIndependentConnections_8(benchmark::State &state)
{
    net::io_context io;
    net::ip::tcp::acceptor acceptor(io,
        net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
    auto port = acceptor.local_endpoint().port();

    std::vector<std::thread> server_threads;
    for (int i = 0; i < 8; ++i)
    {
        server_threads.emplace_back([&acceptor]()
        {
            std::vector<std::byte> buf(16 * 1024);
            boost::system::error_code ec;
            while (true)
            {
                try
                {
                    auto sock = acceptor.accept();
                    while (true)
                    {
                        auto n = sock.read_some(net::buffer(buf), ec);
                        if (ec)
                            break;
                        net::write(sock, net::buffer(buf, n), ec);
                        if (ec)
                            break;
                    }
                    sock.close();
                }
                catch (...)
                {
                    break;
                }
            }
        });
    }

    std::vector<std::thread> client_threads;
    std::atomic<bool> running{true};
    std::atomic<std::size_t> total_bytes{0};

    for (int i = 0; i < 8; ++i)
    {
        client_threads.emplace_back([&]()
        {
            net::io_context client_io;
            net::ip::tcp::socket sock(client_io);
            sock.connect(net::ip::tcp::endpoint(net::ip::address_v4::loopback(), port));
            sock.set_option(net::ip::tcp::no_delay(true));

            std::vector<std::byte> payload(16 * 1024);
            std::vector<std::byte> response(16 * 1024);
            boost::system::error_code ec;

            while (running.load())
            {
                net::write(sock, net::buffer(payload), ec);
                if (ec)
                    break;
                net::read(sock, net::buffer(response), ec);
                if (ec)
                    break;
                total_bytes.fetch_add(16 * 1024 * 2);
            }
            sock.close();
        });
    }

    for (auto _ : state)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    running.store(false);
    acceptor.close();

    for (auto &t : client_threads)
        t.join();
    for (auto &t : server_threads)
        t.join();

    state.SetBytesProcessed(static_cast<std::int64_t>(total_bytes.load()));
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_ConnectionEstablishTime)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ConnectionRate_100)->Unit(benchmark::kMillisecond)->Iterations(5);

BENCHMARK(BM_SingleConnectionThroughput)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_MultiIndependentConnections_4)->Unit(benchmark::kMillisecond)->Iterations(10);
BENCHMARK(BM_MultiIndependentConnections_8)->Unit(benchmark::kMillisecond)->Iterations(10);

BENCHMARK_MAIN();