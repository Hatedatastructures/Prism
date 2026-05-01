/**
 * @file IOBench.cpp
 * @brief TCP/UDP 真实网络 I/O 吞吐量基准测试
 */

#include <benchmark/benchmark.h>
#include <boost/asio.hpp>
#include <array>
#include <cstddef>
#include <cstring>
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

    std::vector<std::byte> make_payload(std::size_t size)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(i & 0xFF);
        return payload;
    }
} // namespace

static void BM_TcpEcho_64B(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(64);
    std::vector<std::byte> response(64);

    std::thread server_thread([&pipe, &payload]()
    {
        std::vector<std::byte> buf(64);
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

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 2);
}

static void BM_TcpEcho_1KB(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(1024);
    std::vector<std::byte> response(1024);

    std::thread server_thread([&pipe]()
    {
        std::vector<std::byte> buf(1024);
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

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 1024 * 2);
}

static void BM_TcpEcho_16KB(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(16 * 1024);
    std::vector<std::byte> response(16 * 1024);

    std::thread server_thread([&pipe]()
    {
        std::vector<std::byte> buf(16 * 1024);
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

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16 * 1024 * 2);
}

static void BM_TcpEcho_64KB(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(64 * 1024);
    std::vector<std::byte> response(64 * 1024);

    std::thread server_thread([&pipe]()
    {
        std::vector<std::byte> buf(64 * 1024);
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

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024 * 2);
}

static void BM_TcpEcho_128KB(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(128 * 1024);
    std::vector<std::byte> response(128 * 1024);

    std::thread server_thread([&pipe]()
    {
        std::vector<std::byte> buf(128 * 1024);
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

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 128 * 1024 * 2);
}

static void BM_MemoryCopy_64B(benchmark::State &state)
{
    const auto payload = make_payload(64);
    std::vector<std::byte> response(64);

    for (auto _ : state)
    {
        std::memcpy(response.data(), payload.data(), 64);
        benchmark::DoNotOptimize(response.data());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 2);
}

static void BM_MemoryCopy_1KB(benchmark::State &state)
{
    const auto payload = make_payload(1024);
    std::vector<std::byte> response(1024);

    for (auto _ : state)
    {
        std::memcpy(response.data(), payload.data(), 1024);
        benchmark::DoNotOptimize(response.data());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 1024 * 2);
}

static void BM_MemoryCopy_16KB(benchmark::State &state)
{
    const auto payload = make_payload(16 * 1024);
    std::vector<std::byte> response(16 * 1024);

    for (auto _ : state)
    {
        std::memcpy(response.data(), payload.data(), 16 * 1024);
        benchmark::DoNotOptimize(response.data());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16 * 1024 * 2);
}

static void BM_MemoryCopy_64KB(benchmark::State &state)
{
    const auto payload = make_payload(64 * 1024);
    std::vector<std::byte> response(64 * 1024);

    for (auto _ : state)
    {
        std::memcpy(response.data(), payload.data(), 64 * 1024);
        benchmark::DoNotOptimize(response.data());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024 * 2);
}

static void BM_MemoryCopy_128KB(benchmark::State &state)
{
    const auto payload = make_payload(128 * 1024);
    std::vector<std::byte> response(128 * 1024);

    for (auto _ : state)
    {
        std::memcpy(response.data(), payload.data(), 128 * 1024);
        benchmark::DoNotOptimize(response.data());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 128 * 1024 * 2);
}

BENCHMARK(BM_TcpEcho_64B)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_TcpEcho_1KB)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_TcpEcho_16KB)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_TcpEcho_64KB)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_TcpEcho_128KB)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_MemoryCopy_64B)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryCopy_1KB)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryCopy_16KB)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryCopy_64KB)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryCopy_128KB)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();