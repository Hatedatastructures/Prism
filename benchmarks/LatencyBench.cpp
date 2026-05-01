/**
 * @file LatencyBench.cpp
 * @brief 延迟基准测试
 * @details 测量单次操作的延迟（单线程，无竞态）。
 */

#include <benchmark/benchmark.h>
#include <boost/asio.hpp>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <numeric>
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

    std::vector<std::byte> make_payload(std::size_t size)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(i & 0xFF);
        return payload;
    }

    template <typename T>
    T calculate_percentile(std::vector<T> &samples, double percentile)
    {
        if (samples.empty())
            return T{};

        std::sort(samples.begin(), samples.end());
        auto index = static_cast<std::size_t>(samples.size() * percentile);
        if (index >= samples.size())
            index = samples.size() - 1;

        return samples[index];
    }
} // namespace

// ============================================================
// 连接建立延迟
// ============================================================

static void BM_ConnectionLatency(benchmark::State &state)
{
    std::vector<std::chrono::microseconds::rep> latencies;

    for (auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();
        pipe_pair pipe;
        auto end = std::chrono::high_resolution_clock::now();

        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        latencies.push_back(latency);

        benchmark::DoNotOptimize(pipe.client);
    }

    if (!latencies.empty())
    {
        state.counters["p50_us"] = static_cast<double>(calculate_percentile(latencies, 0.50));
        state.counters["p90_us"] = static_cast<double>(calculate_percentile(latencies, 0.90));
        state.counters["p99_us"] = static_cast<double>(calculate_percentile(latencies, 0.99));
        state.counters["avg_us"] = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL) / latencies.size());
    }

    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// 数据转发延迟
// ============================================================

static void BM_TunnelLatency(benchmark::State &state)
{
    pipe_pair pipe;

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
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

    std::vector<std::chrono::microseconds::rep> latencies;
    boost::system::error_code ec;

    for (auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();

        net::write(pipe.client, net::buffer(payload), ec);
        if (ec)
            break;
        net::read(pipe.client, net::buffer(response), ec);
        if (ec)
            break;

        auto end = std::chrono::high_resolution_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        latencies.push_back(latency);
    }

    pipe.client.close(ec);
    pipe.server.close(ec);
    server_thread.join();

    if (!latencies.empty())
    {
        state.counters["p50_us"] = static_cast<double>(calculate_percentile(latencies, 0.50));
        state.counters["p90_us"] = static_cast<double>(calculate_percentile(latencies, 0.90));
        state.counters["p99_us"] = static_cast<double>(calculate_percentile(latencies, 0.99));
        state.counters["avg_us"] = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL) / latencies.size());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(payload_size * 2));
}

// ============================================================
// 小包延迟
// ============================================================

static void BM_SmallPacketLatency(benchmark::State &state)
{
    pipe_pair pipe;
    const auto payload = make_payload(64);
    std::vector<std::byte> response(64);

    std::thread server_thread([&pipe]()
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

    std::vector<std::chrono::microseconds::rep> latencies;
    boost::system::error_code ec;

    for (auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();

        net::write(pipe.client, net::buffer(payload), ec);
        if (ec)
            break;
        net::read(pipe.client, net::buffer(response), ec);
        if (ec)
            break;

        auto end = std::chrono::high_resolution_clock::now();
        latencies.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
    }

    pipe.client.close(ec);
    pipe.server.close(ec);
    server_thread.join();

    if (!latencies.empty())
    {
        state.counters["avg_us"] = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL) / latencies.size());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 2);
}

// ============================================================
// 大包延迟
// ============================================================

static void BM_LargePacketLatency(benchmark::State &state)
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

    std::vector<std::chrono::microseconds::rep> latencies;
    boost::system::error_code ec;

    for (auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();

        net::write(pipe.client, net::buffer(payload), ec);
        if (ec)
            break;
        net::read(pipe.client, net::buffer(response), ec);
        if (ec)
            break;

        auto end = std::chrono::high_resolution_clock::now();
        latencies.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
    }

    pipe.client.close(ec);
    pipe.server.close(ec);
    server_thread.join();

    if (!latencies.empty())
    {
        state.counters["avg_us"] = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL) / latencies.size());
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024 * 2);
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_ConnectionLatency)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_TunnelLatency)
    ->Arg(64)
    ->Arg(1 * 1024)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_SmallPacketLatency)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_LargePacketLatency)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();