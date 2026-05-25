/**
 * @file RegressionBench.cpp
 * @brief 性能回归基准测试
 * @details 测量关键热路径操作的性能基线，用于检测性能退化。
 *          包含 AES-256-GCM 吞吐量、X25519 密钥交换延迟、
 *          全局池分配吞吐率、TCP echo RTT 四项基准。
 *          每项基准输出格式: [BENCH] name: value unit
 */

#include "common/TestRunner.hpp"

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/x25519.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <thread>
#include <vector>

namespace
{
    /**
     * @brief 计算样本集合的指定百分位数
     * @param samples 已排序的样本集合
     * @param percentile 百分位 (0.0 ~ 1.0)
     * @return 对应百分位的样本值
     */
    template <typename T>
    auto calculate_percentile(std::vector<T> &samples, double percentile) -> T
    {
        if (samples.empty())
            return T{};

        std::sort(samples.begin(), samples.end());
        auto index = static_cast<std::size_t>(samples.size() * percentile);
        if (index >= samples.size())
            index = samples.size() - 1;

        return samples[index];
    }

    /**
     * @brief 生成填充数据
     * @param size 数据长度
     * @param fill 填充字节
     * @return 指定长度的数据向量
     */
    auto make_payload(std::size_t size, std::uint8_t fill = 0x42) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(size, fill);
    }

    // ================================================================
    // AES-256-GCM 吞吐量基准
    // 加密 1MB 数据，计算 MB/s 吞吐量
    // ================================================================

    void bench_aes256_gcm_throughput(psm::testing::TestRunner &runner)
    {
        runner.LogInfo("Running AES-256-GCM throughput benchmark...");

        // 32 字节全零密钥（仅用于基准测试）
        std::array<std::uint8_t, 32> key{};
        psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_256_gcm, key);

        constexpr std::size_t data_size = 1024 * 1024; // 1MB
        constexpr std::size_t chunk_size = 16384;       // 16KB 每次加密
        constexpr std::size_t iterations = data_size / chunk_size;

        std::vector<std::uint8_t> plaintext(chunk_size, 0x42);
        std::vector<std::uint8_t> ciphertext(
            psm::crypto::aead_context::seal_output_size(chunk_size));

        // 预热：执行一次加密确保上下文初始化完成
        (void)ctx.seal(ciphertext, plaintext);

        auto start = std::chrono::high_resolution_clock::now();

        for (std::size_t i = 0; i < iterations; ++i)
        {
            auto ec = ctx.seal(ciphertext, plaintext);
            if (psm::fault::failed(ec))
            {
                runner.LogFail("AES-256-GCM seal failed during benchmark");
                return;
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

        // 计算吞吐量: 总字节数 / 耗时秒数
        double elapsed_sec = static_cast<double>(elapsed_ns) / 1e9;
        double throughput_mb = static_cast<double>(data_size) / (1024.0 * 1024.0) / elapsed_sec;

        psm::trace::info("[BENCH] aes_256_gcm_throughput: {:.2f} MB/s", throughput_mb);
        runner.Check(throughput_mb > 0.0, "AES-256-GCM throughput > 0 MB/s");
    }

    // ================================================================
    // X25519 密钥交换延迟基准
    // 执行 1000 次密钥交换，计算平均延迟（微秒）
    // ================================================================

    void bench_x25519_latency(psm::testing::TestRunner &runner)
    {
        runner.LogInfo("Running X25519 key exchange latency benchmark...");

        constexpr std::size_t iterations = 1000;

        // 预生成固定密钥对，避免密钥生成开销影响测量
        auto alice = psm::crypto::generate_x25519_keypair();
        auto bob = psm::crypto::generate_x25519_keypair();

        std::vector<std::int64_t> latencies;
        latencies.reserve(iterations);

        // 预热
        {
            auto [ec, shared] = psm::crypto::x25519(alice.private_key, bob.public_key);
            if (psm::fault::failed(ec))
            {
                runner.LogFail("X25519 warmup key exchange failed");
                return;
            }
        }

        for (std::size_t i = 0; i < iterations; ++i)
        {
            auto start = std::chrono::high_resolution_clock::now();

            auto [ec, shared] = psm::crypto::x25519(alice.private_key, bob.public_key);

            auto end = std::chrono::high_resolution_clock::now();

            if (psm::fault::failed(ec))
            {
                runner.LogFail("X25519 key exchange failed during benchmark");
                return;
            }

            auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            latencies.push_back(us);
        }

        double avg_us = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL)) /
            static_cast<double>(latencies.size());

        double p50_us = static_cast<double>(calculate_percentile(latencies, 0.50));
        double p99_us = static_cast<double>(calculate_percentile(latencies, 0.99));

        psm::trace::info("[BENCH] x25519_latency: avg={:.2f} us, p50={:.2f} us, p99={:.2f} us",
                         avg_us, p50_us, p99_us);
        runner.Check(avg_us > 0.0, "X25519 latency measured successfully");
    }

    // ================================================================
    // 全局池分配吞吐率基准
    // 分配/释放 10000 个 256 字节块，计算 ops/s
    // ================================================================

    void bench_global_pool_allocation(psm::testing::TestRunner &runner)
    {
        runner.LogInfo("Running global pool allocation benchmark...");

        constexpr std::size_t iterations = 10000;
        constexpr std::size_t block_size = 256;

        auto *pool = psm::memory::system::global_pool();

        // 预热：分配再释放一轮
        {
            void *ptr = pool->allocate(block_size);
            pool->deallocate(ptr, block_size);
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (std::size_t i = 0; i < iterations; ++i)
        {
            void *ptr = pool->allocate(block_size);
            pool->deallocate(ptr, block_size);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

        double elapsed_sec = static_cast<double>(elapsed_ns) / 1e9;
        double ops_per_sec = static_cast<double>(iterations) / elapsed_sec;

        psm::trace::info("[BENCH] global_pool_alloc: {:.2f} ops/s", ops_per_sec);
        runner.Check(ops_per_sec > 0.0, "Global pool allocation throughput > 0 ops/s");
    }

    // ================================================================
    // TCP echo 延迟基准
    // 通过 localhost socket pair 收发 1KB 数据，计算 RTT（微秒）
    // ================================================================

    void bench_tcp_echo_latency(psm::testing::TestRunner &runner)
    {
        runner.LogInfo("Running TCP echo latency benchmark...");

        namespace net = boost::asio;

        constexpr std::size_t payload_size = 1024;
        constexpr std::size_t iterations = 1000;

        // 建立 localhost TCP 连接对
        net::io_context io;
        net::ip::tcp::socket client(io);
        net::ip::tcp::socket server(io);

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

        const auto payload = make_payload(payload_size);
        std::vector<std::uint8_t> response(payload_size);

        // 启动 echo 服务端线程
        std::atomic<bool> stop_server{false};
        std::thread server_thread([&server, &stop_server]()
        {
            std::vector<std::uint8_t> buf(payload_size);
            boost::system::error_code ec;
            while (!stop_server.load(std::memory_order_relaxed))
            {
                std::size_t n = server.read_some(net::buffer(buf), ec);
                if (ec)
                    break;
                net::write(server, net::buffer(buf, n), ec);
                if (ec)
                    break;
            }
        });

        std::vector<std::int64_t> latencies;
        latencies.reserve(iterations);
        boost::system::error_code ec;

        // 预热
        {
            net::write(client, net::buffer(payload), ec);
            if (ec)
            {
                stop_server.store(true);
                client.close();
                server.close();
                server_thread.join();
                runner.LogFail("TCP echo warmup write failed");
                return;
            }
            net::read(client, net::buffer(response), ec);
            if (ec)
            {
                stop_server.store(true);
                client.close();
                server.close();
                server_thread.join();
                runner.LogFail("TCP echo warmup read failed");
                return;
            }
        }

        for (std::size_t i = 0; i < iterations; ++i)
        {
            auto start = std::chrono::high_resolution_clock::now();

            net::write(client, net::buffer(payload), ec);
            if (ec)
                break;
            net::read(client, net::buffer(response), ec);
            if (ec)
                break;

            auto end = std::chrono::high_resolution_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            latencies.push_back(us);
        }

        stop_server.store(true);
        client.close(ec);
        server.close(ec);
        server_thread.join();

        if (latencies.empty())
        {
            runner.LogFail("TCP echo benchmark collected no samples");
            return;
        }

        double avg_us = static_cast<double>(
            std::accumulate(latencies.begin(), latencies.end(), 0LL)) /
            static_cast<double>(latencies.size());
        double p50_us = static_cast<double>(calculate_percentile(latencies, 0.50));
        double p99_us = static_cast<double>(calculate_percentile(latencies, 0.99));

        psm::trace::info("[BENCH] tcp_echo_rtt: avg={:.2f} us, p50={:.2f} us, p99={:.2f} us",
                         avg_us, p50_us, p99_us);
        runner.Check(avg_us > 0.0, "TCP echo RTT measured successfully");
    }

} // namespace

/**
 * @brief 基准测试入口
 * @details 初始化全局内存池和日志系统，依次运行四项性能回归基准：
 *          AES-256-GCM 吞吐量、X25519 密钥交换延迟、
 *          全局池分配吞吐率、TCP echo RTT。
 *          最后输出汇总结果。
 * @return 0 表示全部基准通过，1 表示存在失败
 */
auto main() -> int
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统（使用默认配置，仅控制台输出）
    psm::trace::init({});

    psm::testing::TestRunner runner("RegressionBench");

    runner.LogInfo("=== Performance Regression Benchmarks ===");
    runner.LogInfo("");

    // AES-256-GCM 加密吞吐量
    bench_aes256_gcm_throughput(runner);

    // X25519 密钥交换延迟
    bench_x25519_latency(runner);

    // 全局池分配吞吐率
    bench_global_pool_allocation(runner);

    // TCP echo 往返延迟
    bench_tcp_echo_latency(runner);

    runner.LogInfo("");
    runner.LogInfo("=== Benchmarks Complete ===");

    return runner.Summary();
}
