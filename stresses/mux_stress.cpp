/**
 * @file mux_stress.cpp
 * @brief 多路复用协议压力测试
 * @details 测试 smux/yamux 帧编解码在高并发和大量数据下的稳定性，
 * 包括帧解码风暴、并发编解码、地址解析覆盖和 UDP 数据报往返验证。
 */

#include <prism/multiplex/smux/frame.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>

#include "counting_resource.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <latch>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace psm;

namespace
{
    struct stress_config
    {
        std::size_t threads = 4;
        std::size_t duration_sec = 5;
        std::size_t iterations = 1000000;       // 单线程场景每轮迭代数
        std::size_t max_payload = 4096;          // 最大 payload 大小
    };

    struct thread_stats
    {
        std::uint64_t ops = 0;
        std::uint64_t errors = 0;
        std::uint64_t bytes_allocated = 0;
        std::uint64_t peak_memory = 0;
    };

    // ============================================================
    // 测试数据生成器
    // ============================================================

    // 构造 smux 帧头（小端序）
    std::array<std::byte, 8> make_smux_frame(multiplex::smux::command cmd,
                                             std::uint16_t length, std::uint32_t stream_id)
    {
        return {
            std::byte{multiplex::smux::protocol_version},
            static_cast<std::byte>(cmd),
            static_cast<std::byte>(length & 0xFF),
            static_cast<std::byte>(length >> 8),
            static_cast<std::byte>(stream_id & 0xFF),
            static_cast<std::byte>(stream_id >> 8 & 0xFF),
            static_cast<std::byte>(stream_id >> 16 & 0xFF),
            static_cast<std::byte>(stream_id >> 24 & 0xFF),
        };
    }

    // 构造 yamux 帧头（大端序）
    std::array<std::byte, 12> make_yamux_frame(multiplex::yamux::message_type type,
                                               multiplex::yamux::flags flag,
                                               std::uint32_t stream_id, std::uint32_t length)
    {
        return {
            std::byte{multiplex::yamux::protocol_version},
            static_cast<std::byte>(type),
            static_cast<std::byte>(static_cast<std::uint16_t>(flag) >> 8 & 0xFF),
            static_cast<std::byte>(static_cast<std::uint16_t>(flag) & 0xFF),
            static_cast<std::byte>(stream_id >> 24 & 0xFF),
            static_cast<std::byte>(stream_id >> 16 & 0xFF),
            static_cast<std::byte>(stream_id >> 8 & 0xFF),
            static_cast<std::byte>(stream_id & 0xFF),
            static_cast<std::byte>(length >> 24 & 0xFF),
            static_cast<std::byte>(length >> 16 & 0xFF),
            static_cast<std::byte>(length >> 8 & 0xFF),
            static_cast<std::byte>(length & 0xFF),
        };
    }

    // 构造 mux address IPv4
    std::vector<std::byte> make_mux_addr_ipv4(std::uint16_t port)
    {
        std::vector<std::byte> buf(9);
        buf[0] = std::byte{0x00}; // flags high
        buf[1] = std::byte{0x00}; // flags low
        buf[2] = std::byte{0x01}; // atype=IPv4
        buf[3] = std::byte{127};
        buf[4] = std::byte{0};
        buf[5] = std::byte{0};
        buf[6] = std::byte{1};
        buf[7] = static_cast<std::byte>(port >> 8);
        buf[8] = static_cast<std::byte>(port & 0xFF);
        return buf;
    }

    // 构造 mux address 域名
    std::vector<std::byte> make_mux_addr_domain(std::string_view domain, std::uint16_t port)
    {
        std::vector<std::byte> buf(3 + 1 + domain.size() + 2);
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x00};
        buf[2] = std::byte{0x03};
        buf[3] = static_cast<std::byte>(domain.size());
        std::memcpy(buf.data() + 4, domain.data(), domain.size());
        const auto off = 4 + domain.size();
        buf[off] = static_cast<std::byte>(port >> 8);
        buf[off + 1] = static_cast<std::byte>(port & 0xFF);
        return buf;
    }

    // 构造 mux address IPv6
    std::vector<std::byte> make_mux_addr_ipv6(std::uint16_t port)
    {
        std::vector<std::byte> buf(3 + 16 + 2);
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x00};
        buf[2] = std::byte{0x04};
        // ::1 — 15 个零字节 + 最后一个字节 0x01
        for (std::size_t i = 3; i < 3 + 16 - 1; ++i)
            buf[i] = std::byte{0x00};
        buf[3 + 16 - 1] = std::byte{0x01};
        buf[3 + 16] = static_cast<std::byte>(port >> 8);
        buf[3 + 16 + 1] = static_cast<std::byte>(port & 0xFF);
        return buf;
    }

    // 生成随机 payload
    std::vector<std::byte> make_random_payload(std::size_t size, std::mt19937 &rng)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(rng() & 0xFF);
        return payload;
    }

    // ============================================================
    // 场景 1：帧解码风暴（单线程）
    // ============================================================

    void run_frame_decode_storm(const stress_config &config)
    {
        std::cout << std::format("\n--- 场景 1: 帧解码风暴 (单线程, {} 轮) ---\n", config.iterations);

        memory::system::enable_global_pooling();
        memory::frame_arena arena;
        auto mr = arena.get();

        // 预生成混合帧数据
        std::mt19937 rng(42);
        std::vector<std::array<std::byte, 8>> smux_frames;
        std::vector<std::array<std::byte, 12>> yamux_frames;

        const multiplex::smux::command smux_cmds[] = {
            multiplex::smux::command::syn,
            multiplex::smux::command::push,
            multiplex::smux::command::fin,
            multiplex::smux::command::nop,
        };

        for (std::size_t i = 0; i < 256; ++i)
        {
            auto cmd = smux_cmds[i % 4];
            std::uint16_t len = static_cast<std::uint16_t>(rng() % 65536);
            smux_frames.push_back(make_smux_frame(cmd, len, static_cast<std::uint32_t>(i + 1)));
        }

        const multiplex::yamux::message_type yamux_types[] = {
            multiplex::yamux::message_type::data,
            multiplex::yamux::message_type::window_update,
            multiplex::yamux::message_type::ping,
            multiplex::yamux::message_type::go_away,
        };

        for (std::size_t i = 0; i < 256; ++i)
        {
            auto type = yamux_types[i % 4];
            auto flag = static_cast<multiplex::yamux::flags>(rng() % 16);
            yamux_frames.push_back(make_yamux_frame(type, flag, static_cast<std::uint32_t>(i + 1), rng()));
        }

        stress::counting_resource counter(memory::system::global_pool());
        std::uint64_t total_ops = 0;
        std::uint64_t errors = 0;

        auto start = std::chrono::steady_clock::now();

        for (std::size_t iter = 0; iter < config.iterations; ++iter)
        {
            arena.reset();

            // 解码 smux 帧
            const auto &sf = smux_frames[iter % smux_frames.size()];
            auto shdr = multiplex::smux::deserialization(sf);
            if (!shdr)
                errors++;
            total_ops++;

            // 解码 yamux 帧
            const auto &yf = yamux_frames[iter % yamux_frames.size()];
            auto yhdr = multiplex::yamux::parse_header(yf);
            if (!yhdr)
                errors++;
            total_ops++;

            // 周期性解析地址（每 10 次迭代）
            if (iter % 10 == 0)
            {
                auto ipv4_data = make_mux_addr_ipv4(443);
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(ipv4_data.data(), ipv4_data.size()), mr);
                if (!addr)
                    errors++;
                total_ops++;
            }
        }

        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(end - start).count();

        std::cout << std::format("  迭代: {}, 操作: {}, 错误: {}\n", config.iterations, total_ops, errors);
        std::cout << std::format("  吞吐量: {:.0f} ops/s\n", total_ops / elapsed);
        std::cout << std::format("  内存: 分配 {} KB, 峰值 {} KB\n",
                                 counter.bytes_allocated() / 1024, counter.peak_bytes_in_use() / 1024);
    }

    // ============================================================
    // 场景 2：并发编解码
    // ============================================================

    void concurrent_worker(std::size_t thread_id, const stress_config &config,
                           std::latch &start_latch, const std::atomic<bool> &stop_flag,
                           thread_stats &stats)
    {
        memory::resource_pointer upstream = memory::system::thread_local_pool();
        stress::counting_resource counter(upstream);
        memory::frame_arena arena;
        auto mr = arena.get();

        std::mt19937 rng(thread_id * 7919 + 12345);

        start_latch.arrive_and_wait();

        while (!stop_flag.load(std::memory_order_relaxed))
        {
            arena.reset();

            // smux 帧解码
            const auto cmd = static_cast<multiplex::smux::command>(rng() % 4);
            auto sf = make_smux_frame(cmd, static_cast<std::uint16_t>(rng() % 1024), static_cast<std::uint32_t>(rng()));
            auto shdr = multiplex::smux::deserialization(sf);
            if (shdr)
                stats.ops++;
            else
                stats.errors++;

            // yamux 帧解码
            const auto type = static_cast<multiplex::yamux::message_type>(rng() % 4);
            auto yf = make_yamux_frame(type, multiplex::yamux::flags::none, static_cast<std::uint32_t>(rng()), rng() % 65536);
            auto yhdr = multiplex::yamux::parse_header(yf);
            if (yhdr)
                stats.ops++;
            else
                stats.errors++;

            // 地址解析
            if (rng() % 3 == 0)
            {
                auto addr_data = make_mux_addr_ipv4(static_cast<std::uint16_t>(rng() % 65536));
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(addr_data.data(), addr_data.size()), mr);
                if (addr)
                    stats.ops++;
                else
                    stats.errors++;
            }

            // UDP 构建与解析
            if (rng() % 5 == 0)
            {
                const auto payload_size = rng() % config.max_payload;
                auto payload = make_random_payload(payload_size, rng);
                auto built = multiplex::smux::build_udp_datagram(
                    "127.0.0.1", 53,
                    std::span<const std::byte>(payload.data(), payload.size()), mr);

                // 反向解析验证
                auto parsed = multiplex::smux::parse_udp_datagram(
                    std::span<const std::byte>(built.data(), built.size()), mr);
                if (!parsed || parsed->host != "127.0.0.1" || parsed->port != 53)
                    stats.errors++;
                else if (parsed->payload.size() != payload.size() ||
                         std::memcmp(parsed->payload.data(), payload.data(), payload.size()) != 0)
                    stats.errors++;
                stats.ops++;
            }
        }

        stats.bytes_allocated = counter.bytes_allocated();
        stats.peak_memory = counter.peak_bytes_in_use();
    }

    void run_concurrent_decode(const stress_config &config)
    {
        std::cout << std::format("\n--- 场景 2: 并发编解码 ({} 线程, {} 秒) ---\n",
                                 config.threads, config.duration_sec);

        std::vector<std::jthread> threads;
        std::vector<thread_stats> all_stats(config.threads);
        std::latch start_latch(config.threads + 1);
        std::atomic<bool> stop_flag{false};

        for (std::size_t i = 0; i < config.threads; ++i)
        {
            threads.emplace_back(concurrent_worker, i, std::cref(config),
                                 std::ref(start_latch), std::ref(stop_flag), std::ref(all_stats[i]));
        }

        start_latch.arrive_and_wait();
        auto start = std::chrono::steady_clock::now();

        for (std::size_t s = 0; s < config.duration_sec; ++s)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        stop_flag.store(true, std::memory_order_release);

        for (auto &t : threads)
            if (t.joinable())
                t.join();

        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(end - start).count();

        thread_stats total{};
        for (const auto &s : all_stats)
        {
            total.ops += s.ops;
            total.errors += s.errors;
            total.bytes_allocated += s.bytes_allocated;
            total.peak_memory += s.peak_memory;
        }

        std::cout << std::format("  持续: {:.2f}s, 操作: {}, 错误: {}\n", elapsed, total.ops, total.errors);
        std::cout << std::format("  吞吐量: {:.0f} ops/s\n", total.ops / elapsed);
        std::cout << std::format("  总分配: {} KB, 峰值: {} KB\n",
                                 total.bytes_allocated / 1024, total.peak_memory / 1024);
    }

    // ============================================================
    // 场景 3：地址解析覆盖
    // ============================================================

    void run_address_parse_coverage(const stress_config &config)
    {
        std::cout << std::format("\n--- 场景 3: 地址解析覆盖 ({} 轮) ---\n", config.iterations);

        memory::system::enable_global_pooling();
        memory::frame_arena arena;
        auto mr = arena.get();

        std::uint64_t ops = 0;
        std::uint64_t errors = 0;

        auto start = std::chrono::steady_clock::now();

        for (std::size_t iter = 0; iter < config.iterations; ++iter)
        {
            arena.reset();

            // IPv4
            {
                auto data = make_mux_addr_ipv4(static_cast<std::uint16_t>(iter % 65536));
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(data.data(), data.size()), mr);
                if (!addr || addr->host != "127.0.0.1" || addr->port != static_cast<std::uint16_t>(iter % 65536))
                    errors++;
                ops++;
            }

            // 域名（短）
            {
                auto data = make_mux_addr_domain("example.com", 443);
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(data.data(), data.size()), mr);
                if (!addr || addr->host != "example.com" || addr->port != 443)
                    errors++;
                ops++;
            }

            // 域名（长，参数化）
            if (iter % 100 == 0)
            {
                std::string long_domain(200, 'a');
                long_domain += ".com";
                auto data = make_mux_addr_domain(long_domain, 8080);
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(data.data(), data.size()), mr);
                if (!addr || addr->port != 8080)
                    errors++;
                ops++;
            }

            // IPv6
            if (iter % 10 == 0)
            {
                auto data = make_mux_addr_ipv6(8443);
                auto addr = multiplex::smux::parse_mux_address(
                    std::span<const std::byte>(data.data(), data.size()), mr);
                if (!addr || addr->port != 8443)
                    errors++;
                ops++;
            }
        }

        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(end - start).count();

        std::cout << std::format("  操作: {}, 错误: {}\n", ops, errors);
        std::cout << std::format("  吞吐量: {:.0f} addr/s\n", ops / elapsed);
    }

    // ============================================================
    // 场景 4：UDP 数据报编解码往返
    // ============================================================

    void run_udp_roundtrip(const stress_config &config)
    {
        std::cout << std::format("\n--- 场景 4: UDP 数据报往返验证 ({} 轮) ---\n", config.iterations);

        memory::system::enable_global_pooling();
        memory::frame_arena arena;
        auto mr = arena.get();

        std::mt19937 rng(9999);
        std::uint64_t ops = 0;
        std::uint64_t errors = 0;

        auto start = std::chrono::steady_clock::now();

        for (std::size_t iter = 0; iter < config.iterations; ++iter)
        {
            arena.reset();
            const auto payload_size = rng() % config.max_payload;
            auto payload = make_random_payload(payload_size, rng);

            // IPv4 往返
            {
                auto built = multiplex::smux::build_udp_datagram(
                    "192.168.1.1", 53,
                    std::span<const std::byte>(payload.data(), payload.size()), mr);
                auto parsed = multiplex::smux::parse_udp_datagram(
                    std::span<const std::byte>(built.data(), built.size()), mr);
                if (!parsed || parsed->host != "192.168.1.1" || parsed->port != 53)
                    errors++;
                else if (parsed->payload.size() != payload.size() ||
                         std::memcmp(parsed->payload.data(), payload.data(), payload.size()) != 0)
                    errors++;
                ops++;
            }

            // 域名往返
            {
                auto built = multiplex::smux::build_udp_datagram(
                    "test.example.org", 8443,
                    std::span<const std::byte>(payload.data(), payload.size()), mr);
                auto parsed = multiplex::smux::parse_udp_datagram(
                    std::span<const std::byte>(built.data(), built.size()), mr);
                if (!parsed || parsed->host != "test.example.org" || parsed->port != 8443)
                    errors++;
                else if (parsed->payload.size() != payload.size() ||
                         std::memcmp(parsed->payload.data(), payload.data(), payload.size()) != 0)
                    errors++;
                ops++;
            }

            // Length-prefixed 往返
            {
                auto built = multiplex::smux::build_udp_length_prefixed(
                    std::span<const std::byte>(payload.data(), payload.size()), mr);
                auto parsed = multiplex::smux::parse_udp_length_prefixed(
                    std::span<const std::byte>(built.data(), built.size()));
                if (!parsed)
                    errors++;
                else if (parsed->payload.size() != payload.size() ||
                         std::memcmp(parsed->payload.data(), payload.data(), payload.size()) != 0)
                    errors++;
                ops++;
            }
        }

        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(end - start).count();

        std::cout << std::format("  操作: {}, 错误: {}\n", ops, errors);
        std::cout << std::format("  吞吐量: {:.0f} roundtrip/s\n", ops / 3.0 / elapsed);
        if (errors > 0)
            std::cout << std::format("  *** 警告: 发现 {} 次数据不一致! ***\n", errors);
        else
            std::cout << "  所有往返验证通过\n";
    }

} // namespace

int main(const int argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif

    memory::system::enable_global_pooling();

    stress_config config;
    config.threads = 4;
    config.duration_sec = 5;
    config.iterations = 1000000;
    config.max_payload = 4096;

    std::cout << "======================================\n";
    std::cout << "  Prism 多路复用协议压力测试\n";
    std::cout << "======================================\n";
    std::cout << std::format("  线程数: {}\n", config.threads);
    std::cout << std::format("  持续时间: {}s\n", config.duration_sec);
    std::cout << std::format("  单线程迭代: {}\n", config.iterations);

    run_frame_decode_storm(config);
    run_concurrent_decode(config);
    run_address_parse_coverage(config);
    run_udp_roundtrip(config);

    std::cout << "\n======================================\n";
    std::cout << "  所有压力测试完成\n";
    std::cout << "======================================\n";

    return 0;
}
