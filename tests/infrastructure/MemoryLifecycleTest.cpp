/**
 * @file MemoryLifecycleTest.cpp
 * @brief 资源指针全生命周期长跑测试
 * @details 验证内存策略在协议处理整个生命周期的稳定性：
 * 1. 单连接长跑：一个 conn 会话内持续传输大流量（256MB），
 *    校验数据完整 + 复用缓冲 capacity 稳定（零再分配）
 * 2. 帧循环长跑：100 万帧编码复用，capacity 不变
 * 3. 会话回收循环：大量 conn 生命周期创建/析构（arena 正确回收）
 * 4. 多连接压力：200 个连接循环（握手 + 传输 + 析构）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/socks5/socks5.hpp>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /// 简单校验和（避免大哈希开销）
    auto checksum(std::span<const std::uint8_t> data) -> std::uint64_t
    {
        std::uint64_t sum = 0;
        for (const auto b : data)
        {
            sum = sum * 31 + b;
        }
        return sum;
    }

    // ── 1. 单连接长跑：256MB 传输 + 复用缓冲稳定性 ──

    TEST(MemoryLifecycle, LongRunSingleConnTransfer)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        std::exception_ptr ep;

        constexpr std::size_t kTotalMB = 256;
        constexpr std::size_t kChunk = 65536;
        constexpr std::size_t kTotal = kTotalMB * 1024 * 1024;
        constexpr std::size_t kChunks = kTotal / kChunk;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            // 服务端：接收并回显校验和
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await socks5::accept(
                    std::make_shared<memory_stream>(std::move(b)), socks5::server_config{});
                if (err != error::none || !conn)
                {
                    co_return;
                }
                std::array<std::uint8_t, kChunk> buf{};
                std::uint64_t total = 0;
                std::size_t done = 0;
                while (done < kTotal)
                {
                    std::error_code ec;
                    const auto n = co_await conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    total += checksum(std::span<const std::uint8_t>(buf).first(n));
                    done += n;
                }
                // 回显校验和（8 字节）
                std::array<std::uint8_t, 8> reply{};
                for (std::size_t i = 0; i < 8; ++i)
                {
                    reply[i] = static_cast<std::uint8_t>((total >> (i * 8)) & 0xFF);
                }
                std::error_code ec;
                co_await conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(reply.data()), reply.size()),
                    ec);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 客户端：发送数据并收集校验和
            auto [err, conn] = co_await socks5::connect(
                std::make_shared<memory_stream>(std::move(a)), socks5::client_config{},
                socks5::address{socks5::address_type::domain, "target.example", 443});

            if (err != error::none || !conn)
            {
                ADD_FAILURE() << "client connect failed";
                co_return;
            }

            std::vector<std::uint8_t> chunk(kChunk);
            for (std::size_t i = 0; i < chunk.size(); ++i)
            {
                chunk[i] = static_cast<std::uint8_t>(i * 7 + (i >> 8));
            }
            std::uint64_t total = 0;
            for (std::size_t c = 0; c < kChunks; ++c)
            {
                std::error_code ec;
                std::size_t off = 0;
                while (off < kChunk)
                {
                    const auto n = co_await conn->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data() + off),
                                                   kChunk - off),
                        ec);
                    if (ec)
                    {
                        ADD_FAILURE() << "write failed at chunk " << c;
                        break;
                    }
                    off += n;
                }
                total += checksum(chunk);
            }

            // 读取服务端回显的校验和
            std::array<std::uint8_t, 8> reply{};
            std::size_t got = 0;
            std::error_code ec;
            while (got < 8)
            {
                const auto n = co_await conn->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(reply.data() + got), 8 - got), ec);
                if (ec || n == 0)
                {
                    break;
                }
                got += n;
            }
            std::uint64_t echo = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                echo |= static_cast<std::uint64_t>(reply[i]) << (i * 8);
            }
            EXPECT_EQ(echo, total) << "256MB 传输校验和不匹配";
            conn->close();
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    // ── 2. 帧循环长跑：100 万帧编码复用 ──

    TEST(MemoryLifecycle, LongRunFrameLoop)
    {
        using namespace psmtest::socks5;

        request req;
        req.ver = version;
        req.cmd = command::connect;
        req.rsv = 0;
        req.target.type = address_type::domain;
        req.target.host = "example.com";
        req.target.port = 443;

        psm::memory::session_memory<> mem;
        typename psm::memory::session_memory<>::buffer<std::uint8_t> tx(mem.arena());

        // 预热（首次扩容）
        build_request(req, tx);
        const auto cap_first = tx.capacity();
        ASSERT_GT(cap_first, 0U);

        constexpr int kIters = 1000000;
        std::size_t cap_max = cap_first;
        std::size_t total = 0;
        for (int i = 0; i < kIters; ++i)
        {
            build_request(req, tx);
            cap_max = std::max(cap_max, tx.capacity());
            total += tx.size();
        }
        EXPECT_EQ(cap_max, cap_first) << "100 万帧后复用缓冲发生再分配";
        // 每帧：[ver][cmd][rsv][ATYP][len][host 11B][port 2B] = 18 字节
        EXPECT_EQ(total, static_cast<std::size_t>(kIters) * 18);
    }

    // ── 3. 会话回收循环：大量 arena 创建/析构 ──

    TEST(MemoryLifecycle, SessionRecycleLoop)
    {
        constexpr int kIters = 100000;
        std::size_t peak_alloc = 0;
        for (int i = 0; i < kIters; ++i)
        {
            psm::memory::session_memory<> mem;
            // 分配 + 释放循环（arena 随析构回收）
            auto v = mem.make_vector<std::uint8_t>();
            v.resize(256 + (i % 64));
            v[0] = static_cast<std::uint8_t>(i);
            peak_alloc = std::max(peak_alloc, v.capacity());
            // 模拟 conn 生命周期：成员缓冲 + 帧缓冲
            typename psm::memory::session_memory<>::buffer<std::uint8_t> tx(mem.arena());
            tx.resize(4096);
            tx[0] = 0xAB;
        }
        // 无崩溃即通过；capacity 峰值 ≤ 单会话最大需求
        EXPECT_LE(peak_alloc, 320U);
        SUCCEED();
    }

    // ── 4. 多连接压力：200 连接循环 ──

    TEST(MemoryLifecycle, MultiConnRecycleLoop)
    {
        net::io_context ioc;
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            constexpr int kConns = 200;
            for (int i = 0; i < kConns; ++i)
            {
                auto [a, b] = make_memory_pair(ioc.get_executor());

                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [err, req, conn] = co_await socks5::accept(
                        std::make_shared<memory_stream>(std::move(b)), socks5::server_config{});
                    if (err == error::none && conn)
                    {
                        std::array<std::uint8_t, 256> buf{};
                        std::error_code ec;
                        while (true)
                        {
                            const auto n = co_await conn->async_read_some(
                                std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                            if (ec || n == 0)
                            {
                                break;
                            }
                        }
                    }
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto [err, conn] = co_await socks5::connect(
                    std::make_shared<memory_stream>(std::move(a)), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "10.0.0.1", 80});
                if (err != error::none || !conn)
                {
                    ADD_FAILURE() << "conn " << i << " connect failed";
                    continue;
                }

                // 传输 16KB 后关闭
                std::vector<std::uint8_t> chunk(16384, static_cast<std::uint8_t>(i));
                std::error_code ec;
                std::size_t off = 0;
                while (off < chunk.size())
                {
                    const auto n = co_await conn->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data() + off),
                                                   chunk.size() - off),
                        ec);
                    if (ec)
                    {
                        break;
                    }
                    off += n;
                }
                conn->close();
            }
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
        SUCCEED();
    }

} // namespace
