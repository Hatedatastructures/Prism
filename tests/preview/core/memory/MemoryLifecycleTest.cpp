/**
 * @file MemoryLifecycleTest.cpp
 * @brief 资源指针全生命周期长跑测试
 * @details 验证内存策略在协议处理整个生命周期的稳定性：
 * 1. 单连接长跑：一个 Conn 会话内持续传输大流量（256MB），
 *    校验数据完整 + 复用缓冲 Capacity 稳定（零再分配）
 * 2. 帧循环长跑：100 万帧编码复用，Capacity 不变
 * 3. 会话回收循环：大量 Conn 生命周期创建/析构（Arena 正确回收）
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

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    /// 简单校验和（避免大哈希开销）
    auto checksum(std::span<const std::uint8_t> Data) -> std::uint64_t
    {
        std::uint64_t sum = 0;
        for (const auto b : Data)
        {
            sum = sum * 31 + b;
        }
        return sum;
    }

    // ── 1. 单连接长跑：256MB 传输 + 复用缓冲稳定性 ──

    TEST(MemoryLifecycle, LongRunSingleConnTransfer)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
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
                auto [err, req, Conn] = co_await Socks5::Accept(
                    std::make_shared<MemoryStream>(std::move(b)), Socks5::ServerConfig{});
                if (err != Error::None || !Conn)
                {
                    co_return;
                }
                std::array<std::uint8_t, kChunk> buf{};
                std::uint64_t Total = 0;
                std::size_t Done = 0;
                while (Done < kTotal)
                {
                    std::error_code ec;
                    const auto n = co_await Conn->async_read_some(
                        std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    Total += checksum(std::span<const std::uint8_t>(buf).first(n));
                    Done += n;
                }
                // 回显校验和（8 字节）
                std::array<std::uint8_t, 8> Reply{};
                for (std::size_t i = 0; i < 8; ++i)
                {
                    Reply[i] = static_cast<std::uint8_t>((Total >> (i * 8)) & 0xFF);
                }
                std::error_code ec;
                co_await Conn->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Reply.data()), Reply.size()),
                    ec);
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            // 客户端：发送数据并收集校验和
            auto [err, Conn] = co_await Socks5::Connect(
                std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                Socks5::Address{Socks5::AddressType::Domain, "Target.example", 443});

            if (err != Error::None || !Conn)
            {
                ADD_FAILURE() << "Client Connect Failed";
                co_return;
            }

            std::vector<std::uint8_t> chunk(kChunk);
            for (std::size_t i = 0; i < chunk.size(); ++i)
            {
                chunk[i] = static_cast<std::uint8_t>(i * 7 + (i >> 8));
            }
            std::uint64_t Total = 0;
            for (std::size_t c = 0; c < kChunks; ++c)
            {
                std::error_code ec;
                std::size_t off = 0;
                while (off < kChunk)
                {
                    const auto n = co_await Conn->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data() + off),
                                                   kChunk - off),
                        ec);
                    if (ec)
                    {
                        ADD_FAILURE() << "Write Failed at chunk " << c;
                        break;
                    }
                    off += n;
                }
                Total += checksum(chunk);
            }

            // 读取服务端回显的校验和
            std::array<std::uint8_t, 8> Reply{};
            std::size_t got = 0;
            std::error_code ec;
            while (got < 8)
            {
                const auto n = co_await Conn->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Reply.data() + got), 8 - got), ec);
                if (ec || n == 0)
                {
                    break;
                }
                got += n;
            }
            std::uint64_t echo = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                echo |= static_cast<std::uint64_t>(Reply[i]) << (i * 8);
            }
            EXPECT_EQ(echo, Total) << "256MB 传输校验和不匹配";
            Conn->Close();
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
        using namespace Preview::Socks5;

        Request req;
        req.Ver = Version;
        req.Cmd = Command::Connect;
        req.Rsv = 0;
        req.Target.Type = AddressType::Domain;
        req.Target.Host = "example.com";
        req.Target.Port = 443;

        Preview::Memory::SessionResource<> mem;
        typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> tx(mem.Arena());

        // 预热（首次扩容）
        BuildRequest(req, tx);
        const auto cap_first = tx.capacity();
        ASSERT_GT(cap_first, 0U);

        constexpr int kIters = 1000000;
        std::size_t cap_max = cap_first;
        std::size_t Total = 0;
        for (int i = 0; i < kIters; ++i)
        {
            BuildRequest(req, tx);
            cap_max = std::max(cap_max, tx.capacity());
            Total += tx.size();
        }
        EXPECT_EQ(cap_max, cap_first) << "100 万帧后复用缓冲发生再分配";
        // 每帧：[ver][cmd][rsv][ATYP][len][host 11B][port 2B] = 18 字节
        EXPECT_EQ(Total, static_cast<std::size_t>(kIters) * 18);
    }

    // ── 3. 会话回收循环：大量 Arena 创建/析构 ──

    TEST(MemoryLifecycle, SessionRecycleLoop)
    {
        constexpr int kIters = 100000;
        std::size_t peak_alloc = 0;
        for (int i = 0; i < kIters; ++i)
        {
            Preview::Memory::SessionResource<> mem;
            // 分配 + 释放循环（Arena 随析构回收）
            auto v = mem.MakeVector<std::uint8_t>();
            v.resize(256 + (i % 64));
            v[0] = static_cast<std::uint8_t>(i);
            peak_alloc = std::max(peak_alloc, v.capacity());
            // 模拟 Conn 生命周期：成员缓冲 + 帧缓冲
            typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> tx(mem.Arena());
            tx.resize(4096);
            tx[0] = 0xAB;
        }
        // 无崩溃即通过；Capacity 峰值 ≤ 单会话最大需求
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
                auto [a, b] = MakeMemoryPair(ioc.get_executor());

                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [err, req, Conn] = co_await Socks5::Accept(
                        std::make_shared<MemoryStream>(std::move(b)), Socks5::ServerConfig{});
                    if (err == Error::None && Conn)
                    {
                        std::array<std::uint8_t, 256> buf{};
                        std::error_code ec;
                        while (true)
                        {
                            const auto n = co_await Conn->async_read_some(
                                std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
                            if (ec || n == 0)
                            {
                                break;
                            }
                        }
                    }
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto [err, Conn] = co_await Socks5::Connect(
                    std::make_shared<MemoryStream>(std::move(a)), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "10.0.0.1", 80});
                if (err != Error::None || !Conn)
                {
                    ADD_FAILURE() << "Conn " << i << " Connect Failed";
                    continue;
                }

                // 传输 16KB 后关闭
                std::vector<std::uint8_t> chunk(16384, static_cast<std::uint8_t>(i));
                std::error_code ec;
                std::size_t off = 0;
                while (off < chunk.size())
                {
                    const auto n = co_await Conn->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(chunk.data() + off),
                                                   chunk.size() - off),
                        ec);
                    if (ec)
                    {
                        break;
                    }
                    off += n;
                }
                Conn->Close();
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
