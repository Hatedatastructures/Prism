/**
 * @file DnsResolverTest.cpp
 * @brief DNS 解析器测试（T3-3）
 * @details 覆盖：
 *          - LRU 缓存命中/未命中（loopback 域名）
 *          - 负缓存（不可解析域名）
 *          - 缓存过期（短 TTL）
 *          - LRU 淘汰（容量限制）
 * @note 测试用真实 Resolver（本地 hosts/loopback），避免外部网络
 */

#include <common/Core/Net/Dns/Resolver.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Config;

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.restart(); // 清除上一次 stop() 状态，使后续 run() 真正执行新协程
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

TEST(DnsResolver, ResolveLoopback)
{
    net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    std::error_code ec;
    std::vector<net::ip::address> addrs;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("localhost", ec);
             });
    EXPECT_FALSE(ec);
    EXPECT_FALSE(addrs.empty());
    // localhost 解析到 127.0.0.1（或 ::1）
    EXPECT_GE(addrs.size(), 1u);
}

TEST(DnsResolver, CacheHit)
{
    net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    std::error_code firstEc;
    std::error_code secondEc;
    std::vector<net::ip::address> first;
    std::vector<net::ip::address> second;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 first = co_await r.AsyncResolve("localhost", firstEc);
                 second = co_await r.AsyncResolve("localhost", secondEc);
             });
    ASSERT_FALSE(firstEc);
    ASSERT_FALSE(first.empty());
    ASSERT_FALSE(secondEc);
    EXPECT_EQ(second, first);
    EXPECT_EQ(r.HitCount(), 1u);
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, NegativeCache)
{
    net::io_context ioc;
    Config cfg;
    cfg.MaxCacheEntries = 64;
    cfg.CacheTtl = std::chrono::seconds(60);
    cfg.NegativeTtl = std::chrono::seconds(10);
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.AsyncResolve("nonexistent-host-prism-test.invalid", ec);
             });
    EXPECT_TRUE(ec);
    // 负缓存已入
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, CacheExpiry)
{
    net::io_context ioc;
    // 极短 TTL（1 秒）
    Config cfg;
    cfg.MaxCacheEntries = 64;
    cfg.CacheTtl = std::chrono::seconds(1);
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.AsyncResolve("localhost", ec);
             });
    ASSERT_FALSE(ec);
    EXPECT_EQ(r.Size(), 1u);

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.AsyncResolve("localhost", ec);
             });
    // 过期后未命中缓存 → 重新解析，缓存条目被替换
    ASSERT_FALSE(ec);
    EXPECT_EQ(r.HitCount(), 0u);
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, CacheCapacityBounded)
{
    net::io_context ioc;
    // 容量 2
    Config cfg;
    cfg.MaxCacheEntries = 2;
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.AsyncResolve("localhost", ec);
                 (void)co_await r.AsyncResolve("127.0.0.1", ec);
                 (void)co_await r.AsyncResolve("127.0.0.2", ec);
             });
    // 三个唯一 key 写入容量为 2 的缓存后，条目数必须有界。
    EXPECT_EQ(r.Size(), 2u);
}

TEST(DnsResolver, ClearCache)
{
    net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.AsyncResolve("localhost", ec);
             });
    EXPECT_EQ(r.Size(), 1u);
    r.Clear();
    EXPECT_EQ(r.Size(), 0u);
}

using Preview::Network::Dns::Resolver;
using Preview::Network::Dns::Server;
using Preview::Network::Dns::StalePolicy;

/// 本地回环 UDP DNS 服务器（Answer/NxDomain/Silent），带查询计数
class MiniDnsServer : public std::enable_shared_from_this<MiniDnsServer>
{
public:
    enum class Behavior
    {
        Answer,      ///< 返回固定地址记录（TTL 60s）
        MixedAnswer, ///< A/AAAA 返回不同 TTL 的地址记录
        NxDomain,    ///< 返回 NXDOMAIN（Rcode=3，零应答）
        Silent,      ///< 收到查询不应答
    };

    MiniDnsServer(net::io_context &ioc, const Behavior behavior, const std::uint32_t ttlSec = 60)
        : Ex_(ioc.get_executor()), Behavior_(behavior), TtlSec_(ttlSec),
          Udp_(ioc, net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0))
    {
    }

    void Start()
    {
        Port_ = Udp_.local_endpoint().port();
        Addr_ = Udp_.local_endpoint().address().to_string();
        auto self = shared_from_this();
        net::co_spawn(Ex_, [self]() { return self->Loop(); }, net::detached);
    }

    /// 构造对应 Resolver 上游配置
    [[nodiscard]] auto MakeConfig() const -> Server
    {
        Server s;
        s.Address = Addr_;
        s.Port = Port_;
        return s;
    }

    [[nodiscard]] auto QueryCount() const -> std::size_t
    {
        return QueryCount_;
    }

    void Close()
    {
        Stopped_ = true;
        boost::system::error_code ec;
        Udp_.close(ec);
    }

private:
    static void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    static void PutU32(std::vector<std::uint8_t> &out, const std::uint32_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 24));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    auto Loop() -> net::awaitable<void>
    {
        std::vector<std::uint8_t> buf(4096);
        net::ip::udp::endpoint sender;
        for (;;)
        {
            boost::system::error_code ec;
            const auto n = co_await Udp_.async_receive_from(
                net::buffer(buf), sender, net::redirect_error(net::use_awaitable, ec));
            if (ec || Stopped_ || n < 12)
            {
                co_return;
            }
            ++QueryCount_;
            if (Behavior_ == Behavior::Silent)
            {
                continue;
            }
            // 定位问题段结束（QNAME + QTYPE + QCLASS）
            std::size_t off = 12;
            while (off < static_cast<std::size_t>(n) && buf[off] != 0)
            {
                off += static_cast<std::size_t>(buf[off]) + 1;
            }
            const auto QEnd = off + 5;
            if (QEnd > static_cast<std::size_t>(n))
            {
                continue;
            }
            const bool Nx = Behavior_ == Behavior::NxDomain;
            const auto QueryType = static_cast<std::uint16_t>((buf[off + 1] << 8) | buf[off + 2]);
            const bool Aaaa = QueryType == 28;
            const bool Full = Behavior_ == Behavior::Answer || Behavior_ == Behavior::MixedAnswer;
            std::vector<std::uint8_t> out;
            PutU16(out, static_cast<std::uint16_t>((buf[0] << 8) | buf[1])); // 回显 Id
            PutU16(out, 0x8180u | (Nx ? 0x0003u : 0u));                      // QR|RD|RA (+Rcode=3)
            PutU16(out, 1);
            PutU16(out, Full ? 1u : 0u);
            PutU16(out, 0);
            PutU16(out, 0);
            out.insert(out.end(), buf.begin() + 12,
                       buf.begin() + static_cast<std::ptrdiff_t>(QEnd));
            if (Full)
            {
                PutU16(out, 0xC00Cu); // 压缩指针指向问题段名字
                PutU16(out, Aaaa ? 28 : 1); // type A / AAAA
                PutU16(out, 1);       // class IN
                const auto Ttl = Behavior_ == Behavior::MixedAnswer
                                     ? (Aaaa ? 1u : 60u)
                                     : TtlSec_;
                PutU32(out, Ttl);
                if (Aaaa)
                {
                    PutU16(out, 16);
                    // 使用文档保留地址，避免把未指定地址 :: 混入地址族合并测试。
                    out.insert(out.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1});
                }
                else
                {
                    PutU16(out, 4); // rdlength
                    out.insert(out.end(), {1, 2, 3, 4});
                }
            }
            (void)co_await Udp_.async_send_to(
                net::buffer(out), sender, net::redirect_error(net::use_awaitable, ec));
        }
    }

    net::any_io_executor Ex_;
    Behavior Behavior_;
    std::uint32_t TtlSec_{60};
    net::ip::udp::socket Udp_;
    std::uint16_t Port_{0};
    std::string Addr_;
    std::size_t QueryCount_{0};
    bool Stopped_{false};
};

TEST(DnsResolver, NxDomainNegativeCachedNoRetry)
{
    // 1.3 端到端验证：NXDOMAIN 被负缓存；二次解析不再打上游
    net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::NxDomain);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    Resolver r(ioc.get_executor(), cfg);

    std::error_code ec;
    std::vector<net::ip::address> addrs;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("nx.local", ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_TRUE(addrs.empty());
    EXPECT_EQ(r.Size(), 1u); // 负缓存已入

    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("nx.local", ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(server->QueryCount(), 1u); // 负缓存命中，不再打上游
    server->Close();
}

TEST(DnsResolver, CacheTtlUsesShortestAddressFamily)
{
    net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::MixedAnswer);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    Resolver r(ioc.get_executor(), cfg);

    std::error_code ec;
    std::vector<net::ip::address> addrs;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("ttl.local", ec);
             });
    ASSERT_FALSE(ec);
    ASSERT_EQ(addrs.size(), 2u);
    EXPECT_EQ(server->QueryCount(), 2u);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("ttl.local", ec);
             });

    EXPECT_FALSE(ec);
    EXPECT_EQ(server->QueryCount(), 4u);
    server->Close();
}

TEST(DnsResolver, ConcurrentSingleFlight)
{
    // 并发同域名解析：single-flight 使上游查询只发生一次（A 族 leader 唯一）
    net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::Answer);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    Resolver r(ioc.get_executor(), cfg);

    constexpr int N = 4;
    std::vector<std::vector<net::ip::address>> results(N);
    std::vector<std::error_code> ecs(N);
    std::exception_ptr ep;
    int done = 0;
    for (int i = 0; i < N; ++i)
    {
        net::co_spawn(ioc,
                      [&, i]() -> net::awaitable<void>
                      {
                          results[static_cast<std::size_t>(i)] =
                              co_await r.AsyncResolve("burst.local", ecs[static_cast<std::size_t>(i)]);
                      },
                      [&](std::exception_ptr e)
                      {
                          if (e)
                          {
                              ep = e;
                          }
                          if (++done == N)
                          {
                              ioc.stop();
                          }
                      });
    }
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }

    EXPECT_EQ(server->QueryCount(), 1u); // 4 个并发请求只打了一次上游
    for (int i = 0; i < N; ++i)
    {
        EXPECT_FALSE(ecs[static_cast<std::size_t>(i)]);
        ASSERT_EQ(results[static_cast<std::size_t>(i)].size(), 1u);
        EXPECT_EQ(results[static_cast<std::size_t>(i)][0], net::ip::make_address("1.2.3.4"));
    }
    server->Close();
}

TEST(DnsResolver, ServeStaleEndToEnd)
{
    // serve-stale 端到端：缓存过期后仍返回旧数据，且不打上游
    net::io_context ioc;
    auto server = std::make_shared<MiniDnsServer>(ioc, MiniDnsServer::Behavior::Answer, 1);
    server->Start();

    Config cfg;
    cfg.Servers = {server->MakeConfig()};
    cfg.DisableIpv6 = true;
    cfg.CacheTtl = std::chrono::seconds(1);
    cfg.CachePolicy = StalePolicy::Serve;
    Resolver r(ioc.get_executor(), cfg);

    std::error_code ec;
    std::vector<net::ip::address> addrs;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.AsyncResolve("stale.local", ec);
             });
    ASSERT_EQ(addrs.size(), 1u);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    std::vector<net::ip::address> stale;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 stale = co_await r.AsyncResolve("stale.local", ec);
             });
    ASSERT_EQ(stale.size(), 1u);
    EXPECT_EQ(stale[0], addrs[0]);          // 过期后仍返回旧数据
    EXPECT_EQ(server->QueryCount(), 1u);    // 未再打上游
    server->Close();
}
