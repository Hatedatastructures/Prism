/**
 * @file DnsTransportTest.cpp
 * @brief DNS 传输层测试（连接池 + DoT/DoH 路径 + RCODE 语义）
 * @details 覆盖：
 *          - TCP 连接池复用（同服务器多查询单连接）、KeepAlive=false 退回
 *            每查询新建、池容量淘汰（MaxConnsPerServer=1）
 *          - DoT 池化复用（MockTlsServer 单连接限制反证复用生效）
 *          - DoH 正常应答（Responder 工厂构造 HTTP 200）与状态码拒绝
 *          - 复用连接被对端关闭后的一次新建重试（OneShot 服务器）
 *          - SERVFAIL（Rcode=2）为错误且 Fallback 继续下一上游
 * @note 全部走 127.0.0.1 回环，无外部网络依赖
 */

#include <preview/Net/Dns/Format.hpp>
#include <preview/Net/Dns/Upstream.hpp>
#include <TestSupport/Tls/MockTlsServer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::Mode;
    using Preview::Network::Dns::Protocol;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::QueryResult;
    using Preview::Network::Dns::Server;
    using Preview::Network::Dns::Upstream;
    using Preview::Network::Dns::UpstreamOptions;

    using net::ip::tcp;
    using net::ip::udp;

    void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    void PutU32(std::vector<std::uint8_t> &out, const std::uint32_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 24));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    /// 定位查询报文问题段结束偏移（QNAME + QTYPE + QCLASS）
    auto QuestionEnd(std::span<const std::uint8_t> query) -> std::size_t
    {
        std::size_t off = 12;
        while (off < query.size() && query[off] != 0)
        {
            off += static_cast<std::size_t>(query[off]) + 1;
        }
        return off + 5;
    }

    /// 构造应答（回显问题段 + 固定 A 记录 1.2.3.4 / 可配 Rcode）
    auto BuildResponse(std::span<const std::uint8_t> query, const std::uint8_t rcode = 0)
        -> std::vector<std::uint8_t>
    {
        const auto QEnd = QuestionEnd(query);
        if (QEnd > query.size())
        {
            return {};
        }
        const bool Full = rcode == 0;
        std::vector<std::uint8_t> out;
        PutU16(out, static_cast<std::uint16_t>((query[0] << 8) | query[1]));
        PutU16(out, 0x8180u | rcode);
        PutU16(out, 1);
        PutU16(out, Full ? 1u : 0u);
        PutU16(out, 0);
        PutU16(out, 0);
        out.insert(out.end(), query.begin() + 12,
                   query.begin() + static_cast<std::ptrdiff_t>(QEnd));
        if (Full)
        {
            PutU16(out, 0xC00Cu);
            PutU16(out, 1);
            PutU16(out, 1);
            PutU32(out, 60);
            PutU16(out, 4);
            out.insert(out.end(), {1, 2, 3, 4});
        }
        return out;
    }

    /**
     * @class FrameTcpServer
     * @brief 计连接数的帧式 TCP DNS 服务器（Loop = 常驻 / OneShot = 一问即断）
     */
    class FrameTcpServer : public std::enable_shared_from_this<FrameTcpServer>
    {
    public:
        enum class Mode
        {
            Loop,    ///< 一连接服务多次查询
            OneShot, ///< 一连接只答一次后关闭（模拟对端关闭 keep-alive 连接）
        };

        FrameTcpServer(net::io_context &ioc, const Mode mode = Mode::Loop)
            : Ex_(ioc.get_executor()), Mode_(mode),
              Acceptor_(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Acceptor_.local_endpoint().port();
            auto self = shared_from_this();
            net::co_spawn(Ex_, [self]() { return self->AcceptLoop(); }, net::detached);
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        [[nodiscard]] auto ConnCount() const -> std::size_t
        {
            return ConnCount_;
        }

        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server s;
            s.Address = "127.0.0.1";
            s.Port = Port_;
            s.Proto = Protocol::Tcp;
            s.TimeoutMs = 2000;
            return s;
        }

        void Close()
        {
            boost::system::error_code ec;
            Acceptor_.close(ec);
        }

    private:
        auto AcceptLoop() -> net::awaitable<void>
        {
            auto self = shared_from_this();
            for (;;)
            {
                boost::system::error_code ec;
                auto sock = std::make_shared<tcp::socket>(
                    co_await Acceptor_.async_accept(net::redirect_error(net::use_awaitable, ec)));
                if (ec)
                {
                    co_return;
                }
                ++ConnCount_;
                net::co_spawn(Ex_, [self, sock]() { return self->ConnLoop(sock); }, net::detached);
            }
        }

        auto ConnLoop(std::shared_ptr<tcp::socket> sock) -> net::awaitable<void>
        {
            for (;;)
            {
                std::array<std::uint8_t, 2> lenBuf{};
                boost::system::error_code ec;
                co_await net::async_read(*sock, net::buffer(lenBuf),
                                         net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return;
                }
                const auto Len = static_cast<std::size_t>((lenBuf[0] << 8) | lenBuf[1]);
                std::vector<std::uint8_t> body(Len);
                co_await net::async_read(*sock, net::buffer(body),
                                         net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return;
                }
                auto resp = BuildResponse(body);
                std::vector<std::uint8_t> frame;
                PutU16(frame, static_cast<std::uint16_t>(resp.size()));
                frame.insert(frame.end(), resp.begin(), resp.end());
                co_await net::async_write(*sock, net::buffer(frame),
                                          net::redirect_error(net::use_awaitable, ec));
                if (ec || Mode_ == Mode::OneShot)
                {
                    co_return; // OneShot：应答后立即关闭，制造"池中连接已死"
                }
            }
        }

        net::any_io_executor Ex_;
        Mode Mode_;
        tcp::acceptor Acceptor_;
        std::uint16_t Port_{0};
        std::size_t ConnCount_{0};
    };

    /**
     * @class RawUdpServer
     * @brief 可配 Rcode 的 UDP DNS 服务器（SERVFAIL/Fallback 语义测试用）
     */
    class RawUdpServer : public std::enable_shared_from_this<RawUdpServer>
    {
    public:
        RawUdpServer(net::io_context &ioc, const std::uint8_t rcode)
            : Ex_(ioc.get_executor()), Rcode_(rcode),
              Udp_(ioc, udp::endpoint(net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto self = shared_from_this();
            net::co_spawn(Ex_, [self]() { return self->Loop(); }, net::detached);
        }

        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server s;
            s.Address = "127.0.0.1";
            s.Port = Port_;
            s.TimeoutMs = 2000;
            return s;
        }

        void Close()
        {
            boost::system::error_code ec;
            Udp_.close(ec);
        }

    private:
        auto Loop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> buf(4096);
            udp::endpoint sender;
            for (;;)
            {
                boost::system::error_code ec;
                const auto n = co_await Udp_.async_receive_from(
                    net::buffer(buf), sender, net::redirect_error(net::use_awaitable, ec));
                if (ec || n < 12)
                {
                    co_return;
                }
                auto resp = BuildResponse({buf.data(), n}, Rcode_);
                if (resp.empty())
                {
                    continue;
                }
                co_await Udp_.async_send_to(net::buffer(resp), sender,
                                            net::redirect_error(net::use_awaitable, ec));
            }
        }

        net::any_io_executor Ex_;
        std::uint8_t Rcode_;
        udp::socket Udp_;
        std::uint16_t Port_{0};
    };

    template <typename A>
    void RunCoro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

TEST(DnsTransport, TestTcpPoolReusesConnection)
{
    // 同一服务器连续查询共享一条 TCP 连接（keep-alive 默认开启）
    net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::Loop);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult first;
    QueryResult second;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                first = co_await up.Resolve("one.example.com", QType::A);
                second = co_await up.Resolve("two.example.com", QType::A);
                server->Close();
            });

    EXPECT_FALSE(first.Error);
    EXPECT_FALSE(second.Error);
    EXPECT_EQ(server->ConnCount(), 1u); // 两次查询仅一条连接
    EXPECT_EQ(up.IdleConnCount(), 1u);  // 用毕归还池中
}

TEST(DnsTransport, TestKeepAliveOffDisablesPool)
{
    // KeepAlive=false：每查询新建连接，不入池
    net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::Loop);
    server->Start();

    auto cfg = server->MakeConfig();
    cfg.KeepAlive = false;
    Upstream up(ioc.get_executor(), {cfg});
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                (void)co_await up.Resolve("one.example.com", QType::A);
                (void)co_await up.Resolve("two.example.com", QType::A);
                server->Close();
            });

    EXPECT_EQ(server->ConnCount(), 2u);
    EXPECT_EQ(up.IdleConnCount(), 0u);
}

TEST(DnsTransport, TestPoolCapacityEviction)
{
    // MaxConnsPerServer=1：并发两查询各建一连接，归还后仅保留 1 条闲置
    net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::Loop);
    server->Start();

    UpstreamOptions options;
    options.Servers = {server->MakeConfig()};
    options.QueryMode = Mode::Fastest;
    options.DefaultTimeout = std::chrono::milliseconds{4000};
    options.MaxConnsPerServer = 1;
    Upstream up(ioc.get_executor(), std::move(options));
    std::exception_ptr ep;
    int done = 0;
    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { (void)co_await up.Resolve("a.example.com", QType::A); },
                  [&](std::exception_ptr e)
                  {
                      if (e) { ep = e; }
                      if (++done == 2) { ioc.stop(); }
                  });
    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { (void)co_await up.Resolve("b.example.com", QType::A); },
                  [&](std::exception_ptr e)
                  {
                      if (e) { ep = e; }
                      if (++done == 2) { ioc.stop(); }
                  });
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }

    EXPECT_EQ(server->ConnCount(), 2u); // 并发期各建一条
    EXPECT_EQ(up.IdleConnCount(), 1u);  // 容量 1 → 只留一条
    server->Close();
}

TEST(DnsTransport, TestStalePoolConnRetriedOnce)
{
    // OneShot 服务器：首次查询后关闭连接；第二次查询从池中取到"已死"连接，
    // 复用失败自动新建重试一次并最终成功
    net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::OneShot);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult first;
    QueryResult second;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                first = co_await up.Resolve("one.example.com", QType::A);
                second = co_await up.Resolve("two.example.com", QType::A);
                server->Close();
            });

    EXPECT_FALSE(first.Error);
    EXPECT_FALSE(second.Error);
    EXPECT_EQ(server->ConnCount(), 2u); // 死连接复用失败 → 新建第二条
}

TEST(DnsTransport, TestTlsPoolReuse)
{
    // MockTlsServer 限制 MaxConnections=1：若第二次查询未复用连接，
    // 服务器已退出 accept → 必失败；两查询均成功即证明池化复用
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
    net::co_spawn(ioc, Preview::Testing::Tls::MockTlsServer::Run(acceptor, 1), net::detached);

    Preview::Network::Dns::Server cfg;
    cfg.Address = "127.0.0.1";
    cfg.Port = Port;
    cfg.Proto = Protocol::Tls;
    cfg.Hostname = "127.0.0.1";
    cfg.SkipCertCheck = true;
    cfg.TimeoutMs = 2000;

    Upstream up(ioc.get_executor(), {cfg});
    QueryResult first;
    QueryResult second;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                first = co_await up.Resolve("one.example.com", QType::A);
                second = co_await up.Resolve("two.example.com", QType::A);
                acceptor.close();
            });

    EXPECT_EQ(first.Error, boost::system::error_code{});
    EXPECT_EQ(second.Error, boost::system::error_code{});
}

TEST(DnsTransport, TestDohStatus200WithResponder)
{
    // Responder 工厂回真实 HTTP 200 + DNS 应答体：状态码校验、
    // Content-Length 头区解析、报文体收满全链路
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
    net::co_spawn(ioc,
                  Preview::Testing::Tls::MockTlsServer::Run(
                      acceptor, 2, Preview::Testing::Tls::MakeDohResponder("HTTP/1.1 200 OK")),
                  net::detached);

    Preview::Network::Dns::Server cfg;
    cfg.Address = "127.0.0.1";
    cfg.Port = Port;
    cfg.Proto = Protocol::Https;
    cfg.Hostname = "127.0.0.1";
    cfg.SkipCertCheck = true;
    cfg.TimeoutMs = 2000;

    Upstream up(ioc.get_executor(), {cfg});
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("doh.example.com", QType::A);
                acceptor.close();
            });

    // 应答体是查询回显：Id 匹配、Rcode=0、零应答记录 → 成功 + 空 IP
    EXPECT_EQ(result.Error, boost::system::error_code{});
    EXPECT_TRUE(result.Ips.empty());
}

TEST(DnsTransport, TestDohStatusRejection)
{
    // HTTP 404 → BadMessage，不当作有效应答
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
    net::co_spawn(ioc,
                  Preview::Testing::Tls::MockTlsServer::Run(
                      acceptor, 1, Preview::Testing::Tls::MakeDohResponder("HTTP/1.1 404 Not Found")),
                  net::detached);

    Preview::Network::Dns::Server cfg;
    cfg.Address = "127.0.0.1";
    cfg.Port = Port;
    cfg.Proto = Protocol::Https;
    cfg.Hostname = "127.0.0.1";
    cfg.SkipCertCheck = true;
    cfg.TimeoutMs = 2000;

    Upstream up(ioc.get_executor(), {cfg});
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("doh.example.com", QType::A);
                acceptor.close();
            });

    EXPECT_TRUE(result.Error);
    EXPECT_TRUE(result.Ips.empty());
}

TEST(DnsTransport, TestServfailFallsThroughInFallbackMode)
{
    // SERVFAIL（Rcode=2）为明确拒绝：Fallback 跳过它继续下一个上游
    net::io_context ioc;
    auto servfail = std::make_shared<RawUdpServer>(ioc, 2);
    auto good = std::make_shared<RawUdpServer>(ioc, 0);
    servfail->Start();
    good->Start();

    Upstream up(ioc.get_executor(),
                {servfail->MakeConfig(), good->MakeConfig()}, Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("sf.example.com", QType::A);
                servfail->Close();
                good->Close();
            });

    EXPECT_FALSE(result.Error);
    ASSERT_EQ(result.Ips.size(), 1u);
    EXPECT_EQ(result.Ips[0], net::ip::make_address_v4("1.2.3.4"));
}

TEST(DnsTransport, TestServfailAloneIsError)
{
    // 单 SERVFAIL 上游：结果为错误（不冒充"成功+空"进负缓存语义）
    net::io_context ioc;
    auto servfail = std::make_shared<RawUdpServer>(ioc, 2);
    servfail->Start();

    Upstream up(ioc.get_executor(), {servfail->MakeConfig()}, Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("sf.example.com", QType::A);
                servfail->Close();
            });

    EXPECT_TRUE(result.Error);
    EXPECT_TRUE(result.Ips.empty());
}
