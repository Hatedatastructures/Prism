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

#include <Preview/Net/Dns/Format.hpp>
#include <Preview/Net/Dns/Transport.hpp>
#include <Preview/Net/Dns/Upstream.hpp>
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
    namespace Net = boost::asio;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::Mode;
    using Preview::Network::Dns::Protocol;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::QueryResult;
    using Preview::Network::Dns::Server;
    using Preview::Network::Dns::Upstream;
    using Preview::Network::Dns::UpstreamOptions;

    using Net::ip::tcp;
    using Net::ip::udp;

    auto PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    auto PutU32(std::vector<std::uint8_t> &Output, const std::uint32_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 24));
        Output.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    /// 定位查询报文问题段结束偏移（QNAME + QTYPE + QCLASS）
    auto QuestionEnd(std::span<const std::uint8_t> Query) -> std::size_t
    {
        std::size_t Offset = 12;
        while (Offset < Query.size() && Query[Offset] != 0)
        {
            Offset += static_cast<std::size_t>(Query[Offset]) + 1;
        }
        return Offset + 5;
    }

    /// 构造应答（回显问题段 + 固定 A 记录 1.2.3.4 / 可配 Rcode）
    auto BuildResponse(std::span<const std::uint8_t> Query, const std::uint8_t Rcode = 0)
        -> std::vector<std::uint8_t>
    {
        const auto QEnd = QuestionEnd(Query);
        if (QEnd > Query.size())
        {
            return {};
        }
        const bool Full = Rcode == 0;
        std::vector<std::uint8_t> Output;
        PutU16(Output, static_cast<std::uint16_t>((Query[0] << 8) | Query[1]));
        PutU16(Output, 0x8180u | Rcode);
        PutU16(Output, 1);
        std::uint16_t AnswerCount = 0;
        if (Full)
        {
            AnswerCount = 1;
        }
        PutU16(Output, AnswerCount);
        PutU16(Output, 0);
        PutU16(Output, 0);
        Output.insert(Output.end(), Query.begin() + 12,
                      Query.begin() + static_cast<std::ptrdiff_t>(QEnd));
        if (Full)
        {
            PutU16(Output, 0xC00Cu);
            PutU16(Output, 1);
            PutU16(Output, 1);
            PutU32(Output, 60);
            PutU16(Output, 4);
            Output.insert(Output.end(), {1, 2, 3, 4});
        }
        return Output;
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

        FrameTcpServer(Net::io_context &Ioc, const Mode ServerMode = Mode::Loop)
            : Ex_(Ioc.get_executor()), Mode_(ServerMode),
              Acceptor_(Ioc, tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Acceptor_.local_endpoint().port();
            auto Self = shared_from_this();
            Net::co_spawn(Ex_, [Self]() { return Self->AcceptLoop(); }, Net::detached);
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
        auto AcceptLoop() -> Net::awaitable<void>
        {
            auto Self = shared_from_this();
            for (;;)
            {
                boost::system::error_code ec;
                auto Socket = std::make_shared<tcp::socket>(
                    co_await Acceptor_.async_accept(Net::redirect_error(Net::use_awaitable, ec)));
                if (ec)
                {
                    co_return;
                }
                ++ConnCount_;
                Net::co_spawn(Ex_, [Self, Socket]() { return Self->ConnLoop(Socket); }, Net::detached);
            }
        }

        auto ConnLoop(std::shared_ptr<tcp::socket> Socket) -> Net::awaitable<void>
        {
            for (;;)
            {
                std::array<std::uint8_t, 2> lenBuf{};
                boost::system::error_code ec;
                co_await Net::async_read(*Socket, Net::buffer(lenBuf),
                                         Net::redirect_error(Net::use_awaitable, ec));
                if (ec)
                {
                    co_return;
                }
                const auto Len = static_cast<std::size_t>((lenBuf[0] << 8) | lenBuf[1]);
                std::vector<std::uint8_t> body(Len);
                co_await Net::async_read(*Socket, Net::buffer(body),
                                         Net::redirect_error(Net::use_awaitable, ec));
                if (ec)
                {
                    co_return;
                }
                auto resp = BuildResponse(body);
                std::vector<std::uint8_t> frame;
                PutU16(frame, static_cast<std::uint16_t>(resp.size()));
                frame.insert(frame.end(), resp.begin(), resp.end());
                co_await Net::async_write(*Socket, Net::buffer(frame),
                                          Net::redirect_error(Net::use_awaitable, ec));
                if (ec || Mode_ == Mode::OneShot)
                {
                    co_return; // OneShot：应答后立即关闭，制造"池中连接已死"
                }
            }
        }

        Net::any_io_executor Ex_;
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
        RawUdpServer(Net::io_context &Ioc, const std::uint8_t Rcode)
            : Ex_(Ioc.get_executor()), Rcode_(Rcode),
              Udp_(Ioc, udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto Self = shared_from_this();
            Net::co_spawn(Ex_, [Self]() { return Self->Loop(); }, Net::detached);
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
        auto Loop() -> Net::awaitable<void>
        {
            std::vector<std::uint8_t> buf(4096);
            udp::endpoint sender;
            for (;;)
            {
                boost::system::error_code ec;
                const auto Count = co_await Udp_.async_receive_from(
                    Net::buffer(buf), sender, Net::redirect_error(Net::use_awaitable, ec));
                if (ec || Count < 12)
                {
                    co_return;
                }
                auto Response = BuildResponse({buf.data(), Count}, Rcode_);
                if (Response.empty())
                {
                    continue;
                }
                co_await Udp_.async_send_to(Net::buffer(Response), sender,
                                            Net::redirect_error(Net::use_awaitable, ec));
            }
        }

        Net::any_io_executor Ex_;
        std::uint8_t Rcode_;
        udp::socket Udp_;
        std::uint16_t Port_{0};
    };

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
} // namespace

TEST(DnsTransport, TestTcpPoolReusesConnection)
{
    // 同一服务器连续查询共享一条 TCP 连接（keep-alive 默认开启）
Net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::Loop);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult first;
    QueryResult second;
    RunCoro(ioc,
[&]() -> Net::awaitable<void>
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

TEST(DnsTransport, RejectsOversizedTcpFrameBeforeLengthEncoding)
{
    const std::vector<std::uint8_t> Maximum(Preview::Network::Dns::Detail::MaxFrameBytes, 0xA5);
    const std::vector<std::uint8_t> Oversized(Preview::Network::Dns::Detail::MaxFrameBytes + 1, 0xA5);

    const auto MaxFrame = Preview::Network::Dns::Detail::MakeTcpFrame(Maximum);
    ASSERT_TRUE(MaxFrame.has_value());
    EXPECT_EQ(MaxFrame->size(), Maximum.size() + 2);

    const auto OversizedFrame = Preview::Network::Dns::Detail::MakeTcpFrame(Oversized);
    ASSERT_FALSE(OversizedFrame.has_value());
    EXPECT_EQ(OversizedFrame.error(),
              boost::system::errc::make_error_code(boost::system::errc::message_size));
}

TEST(DnsTransport, TestKeepAliveOffDisablesPool)
{
    // KeepAlive=false：每查询新建连接，不入池
Net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::Loop);
    server->Start();

    auto cfg = server->MakeConfig();
    cfg.KeepAlive = false;
    Upstream up(ioc.get_executor(), {cfg});
    RunCoro(ioc,
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
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
Net::co_spawn(ioc,
[&]() -> Net::awaitable<void>
                  { (void)co_await up.Resolve("a.example.com", QType::A); },
                  [&](std::exception_ptr e)
                  {
                      if (e) { ep = e; }
                      if (++done == 2) { ioc.stop(); }
                  });
Net::co_spawn(ioc,
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
    auto server = std::make_shared<FrameTcpServer>(ioc, FrameTcpServer::Mode::OneShot);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult first;
    QueryResult second;
    RunCoro(ioc,
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
    Net::co_spawn(ioc, Preview::Testing::Tls::MockTlsServer::Run(acceptor, 1), Net::detached);

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
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
Net::co_spawn(ioc,
                  Preview::Testing::Tls::MockTlsServer::Run(
                      acceptor, 2, Preview::Testing::Tls::MakeDohResponder("HTTP/1.1 200 OK")),
                  Net::detached);

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
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0));
    const auto Port = acceptor.local_endpoint().port();
Net::co_spawn(ioc,
                  Preview::Testing::Tls::MockTlsServer::Run(
                      acceptor, 1, Preview::Testing::Tls::MakeDohResponder("HTTP/1.1 404 Not Found")),
                  Net::detached);

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
[&]() -> Net::awaitable<void>
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
Net::io_context ioc;
    auto servfail = std::make_shared<RawUdpServer>(ioc, 2);
    auto good = std::make_shared<RawUdpServer>(ioc, 0);
    servfail->Start();
    good->Start();

    Upstream up(ioc.get_executor(),
                {servfail->MakeConfig(), good->MakeConfig()}, Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
[&]() -> Net::awaitable<void>
            {
                result = co_await up.Resolve("sf.example.com", QType::A);
                servfail->Close();
                good->Close();
            });

    EXPECT_FALSE(result.Error);
    ASSERT_EQ(result.Ips.size(), 1u);
    EXPECT_EQ(result.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
}

TEST(DnsTransport, TestServfailAloneIsError)
{
    // 单 SERVFAIL 上游：结果为错误（不冒充"成功+空"进负缓存语义）
Net::io_context ioc;
    auto servfail = std::make_shared<RawUdpServer>(ioc, 2);
    servfail->Start();

    Upstream up(ioc.get_executor(), {servfail->MakeConfig()}, Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
[&]() -> Net::awaitable<void>
            {
                result = co_await up.Resolve("sf.example.com", QType::A);
                servfail->Close();
            });

    EXPECT_TRUE(result.Error);
    EXPECT_TRUE(result.Ips.empty());
}
