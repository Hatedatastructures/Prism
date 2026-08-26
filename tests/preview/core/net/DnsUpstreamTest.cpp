/**
 * @file DnsUpstreamTest.cpp
 * @brief DNS 上游查询层测试（本地 fake DNS server）
 * @details 内置回环 UDP/TCP fake DNS server（可配置应答/空应答/截断/静默/
 *          延迟行为），覆盖：UDP 查询成功、TC 截断回退 TCP、Fallback 顺序
 *          容错、First 按序首胜、Fastest RTT 选优、超时失败
 * @note 全部走 127.0.0.1/127.0.0.2 回环，无外部网络依赖
 */

#include <common/Core/Net/Dns/Format.hpp>
#include <common/Core/Net/Dns/Upstream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <chrono>
#include <span>
#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::QueryResult;
    using Preview::Network::Dns::Server;
    using Preview::Network::Dns::Upstream;

    using net::ip::tcp;
    using net::ip::udp;

    /// 大端写入 16 位整数
    void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    /**
     * @class FakeDnsServer
     * @brief 回环 fake DNS 服务器（UDP 必备，Truncate 行为附加 TCP）
     */
    class FakeDnsServer : public std::enable_shared_from_this<FakeDnsServer>
    {
    public:
        enum class Behavior
        {
            Answer,    ///< 正常返回固定 A 记录
            EmptyAnswer, ///< 返回合法但零应答报文（模拟无记录）
            Truncate,  ///< UDP 回 TC=1，TCP 回完整应答
            Silent,    ///< 收到查询不应答（触发客户端超时）
        };

        FakeDnsServer(net::io_context &ioc, const Behavior behavior,
                      std::chrono::milliseconds delay = std::chrono::milliseconds(0))
            : Ex_(ioc.get_executor()), Behavior_(behavior), Delay_(delay),
              Udp_(ioc, udp::endpoint(net::ip::make_address("127.0.0.1"), 0))
        {
        }

        /// 绑定端口并启动收发循环；Truncate 行为同时监听 TCP
        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            Addr_ = Udp_.local_endpoint().address().to_string();
            auto self = shared_from_this();
            net::co_spawn(Ex_, [self]() { return self->UdpLoop(); }, net::detached);
            if (Behavior_ == Behavior::Truncate)
            {
                Acceptor_.emplace(Ex_, tcp::endpoint(Udp_.local_endpoint().address(), Port_));
                net::co_spawn(Ex_, [self]() { return self->AcceptLoop(); }, net::detached);
            }
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        /// Server.Address 形式的地址串（用于断言响应来源）
        [[nodiscard]] auto Addr() const -> const std::string &
        {
            return Addr_;
        }

        /// 构造对应 Upstream 配置项
        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server s;
            s.Address = Addr_;
            s.Port = Port_;
            return s;
        }

        /// 停止服务：关闭套接字使挂起协程以 operation_aborted 退出
        void Close()
        {
            Stopped_ = true;
            boost::system::error_code ec;
            Udp_.close(ec);
            if (Acceptor_)
            {
                Acceptor_->close(ec);
            }
            for (auto &conn : Conns_)
            {
                conn->close(ec);
            }
        }

    private:
        /// 解析查询报文中问题段结束偏移（跳过 QNAME + QTYPE + QCLASS）
        [[nodiscard]] static auto QuestionEnd(std::span<const std::uint8_t> query)
            -> std::size_t
        {
            std::size_t off = 12;
            while (off < query.size() && query[off] != 0)
            {
                off += static_cast<std::size_t>(query[off]) + 1;
            }
            return off + 5;
        }

        /// 构造应答报文（回显问题段 + 固定 A 记录 1.2.3.4）
        [[nodiscard]] auto BuildResponse(std::span<const std::uint8_t> query,
                                         const bool truncate) const -> std::vector<std::uint8_t>
        {
            const auto QEnd = QuestionEnd(query);
            if (QEnd > query.size())
            {
                return {};
            }
            std::vector<std::uint8_t> out;
            const bool Full = !truncate && Behavior_ != Behavior::EmptyAnswer;
            PutU16(out, static_cast<std::uint16_t>((query[0] << 8) | query[1]));
            // QR|RD|RA (+TC)
            PutU16(out, 0x8180u | (truncate ? 0x0200u : 0u));
            PutU16(out, 1);              // qdcount
            PutU16(out, Full ? 1u : 0u); // ancount
            PutU16(out, 0);
            PutU16(out, 0);
            out.insert(out.end(), query.begin() + 12, query.begin() + static_cast<std::ptrdiff_t>(QEnd));
            if (Full)
            {
                PutU16(out, 0xC00Cu); // 压缩指针指向问题段名字
                PutU16(out, 1);       // type A
                PutU16(out, 1);       // class IN
                PutU32Ttl(out);
                PutU16(out, 4);       // rdlength
                out.insert(out.end(), {1, 2, 3, 4});
            }
            return out;
        }

        void PutU32Ttl(std::vector<std::uint8_t> &out) const
        {
            out.push_back(0);
            out.push_back(0);
            out.push_back(0);
            out.push_back(60);
        }

        /// 延迟后发送（模拟慢上游，供 Fastest RTT 选优测试区分）
        auto MaybeDelay() -> net::awaitable<void>
        {
            if (Delay_.count() > 0)
            {
                net::steady_timer t(Ex_);
                t.expires_after(Delay_);
                co_await t.async_wait(net::use_awaitable);
            }
        }

        auto UdpLoop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> buf(4096);
            udp::endpoint sender;
            for (;;)
            {
                boost::system::error_code ec;
                const auto n = co_await Udp_.async_receive_from(
                    net::buffer(buf), sender,
                    net::redirect_error(net::use_awaitable, ec));
                if (ec || Stopped_ || n < 12)
                {
                    co_return;
                }
                const bool truncate = Behavior_ == Behavior::Truncate;
                if (Behavior_ == Behavior::Silent)
                {
                    continue;
                }
                co_await MaybeDelay();
                if (Stopped_)
                {
                    co_return;
                }
                auto resp = BuildResponse({buf.data(), n}, truncate);                if (resp.empty())
                {
                    continue;
                }
                (void)co_await Udp_.async_send_to(
                    net::buffer(resp), sender,
                    net::redirect_error(net::use_awaitable, ec));
            }
        }

        auto AcceptLoop() -> net::awaitable<void>
        {
            for (;;)
            {
                boost::system::error_code ec;
                auto sock = std::make_shared<tcp::socket>(
                    co_await Acceptor_->async_accept(
                        net::redirect_error(net::use_awaitable, ec)));
                if (ec || Stopped_)
                {
                    co_return;
                }
                Conns_.push_back(sock);
                auto self = shared_from_this();
                net::co_spawn(Ex_,
                              [self, sock]() { return self->TcpConn(sock); },
                              net::detached);
            }
        }

        auto TcpConn(std::shared_ptr<tcp::socket> sock) -> net::awaitable<void>
        {
            for (;;)
            {
                std::array<std::uint8_t, 2> lenBuf{};
                boost::system::error_code ec;
                co_await net::async_read(*sock, net::buffer(lenBuf),
                                         net::redirect_error(net::use_awaitable, ec));
                if (ec || Stopped_)
                {
                    co_return;
                }
                const auto Len = static_cast<std::size_t>((lenBuf[0] << 8) | lenBuf[1]);
                std::vector<std::uint8_t> body(Len);
                co_await net::async_read(*sock, net::buffer(body),
                                         net::redirect_error(net::use_awaitable, ec));
                if (ec || Stopped_)
                {
                    co_return;
                }
                co_await MaybeDelay();
                auto resp = BuildResponse(body, false);
                std::vector<std::uint8_t> frame;
                PutU16(frame, static_cast<std::uint16_t>(resp.size()));
                frame.insert(frame.end(), resp.begin(), resp.end());
                (void)co_await net::async_write(*sock, net::buffer(frame),
                                                net::redirect_error(net::use_awaitable, ec));
            }
        }

        net::any_io_executor Ex_;
        Behavior Behavior_;
        std::chrono::milliseconds Delay_;
        udp::socket Udp_;
        std::optional<tcp::acceptor> Acceptor_; ///< 仅 Truncate 行为使用
        std::vector<std::shared_ptr<tcp::socket>> Conns_;
        std::uint16_t Port_{0};
        std::string Addr_;
        bool Stopped_{false};
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

TEST(DnsUpstream, TestUdpQuerySuccess)
{
    net::io_context ioc;
    auto server = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("example.com", QType::A);
                server->Close();
            });

    EXPECT_FALSE(result.Error);
    ASSERT_EQ(result.Ips.size(), 1u);
    EXPECT_EQ(result.Ips[0], net::ip::make_address_v4("1.2.3.4"));
    EXPECT_EQ(result.ServerAddr, server->Addr());
    EXPECT_EQ(result.Response.MinTtl(), 60u);
}

TEST(DnsUpstream, TestTruncatedFallsBackToTcp)
{
    net::io_context ioc;
    auto server = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Truncate);
    server->Start();

    Upstream up(ioc.get_executor(), {server->MakeConfig()});
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("big.example.com", QType::A);
                server->Close();
            });

    // UDP TC=1 → 自动改走 TCP 取得完整应答
    EXPECT_FALSE(result.Error);
    ASSERT_EQ(result.Ips.size(), 1u);
    EXPECT_EQ(result.Ips[0], net::ip::make_address_v4("1.2.3.4"));
}

TEST(DnsUpstream, TestFallbackSkipsFailedServer)
{
    net::io_context ioc;
    auto empty = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::EmptyAnswer);
    auto good = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer);
    empty->Start();
    good->Start();

    Upstream up(ioc.get_executor(),
                {empty->MakeConfig(), good->MakeConfig()},
                Preview::Network::Dns::Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("fallback.com", QType::A);
                empty->Close();
                good->Close();
            });

    // 首个上游零应答视为失败 → 顺序尝试第二个
    EXPECT_FALSE(result.Error);
    ASSERT_EQ(result.Ips.size(), 1u);
    EXPECT_EQ(result.ServerAddr, good->Addr());
}

TEST(DnsUpstream, TestFirstReturnsInServerOrder)
{
    net::io_context ioc;
    // 首个上游故意延迟：First 策略仍按服务器顺序取首个成功者
    auto slow = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer,
                                                std::chrono::milliseconds(50));
    auto fast = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer);
    slow->Start();
    fast->Start();

    Upstream up(ioc.get_executor(),
                {slow->MakeConfig(), fast->MakeConfig()},
                Preview::Network::Dns::Mode::First);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("first.com", QType::A);
                slow->Close();
                fast->Close();
            });

    EXPECT_FALSE(result.Error);
    EXPECT_EQ(result.ServerAddr, slow->Addr());
}

TEST(DnsUpstream, TestFastestPicksLowerRtt)
{
    net::io_context ioc;
    auto instant = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer);
    auto sluggish = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Answer,
                                                    std::chrono::milliseconds(200));
    instant->Start();
    sluggish->Start();

    Upstream up(ioc.get_executor(),
                {sluggish->MakeConfig(), instant->MakeConfig()},
                Preview::Network::Dns::Mode::Fastest);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("fastest.com", QType::A);
                instant->Close();
                sluggish->Close();
            });

    // Fastest 等全部完成后选 RTT 最低者
    EXPECT_FALSE(result.Error);
    EXPECT_EQ(result.ServerAddr, instant->Addr());
}

TEST(DnsUpstream, TestTimeoutOnSilentServer)
{
    net::io_context ioc;
    auto silent = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Silent);
    silent->Start();

    Server cfg = silent->MakeConfig();
    cfg.TimeoutMs = 300;
    Upstream up(ioc.get_executor(), {cfg});
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("silent.com", QType::A);
                silent->Close();
            });

    EXPECT_TRUE(result.Error);
    EXPECT_TRUE(result.Ips.empty());
}

TEST(DnsUpstream, TestAllServersFail)
{
    net::io_context ioc;
    auto a = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::EmptyAnswer);
    auto b = std::make_shared<FakeDnsServer>(ioc, FakeDnsServer::Behavior::Silent);
    a->Start();
    b->Start();

    Server bCfg = b->MakeConfig();
    bCfg.TimeoutMs = 200;
    Upstream up(ioc.get_executor(), {a->MakeConfig(), bCfg},
                Preview::Network::Dns::Mode::Fallback);
    QueryResult result;
    RunCoro(ioc,
            [&]() -> net::awaitable<void>
            {
                result = co_await up.Resolve("none.com", QType::A);
                a->Close();
                b->Close();
            });

    EXPECT_TRUE(result.Error);
    EXPECT_TRUE(result.Ips.empty());
}
