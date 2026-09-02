/**
 * @file Socks5TcpE2ETest.cpp
 * @brief SOCKS5 TCP CONNECT 真实纵向链路测试（阶段 5 v2 补缺）
 * @details 覆盖：
 *          - 真实 TCP listener → Session → adapter::MakeAcceptSocks5 →
 *            Dial → PostDial(success) → relay → echo 上游
 *          - CONNECT 应答「拨号后发送」：上游拒绝时客户端收到 connection_refused
 *          - runtime 传给 Dial 的目标地址与客户端请求一致
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::RunCoro;
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::StartTcpEchoUpstream;

    /// SOCKS5 无认证 Greeting
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// SOCKS5 CONNECT 请求（domain）
    auto socks5_connect_request(const std::string &host, std::uint16_t port) -> std::string
    {
        std::string req;
        req.push_back(0x05); // version
        req.push_back(0x01); // CONNECT
        req.push_back(0x00); // reserved
        req.push_back(0x03); // atyp domain
        req.push_back(static_cast<char>(host.size()));
        req += host;
        req.push_back(static_cast<char>((port >> 8) & 0xff));
        req.push_back(static_cast<char>(port & 0xff));
        return req;
    }

    /// 读取 SOCKS5 应答并返回 rep 字段
    /// @note 使用 AsyncRead 读满固定长度，避免半包；错误/EOF 时直接返回
    auto read_socks5_reply(SharedTransmission Conn, std::uint8_t &rep) -> net::awaitable<void>
    {
        std::array<std::byte, 4> head{};
        std::error_code ec;
        const auto n = co_await Conn->AsyncRead(head, ec);
        if (ec || n < 4)
        {
            co_return;
        }
        rep = static_cast<std::uint8_t>(head[1]);
        // 跳过 BND.ADDR + BND.PORT
        const auto atyp = static_cast<std::uint8_t>(head[3]);
        std::size_t skip = 2;
        if (atyp == 0x01)
        {
            skip += 4;
        }
        else if (atyp == 0x04)
        {
            skip += 16;
        }
        else if (atyp == 0x03)
        {
            std::array<std::byte, 1> len{};
            const auto ln = co_await Conn->AsyncRead(len, ec);
            if (ec || ln < 1)
            {
                co_return;
            }
            skip += static_cast<std::size_t>(static_cast<std::uint8_t>(len[0]));
        }
        std::vector<std::byte> rest(skip);
        if (!rest.empty())
        {
            co_await Conn->AsyncRead(rest, ec);
        }
    }

    /// SOCKS5 TCP 链路用例结果
    struct socks5_chain_result
    {
        std::string echo;                 ///< 回显数据
        std::uint8_t rep{0xff};           ///< CONNECT 应答码
    };

    /// 组装 SOCKS5 TCP 会话 listener（识别 → adapter → Dial）
    auto make_socks5_listener(net::io_context &ioc, std::uint16_t echo_port, bool refused)
        -> Preview::Runtime::TcpListener
    {
        return Preview::Runtime::TcpListener(
            ioc.get_executor(),
            [&, echo_port, refused](Preview::SharedTransmission Inbound, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(500);
                Socks5::ServerConfig scfg;
                scfg.EnableTcp = true;
                opts.AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(std::move(scfg));
                opts.Dial = [&](const Preview::Network::Target &t) -> net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    // 目标必须是客户端请求的地址
                    EXPECT_EQ(t.Host, "example.com");
                    EXPECT_EQ(t.Port, "443");
                    if (refused)
                    {
                        co_return std::pair{Preview::Fault::Code::ConnectionRefused, nullptr};
                    }
                    std::error_code ec;
                    Preview::Network::Dialer::Dialer d(ioc.get_executor());
                    auto Conn = co_await d.Connect("127.0.0.1", echo_port, ec);
                    if (ec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            },
            1);
    }

    /// 运行一条 SOCKS5 TCP CONNECT 链路
    /// @param refused 为 true 时 Dial 返回 connection_refused
    auto run_socks5_connect(bool refused) -> socks5_chain_result
    {
        net::io_context ioc;
        const auto echo_port = StartTcpEchoUpstream(ioc);
        auto listener = make_socks5_listener(ioc, echo_port, refused);

        socks5_chain_result out;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         co_return;
                     }

                     // 1. Greeting → Method Reply
                     const auto Greeting = socks5_greeting();
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()), ec);
                     if (ec)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     std::array<std::byte, 2> mrep{};
                     const auto mn = co_await Conn->AsyncRead(mrep, ec);
                     if (ec || mn < 2)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     EXPECT_EQ(static_cast<std::uint8_t>(mrep[0]), 0x05);
                     EXPECT_EQ(static_cast<std::uint8_t>(mrep[1]), 0x00);

                     // 2. CONNECT 请求 → 应答（拨号后发送）
                     const auto req = socks5_connect_request("example.com", 443);
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(req.data()), req.size()), ec);
                     if (!ec)
                     {
                         co_await read_socks5_reply(Conn, out.rep);
                     }

                     // 3. 回显往返（仅拨号成功时）
                     if (!refused && !ec)
                     {
                         const std::string payload = "socks5-e2e-payload";
                         co_await Conn->AsyncWrite(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
                         std::array<std::byte, 64> rbuf{};
                         std::error_code rec;
                         const auto rn = co_await Conn->AsyncRead(std::span<std::byte>(rbuf).first(payload.size()), rec);
                         out.echo.assign(reinterpret_cast<const char *>(rbuf.data()), rn);
                     }

                     Conn->Close();
                     // 让 relay 收尾（不依赖 ioc.Stop 打断在途协程）
                     net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(30));
                     boost::system::error_code tec;
                     co_await timer.async_wait(net::redirect_error(net::use_awaitable, tec));
                     listener.Stop();
                 });
        return out;
    }

    TEST(Socks5TcpChain, FullConnectEcho)
    {
        const auto r = run_socks5_connect(false);
        EXPECT_EQ(r.rep, static_cast<std::uint8_t>(Socks5::ReplyCode::Success));
        EXPECT_EQ(r.echo, "socks5-e2e-payload");
    }

    TEST(Socks5TcpChain, DialRefusedMapsToConnectionRefused)
    {
        const auto r = run_socks5_connect(true);
        EXPECT_EQ(r.rep, static_cast<std::uint8_t>(Socks5::ReplyCode::ConnectionRefused));
        EXPECT_TRUE(r.echo.empty());
    }


    TEST(Socks5TcpChain, ReplyWriteFailureAfterClientDisconnect)
    {
        // A-2 回归：客户端 CONNECT 后立即断开，服务端慢拨号完成后应答写在已关闭连接上，
        // 必须记录错误并收口，不能静默丢失也不得挂起。
        net::io_context ioc;

        boost::asio::ip::tcp::acceptor echo_acceptor(
            ioc, net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor.async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(ioc.get_executor(), TcpEchoServer(std::move(sock)), net::detached);
                }
            },
            net::detached);

        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                Socks5::ServerConfig scfg;
                scfg.EnableTcp = true;
                opts.AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(std::move(scfg));
                opts.Dial = [&](const Preview::Network::Target &)
                    -> net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    // 慢拨号：确保客户端已断开后再发送 CONNECT 应答
                    net::steady_timer slow(ioc.get_executor(), std::chrono::milliseconds(200));
                    boost::system::error_code sec;
                    co_await slow.async_wait(net::redirect_error(net::use_awaitable, sec));
                    std::error_code dec;
                    Preview::Network::Dialer::Dialer d(ioc.get_executor());
                    auto Conn = co_await d.Connect("127.0.0.1", echo_port, dec);
                    if (dec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            },
            1);

        bool completed = false;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(
                         net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         listener.Stop();
                         co_return;
                     }

                     // Greeting → Method Reply
                     const auto Greeting = socks5_greeting();
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(Greeting.data()),
                             Greeting.size()),
                         ec);
                     if (ec)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }
                     std::array<std::byte, 2> mrep{};
                     const auto mn = co_await Conn->AsyncRead(mrep, ec);
                     if (ec || mn < 2)
                     {
                         Conn->Close();
                         listener.Stop();
                         co_return;
                     }

                     // CONNECT 请求后立即断开
                     const auto req = socks5_connect_request("example.com", 443);
                     co_await Conn->AsyncWrite(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(req.data()),
                             req.size()),
                         ec);
                     Conn->Close();

                     // 等待服务端完成慢拨号 + 应答写失败收口
                     net::steady_timer t(ioc.get_executor(), std::chrono::milliseconds(500));
                     boost::system::error_code tec;
                     co_await t.async_wait(net::redirect_error(net::use_awaitable, tec));
                     completed = true;
                     listener.Stop();
                 });
        EXPECT_TRUE(completed);
    }
} // namespace
