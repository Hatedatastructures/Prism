/**
 * @file Http11ConnectTest.cpp
 * @brief HTTP/1.1 CONNECT 站点协议测试（T3-5 / D4）
 * @details 覆盖：
 *          - CONNECT 请求解析（方法/目标/Host/Proxy-Authorization）
 *          - 客户端请求构造与响应状态码提取
 *          - Basic 认证（407/200）
 *          - CONNECT E2E：握手 + 隧道双向转发
 *          - 异常路径：畸形请求 400 / 读失败
 */

#include <common/Core/Authenticator.hpp>
#include <common/Protocols/Http1/Conn.hpp>
#include <common/Protocols/Http1/Parser.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Transport/Reliable.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
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

TEST(Http11Connect, ParseRequestOk)
{
    const std::string raw = "CONNECT example.com:443 HTTP/1.1\r\n"
                            "Host: example.com:443\r\n"
                            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                            "User-Agent: test\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest req;
    const auto rc = Preview::Http11::ParseRequest(raw, req);
    EXPECT_EQ(rc, Preview::Fault::Code::success);
    EXPECT_EQ(req.Method, "CONNECT");
    EXPECT_EQ(req.Target, "example.com:443");
    EXPECT_EQ(req.version, "HTTP/1.1");
    EXPECT_EQ(req.host, "example.com:443");
    EXPECT_EQ(req.authorization, "Basic dXNlcjpwYXNz");
}

TEST(Http11Connect, ParseCaseInsensitiveHeaders)
{
    const std::string raw = "CONNECT host:80 HTTP/1.1\r\n"
                            "hOsT: host:80\r\n"
                            "PrOxY-aUtHoRiZaTiOn: Basic abc\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest req;
    const auto rc = Preview::Http11::ParseRequest(raw, req);
    EXPECT_EQ(rc, Preview::Fault::Code::success);
    EXPECT_EQ(req.host, "host:80");
    EXPECT_EQ(req.authorization, "Basic abc");
}

TEST(Http11Connect, ParseMalformed)
{
    Preview::Http11::HttpRequest req;
    // 缺请求行
    EXPECT_EQ(Preview::Http11::ParseRequest("GET\r\n\r\n", req), Preview::Fault::Code::parse_error);
    // 缺头结束
    EXPECT_EQ(Preview::Http11::ParseRequest("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n", req),
              Preview::Fault::Code::parse_error);
    // 空数据
    EXPECT_EQ(Preview::Http11::ParseRequest("", req), Preview::Fault::Code::parse_error);
}

TEST(Http11Connect, ParseStatusCode)
{
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 200 Connection Established\r\n\r\n"), 200);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), 407);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("garbage"), 0);
}

TEST(Http11Connect, MakeConnectRequest)
{
    const auto req = Preview::Http11::MakeConnectRequest("example.com", 443);
    EXPECT_TRUE(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    EXPECT_TRUE(req.find("Host: example.com:443\r\n") != std::string::npos);
    EXPECT_EQ(req.find("Proxy-Authorization"), std::string::npos);

    const auto with_auth = Preview::Http11::MakeConnectRequest("h", 80, "Basic dXNlcjpwYXNz");
    EXPECT_TRUE(with_auth.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != std::string::npos);
}

TEST(Http11Connect, CheckBasicAuth)
{
    // user:pass 的 base64
    constexpr std::string_view auth_ok = "Basic dXNlcjpwYXNz";
    constexpr std::string_view auth_bad = "Basic dXNlcjpiYWQ=";
    const Preview::StaticAuthenticator Auth("user", "pass");

    auto Ok = Preview::Http11::CheckBasic(auth_ok, Auth);
    EXPECT_TRUE(Ok.Ok);
    EXPECT_EQ(Ok.identity, "user");

    EXPECT_FALSE(Preview::Http11::CheckBasic(auth_bad, Auth).Ok);
    EXPECT_FALSE(Preview::Http11::CheckBasic("Bearer token", Auth).Ok);
    EXPECT_FALSE(Preview::Http11::CheckBasic("", Auth).Ok);
}

TEST(Http11Connect, HandshakeOkE2E)
{
    net::io_context ioc;
    Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    SharedTransmission Client;
    int status = 0;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         auto transport = Preview::Transport::make_reliable(std::move(sock));
                         Preview::Http11::ServerConn Server(transport);
                         Preview::Http11::HttpRequest req;
                         const auto rc = co_await Server.ReadRequest(req);
                         if (rc == Preview::Fault::Code::success && req.Method == "CONNECT")
                         {
                             co_await Server.SendResponse(Preview::Http11::status::Ok);
                         }
                     },
                     net::detached);

                 Client = co_await Preview::Network::Dialer::Dialer(ioc.get_executor()).Connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await Preview::Http11::SendConnect(Client, "example.com", 443);
                     status = co_await Preview::Http11::ReadResponse(Client, ec);
                 }
             });
    EXPECT_FALSE(ec);
    EXPECT_EQ(status, 200);
}

TEST(Http11Connect, AuthRequired407)
{
    net::io_context ioc;
    Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    const Preview::StaticAuthenticator Auth("user", "pass");
    std::error_code ec;
    SharedTransmission Client;
    int status_no_auth = 0;
    int status_ok = 0;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 // Server：循环 Accept 两次，按凭据决定 407/200
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         for (int round = 0; round < 2; ++round)
                         {
                             auto sock = co_await acceptor.async_accept(net::use_awaitable);
                             auto transport = Preview::Transport::make_reliable(std::move(sock));
                             Preview::Http11::ServerConn Server(transport);
                             Preview::Http11::HttpRequest req;
                             const auto rc = co_await Server.ReadRequest(req);
                             if (rc == Preview::Fault::Code::success)
                             {
                                 const auto ar = Preview::Http11::CheckBasic(req.authorization, Auth);
                                 co_await Server.SendResponse(ar.Ok ? Preview::Http11::status::Ok
                                                                     : Preview::Http11::status::ProxyAuthRequired);
                             }
                         }
                     },
                     net::detached);

                 // 连接 1：无凭据 → 407
                 Client = co_await Preview::Network::Dialer::Dialer(ioc.get_executor()).Connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await Preview::Http11::SendConnect(Client, "example.com", 443);
                     status_no_auth = co_await Preview::Http11::ReadResponse(Client, ec);
                     Client->Close();
                 }
                 // 连接 2：正确凭据 → 200
                 Client = co_await Preview::Network::Dialer::Dialer(ioc.get_executor()).Connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await Preview::Http11::SendConnect(Client, "example.com", 443, "Basic dXNlcjpwYXNz");
                     status_ok = co_await Preview::Http11::ReadResponse(Client, ec);
                     Client->Close();
                 }
             });
    EXPECT_EQ(status_no_auth, 407);
    EXPECT_EQ(status_ok, 200);
}

TEST(Http11Connect, BadRequest400)
{
    net::io_context ioc;
    Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    SharedTransmission Client;
    std::string Reply;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         auto transport = Preview::Transport::make_reliable(std::move(sock));
                         Preview::Http11::ServerConn Server(transport);
                         Preview::Http11::HttpRequest req;
                         const auto rc = co_await Server.ReadRequest(req);
                         co_await Server.SendResponse(rc == Preview::Fault::Code::success
                                                           ? Preview::Http11::status::Ok
                                                           : Preview::Http11::status::BadRequest);
                     },
                     net::detached);

                 Client = co_await Preview::Network::Dialer::Dialer(ioc.get_executor()).Connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     // 畸形请求（缺方法名）
                     const std::string bad = "\r\n\r\n";
                     co_await Client->AsyncWriteSome(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(bad.data()),
                                                    bad.size()),
                         ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await Client->AsyncReadSome(buf, ec);
                     Reply.assign(reinterpret_cast<const char *>(buf.data()), n);
                 }
             });
    EXPECT_TRUE(Reply.starts_with("HTTP/1.1 400"));
}

TEST(Http11Connect, TunnelBidirectional)
{
    net::io_context ioc;
    Tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    SharedTransmission Client;
    int status = 0;
    std::string echo_back;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         auto transport = Preview::Transport::make_reliable(std::move(sock));
                         Preview::Http11::ServerConn Server(transport);
                         Preview::Http11::HttpRequest req;
                         const auto rc = co_await Server.ReadRequest(req);
                         if (rc == Preview::Fault::Code::success)
                         {
                             co_await Server.SendResponse(Preview::Http11::status::Ok);
                             // 隧道模式：echo 一次（用 transport，sock 已被 move）
                             std::array<std::byte, 128> buf{};
                             std::error_code r_ec;
                             const auto n = co_await transport->AsyncReadSome(buf, r_ec);
                             if (n > 0)
                             {
                                 co_await transport->AsyncWriteSome(
                                     std::span<const std::byte>(buf.data(), n), r_ec);
                             }
                         }
                     },
                     net::detached);

                 Client = co_await Preview::Network::Dialer::Dialer(ioc.get_executor()).Connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await Preview::Http11::SendConnect(Client, "example.com", 443);
                     status = co_await Preview::Http11::ReadResponse(Client, ec);
                     // 隧道数据
                     const std::string msg = "tunnel-echo";
                     co_await Client->AsyncWriteSome(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                    msg.size()),
                         ec);
                     std::array<std::byte, 128> buf{};
                     const auto n = co_await Client->AsyncReadSome(buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                 }
             });
    EXPECT_EQ(status, 200);
    EXPECT_EQ(echo_back, "tunnel-echo");
}
