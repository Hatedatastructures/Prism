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

#include <common/core/authenticator.hpp>
#include <common/protocols/http1/conn.hpp>
#include <common/protocols/http1/parser.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/transport/reliable.hpp>

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
    using tcp = net::ip::tcp;
    using namespace preview;

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
    preview::http11::http_request req;
    const auto rc = preview::http11::parse_request(raw, req);
    EXPECT_EQ(rc, preview::fault::code::success);
    EXPECT_EQ(req.method, "CONNECT");
    EXPECT_EQ(req.target, "example.com:443");
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
    preview::http11::http_request req;
    const auto rc = preview::http11::parse_request(raw, req);
    EXPECT_EQ(rc, preview::fault::code::success);
    EXPECT_EQ(req.host, "host:80");
    EXPECT_EQ(req.authorization, "Basic abc");
}

TEST(Http11Connect, ParseMalformed)
{
    preview::http11::http_request req;
    // 缺请求行
    EXPECT_EQ(preview::http11::parse_request("GET\r\n\r\n", req), preview::fault::code::parse_error);
    // 缺头结束
    EXPECT_EQ(preview::http11::parse_request("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n", req),
              preview::fault::code::parse_error);
    // 空数据
    EXPECT_EQ(preview::http11::parse_request("", req), preview::fault::code::parse_error);
}

TEST(Http11Connect, ParseStatusCode)
{
    EXPECT_EQ(preview::http11::parse_status_code("HTTP/1.1 200 Connection Established\r\n\r\n"), 200);
    EXPECT_EQ(preview::http11::parse_status_code("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), 407);
    EXPECT_EQ(preview::http11::parse_status_code("garbage"), 0);
}

TEST(Http11Connect, MakeConnectRequest)
{
    const auto req = preview::http11::make_connect_request("example.com", 443);
    EXPECT_TRUE(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    EXPECT_TRUE(req.find("Host: example.com:443\r\n") != std::string::npos);
    EXPECT_EQ(req.find("Proxy-Authorization"), std::string::npos);

    const auto with_auth = preview::http11::make_connect_request("h", 80, "Basic dXNlcjpwYXNz");
    EXPECT_TRUE(with_auth.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != std::string::npos);
}

TEST(Http11Connect, CheckBasicAuth)
{
    // user:pass 的 base64
    constexpr std::string_view auth_ok = "Basic dXNlcjpwYXNz";
    constexpr std::string_view auth_bad = "Basic dXNlcjpiYWQ=";
    const preview::static_authenticator auth("user", "pass");

    auto ok = preview::http11::check_basic(auth_ok, auth);
    EXPECT_TRUE(ok.ok);
    EXPECT_EQ(ok.identity, "user");

    EXPECT_FALSE(preview::http11::check_basic(auth_bad, auth).ok);
    EXPECT_FALSE(preview::http11::check_basic("Bearer token", auth).ok);
    EXPECT_FALSE(preview::http11::check_basic("", auth).ok);
}

TEST(Http11Connect, HandshakeOkE2E)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    shared_transmission client;
    int status = 0;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         auto transport = preview::transport::make_reliable(std::move(sock));
                         preview::http11::server_conn server(transport);
                         preview::http11::http_request req;
                         const auto rc = co_await server.read_request(req);
                         if (rc == preview::fault::code::success && req.method == "CONNECT")
                         {
                             co_await server.send_response(preview::http11::status::ok);
                         }
                     },
                     net::detached);

                 client = co_await preview::network::dialer::dialer(ioc.get_executor()).connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await preview::http11::send_connect(client, "example.com", 443);
                     status = co_await preview::http11::read_response(client, ec);
                 }
             });
    EXPECT_FALSE(ec);
    EXPECT_EQ(status, 200);
}

TEST(Http11Connect, AuthRequired407)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    const preview::static_authenticator auth("user", "pass");
    std::error_code ec;
    shared_transmission client;
    int status_no_auth = 0;
    int status_ok = 0;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 // server：循环 accept 两次，按凭据决定 407/200
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         for (int round = 0; round < 2; ++round)
                         {
                             auto sock = co_await acceptor.async_accept(net::use_awaitable);
                             auto transport = preview::transport::make_reliable(std::move(sock));
                             preview::http11::server_conn server(transport);
                             preview::http11::http_request req;
                             const auto rc = co_await server.read_request(req);
                             if (rc == preview::fault::code::success)
                             {
                                 const auto ar = preview::http11::check_basic(req.authorization, auth);
                                 co_await server.send_response(ar.ok ? preview::http11::status::ok
                                                                     : preview::http11::status::proxy_auth_required);
                             }
                         }
                     },
                     net::detached);

                 // 连接 1：无凭据 → 407
                 client = co_await preview::network::dialer::dialer(ioc.get_executor()).connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await preview::http11::send_connect(client, "example.com", 443);
                     status_no_auth = co_await preview::http11::read_response(client, ec);
                     client->close();
                 }
                 // 连接 2：正确凭据 → 200
                 client = co_await preview::network::dialer::dialer(ioc.get_executor()).connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await preview::http11::send_connect(client, "example.com", 443, "Basic dXNlcjpwYXNz");
                     status_ok = co_await preview::http11::read_response(client, ec);
                     client->close();
                 }
             });
    EXPECT_EQ(status_no_auth, 407);
    EXPECT_EQ(status_ok, 200);
}

TEST(Http11Connect, BadRequest400)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    shared_transmission client;
    std::string reply;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         auto transport = preview::transport::make_reliable(std::move(sock));
                         preview::http11::server_conn server(transport);
                         preview::http11::http_request req;
                         const auto rc = co_await server.read_request(req);
                         co_await server.send_response(rc == preview::fault::code::success
                                                           ? preview::http11::status::ok
                                                           : preview::http11::status::bad_request);
                     },
                     net::detached);

                 client = co_await preview::network::dialer::dialer(ioc.get_executor()).connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     // 畸形请求（缺方法名）
                     const std::string bad = "\r\n\r\n";
                     co_await client->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(bad.data()),
                                                    bad.size()),
                         ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await client->async_read_some(buf, ec);
                     reply.assign(reinterpret_cast<const char *>(buf.data()), n);
                 }
             });
    EXPECT_TRUE(reply.starts_with("HTTP/1.1 400"));
}

TEST(Http11Connect, TunnelBidirectional)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    shared_transmission client;
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
                         auto transport = preview::transport::make_reliable(std::move(sock));
                         preview::http11::server_conn server(transport);
                         preview::http11::http_request req;
                         const auto rc = co_await server.read_request(req);
                         if (rc == preview::fault::code::success)
                         {
                             co_await server.send_response(preview::http11::status::ok);
                             // 隧道模式：echo 一次（用 transport，sock 已被 move）
                             std::array<std::byte, 128> buf{};
                             std::error_code r_ec;
                             const auto n = co_await transport->async_read_some(buf, r_ec);
                             if (n > 0)
                             {
                                 co_await transport->async_write_some(
                                     std::span<const std::byte>(buf.data(), n), r_ec);
                             }
                         }
                     },
                     net::detached);

                 client = co_await preview::network::dialer::dialer(ioc.get_executor()).connect("127.0.0.1", port, ec);
                 if (!ec)
                 {
                     co_await preview::http11::send_connect(client, "example.com", 443);
                     status = co_await preview::http11::read_response(client, ec);
                     // 隧道数据
                     const std::string msg = "tunnel-echo";
                     co_await client->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                    msg.size()),
                         ec);
                     std::array<std::byte, 128> buf{};
                     const auto n = co_await client->async_read_some(buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                 }
             });
    EXPECT_EQ(status, 200);
    EXPECT_EQ(echo_back, "tunnel-echo");
}
