/**
 * @file E2E.cpp
 * @brief 端到端集成测试
 * @details 验证完整代理会话生命周期中各协议的全链路处理：
 * 1. SOCKS5 全链路 echo (E2ESocks5Echo)
 * 2. HTTP CONNECT 全链路 echo (E2EHttpConnectEcho)
 * 3. SOCKS5 用户名/密码认证 (E2ESocks5Auth)
 * 4. HTTP 407 认证挑战 (E2EHttpAuth407)
 * 5. 多连接并发 (E2EConcurrency)
 */

#include <prism/runtime/config.hpp>
#include <prism/config/config.hpp>
#include <prism/resource/session.hpp>
#include <prism/account/directory.hpp>
#include <prism/runtime/session/session.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/foundation/exception/network.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <format>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

namespace agent = psm::runtime;

namespace
{

// ============================================================
// 辅助协程
// ============================================================

net::awaitable<void> EchoServer(tcp::acceptor acceptor)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    std::array<char, 8192> buf{};
    while (true)
    {
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec || n == 0)
        {
            break;
        }
        co_await net::async_write(socket, net::buffer(buf.data(), n), token);
        if (ec)
        {
            break;
        }
    }
}

net::awaitable<void> MultiEchoServer(tcp::acceptor acceptor, const int count)
{
    for (int i = 0; i < count; ++i)
    {
        boost::system::error_code accept_ec;
        auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
        tcp::socket socket = co_await acceptor.async_accept(accept_token);
        if (accept_ec)
        {
            co_return;
        }

        net::co_spawn(co_await net::this_coro::executor, [sock = std::move(socket)]() mutable -> net::awaitable<void>
                      {
                          std::array<char, 8192> buf{};
                          while (true)
                          {
                              boost::system::error_code ec;
                              auto token = net::redirect_error(net::use_awaitable, ec);
                              const std::size_t n = co_await sock.async_read_some(net::buffer(buf), token);
                              if (ec || n == 0)
                              {
                                  break;
                              }
                              co_await net::async_write(sock, net::buffer(buf.data(), n), token);
                              if (ec)
                              {
                                  break;
                              }
                          } }, net::detached);
    }
}

net::awaitable<void> ProxyAcceptOne(tcp::acceptor acceptor, psm::resource::process &server_ctx,
                                    psm::resource::worker &worker_ctx)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }
    auto inbound = psm::transport::make_reliable(std::move(socket));

    psm::runtime::session::session_params params{server_ctx, worker_ctx, std::move(inbound)};
    auto session_ptr = psm::runtime::session::make_session(std::move(params));

    session_ptr->start();
}

net::awaitable<void> MultiProxyAccept(tcp::acceptor acceptor, const int count,
                                      psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    for (int i = 0; i < count; ++i)
    {
        boost::system::error_code accept_ec;
        auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
        tcp::socket socket = co_await acceptor.async_accept(accept_token);
        if (accept_ec)
        {
            co_return;
        }

        auto inbound = psm::transport::make_reliable(std::move(socket));
        psm::runtime::session::session_params params{server_ctx, worker_ctx, std::move(inbound)};
        auto session_ptr = psm::runtime::session::make_session(std::move(params));
        session_ptr->start();
    }
}

net::awaitable<void> EmitCancelAfter(std::shared_ptr<net::cancellation_signal> signal,
                                     const std::chrono::milliseconds timeout)
{
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(timeout);

    boost::system::error_code ec;
    auto token = net::redirect_error(net::use_awaitable, ec);
    co_await timer.async_wait(token);
    if (!ec)
    {
        signal->emit(net::cancellation_type::all);
    }
}

net::awaitable<void> WaitUntilTrue(std::shared_ptr<std::atomic_bool> flag,
                                   const std::chrono::milliseconds timeout)
{
    auto executor = co_await net::this_coro::executor;
    net::steady_timer timer(executor);

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag->load())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            throw psm::exception::network("timeout waiting for expected condition");
        }

        timer.expires_after(std::chrono::milliseconds(10));
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await timer.async_wait(token);
        if (ec)
        {
            co_return;
        }
    }
}

net::awaitable<std::string> ReadProxyConnectResponse(tcp::socket &socket)
{
    std::string response;
    response.reserve(256);
    std::array<char, 512> buf{};
    while (response.find("\r\n\r\n") == std::string::npos)
    {
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec)
        {
            throw psm::exception::network("proxy response read failed: " + ec.message());
        }
        if (n == 0)
        {
            throw psm::exception::network("proxy response eof");
        }
        response.append(buf.data(), n);
        if (response.size() > 8192)
        {
            throw psm::exception::network("proxy response too large");
        }
    }
    co_return response;
}

net::awaitable<std::string> ReadHttpResponse(tcp::socket &socket)
{
    co_return co_await ReadProxyConnectResponse(socket);
}

// ============================================================
// 客户端协程
// ============================================================

net::awaitable<void> RawSocks5ClientEcho(tcp::endpoint proxy_ep, tcp::endpoint echo_ep,
                                         const std::string_view tag, const std::string_view payload)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);

    // 方法协商: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
    constexpr std::array<std::uint8_t, 3> method_req = {0x05, 0x01, 0x00};
    co_await net::async_write(socket, net::buffer(method_req), net::use_awaitable);

    std::array<std::uint8_t, 2> method_resp{};
    co_await net::async_read(socket, net::buffer(method_resp), net::use_awaitable);
    if (method_resp[0] != 0x05 || method_resp[1] != 0x00)
    {
        throw psm::exception::network(std::format("{} method negotiation failed: {:02x} {:02x}",
                                                  tag, method_resp[0], method_resp[1]));
    }

    // CONNECT 请求: VER=5, CMD=1(CONNECT), RSV=0, ATYP=1(IPv4)
    const auto echo_addr = echo_ep.address().to_v4().to_bytes();
    const auto echo_port = echo_ep.port();
    std::array<std::uint8_t, 10> connect_req{};
    connect_req[0] = 0x05;
    connect_req[1] = 0x01;
    connect_req[2] = 0x00;
    connect_req[3] = 0x01;
    connect_req[4] = echo_addr[0];
    connect_req[5] = echo_addr[1];
    connect_req[6] = echo_addr[2];
    connect_req[7] = echo_addr[3];
    connect_req[8] = static_cast<std::uint8_t>((echo_port >> 8) & 0xFF);
    connect_req[9] = static_cast<std::uint8_t>(echo_port & 0xFF);
    co_await net::async_write(socket, net::buffer(connect_req), net::use_awaitable);

    // 读取 CONNECT 响应 (至少 4 字节头)
    std::array<std::uint8_t, 256> connect_resp{};
    co_await net::async_read(socket, net::buffer(connect_resp, 4), net::use_awaitable);
    if (connect_resp[0] != 0x05 || connect_resp[1] != 0x00)
    {
        throw psm::exception::network(std::format("{} CONNECT failed: {:02x} {:02x}",
                                                  tag, connect_resp[0], connect_resp[1]));
    }
    // 根据 ATYP 读取剩余地址字节 + 2 字节端口
    const auto atyp = connect_resp[3];
    std::size_t addr_len = 0;
    if (atyp == 0x01)
    {
        addr_len = 4;
    }
    else if (atyp == 0x04)
    {
        addr_len = 16;
    }
    else if (atyp == 0x03)
    {
        co_await net::async_read(socket, net::buffer(connect_resp.data() + 4, 1), net::use_awaitable);
        addr_len = static_cast<std::size_t>(connect_resp[4]) + 1;
    }
    // 读取地址 + 2 字节端口
    co_await net::async_read(socket, net::buffer(connect_resp.data() + 4, addr_len + 2), net::use_awaitable);

    // 发送载荷并验证回显
    co_await net::async_write(socket, net::buffer(payload.data(), payload.size()), net::use_awaitable);

    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(
            net::buffer(echo.data() + got, payload.size() - got), net::use_awaitable);
    }

    if (echo != payload)
    {
        std::string expected_hex, got_hex;
        for (auto c : payload)
            expected_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        for (auto c : echo)
            got_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        throw psm::exception::network(std::format("{} echo mismatch: expected [{}] got [{}]", tag, expected_hex, got_hex));
    }

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

net::awaitable<void> RawSocks5AuthClientEcho(tcp::endpoint proxy_ep, tcp::endpoint echo_ep,
                                             const std::string_view user, const std::string_view pass,
                                             const std::string_view tag, const std::string_view payload)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);

    // 方法协商: 支持 no auth (0x00) 和 password (0x02)
    constexpr std::array<std::uint8_t, 4> method_req = {0x05, 0x02, 0x00, 0x02};
    co_await net::async_write(socket, net::buffer(method_req), net::use_awaitable);

    std::array<std::uint8_t, 2> method_resp{};
    co_await net::async_read(socket, net::buffer(method_resp), net::use_awaitable);
    if (method_resp[0] != 0x05 || method_resp[1] != 0x02)
    {
        throw psm::exception::network(std::format("{} auth method negotiation failed: {:02x} {:02x}",
                                                  tag, method_resp[0], method_resp[1]));
    }

    // RFC 1929 认证: VER=1, ULEN, UNAME, PLEN, PASSWD
    const auto ulen = static_cast<std::uint8_t>(user.size());
    const auto plen = static_cast<std::uint8_t>(pass.size());
    std::vector<std::uint8_t> auth_req;
    auth_req.reserve(3 + user.size() + pass.size());
    auth_req.push_back(0x01);
    auth_req.push_back(ulen);
    auth_req.insert(auth_req.end(), user.begin(), user.end());
    auth_req.push_back(plen);
    auth_req.insert(auth_req.end(), pass.begin(), pass.end());
    co_await net::async_write(socket, net::buffer(auth_req), net::use_awaitable);

    // 读取认证响应
    std::array<std::uint8_t, 2> auth_resp{};
    co_await net::async_read(socket, net::buffer(auth_resp), net::use_awaitable);
    if (auth_resp[0] != 0x01 || auth_resp[1] != 0x00)
    {
        throw psm::exception::network(std::format("{} auth failed: {:02x} {:02x}",
                                                  tag, auth_resp[0], auth_resp[1]));
    }

    // CONNECT 请求
    const auto echo_addr = echo_ep.address().to_v4().to_bytes();
    const auto echo_port = echo_ep.port();
    std::array<std::uint8_t, 10> connect_req{};
    connect_req[0] = 0x05;
    connect_req[1] = 0x01;
    connect_req[2] = 0x00;
    connect_req[3] = 0x01;
    connect_req[4] = echo_addr[0];
    connect_req[5] = echo_addr[1];
    connect_req[6] = echo_addr[2];
    connect_req[7] = echo_addr[3];
    connect_req[8] = static_cast<std::uint8_t>((echo_port >> 8) & 0xFF);
    connect_req[9] = static_cast<std::uint8_t>(echo_port & 0xFF);
    co_await net::async_write(socket, net::buffer(connect_req), net::use_awaitable);

    std::array<std::uint8_t, 256> connect_resp{};
    co_await net::async_read(socket, net::buffer(connect_resp, 4), net::use_awaitable);
    if (connect_resp[0] != 0x05 || connect_resp[1] != 0x00)
    {
        throw psm::exception::network(std::format("{} CONNECT failed: {:02x} {:02x}",
                                                  tag, connect_resp[0], connect_resp[1]));
    }
    const auto atyp = connect_resp[3];
    std::size_t addr_len = 0;
    if (atyp == 0x01)
    {
        addr_len = 4;
    }
    else if (atyp == 0x04)
    {
        addr_len = 16;
    }
    else if (atyp == 0x03)
    {
        co_await net::async_read(socket, net::buffer(connect_resp.data() + 4, 1), net::use_awaitable);
        addr_len = static_cast<std::size_t>(connect_resp[4]) + 1;
    }
    // 读取地址 + 2 字节端口
    co_await net::async_read(socket, net::buffer(connect_resp.data() + 4, addr_len + 2), net::use_awaitable);

    // 回显验证
    co_await net::async_write(socket, net::buffer(payload.data(), payload.size()), net::use_awaitable);

    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(
            net::buffer(echo.data() + got, payload.size() - got), net::use_awaitable);
    }

    if (echo != payload)
    {
        std::string expected_hex, got_hex;
        for (auto c : payload)
            expected_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        for (auto c : echo)
            got_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        throw psm::exception::network(std::format("{} echo mismatch: expected [{}] got [{}]", tag, expected_hex, got_hex));
    }

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

net::awaitable<void> ProxyConnectClientEcho(tcp::endpoint proxy_ep, tcp::endpoint echo_ep,
                                            const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    echo_ep.address().to_string(), echo_ep.port(),
                                                    echo_ep.address().to_string(), echo_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    const std::string response = co_await ReadProxyConnectResponse(socket);

    if (!response.starts_with("HTTP/1.1 200"))
    {
        throw psm::exception::network(std::format("{} proxy connect failed: {}", tag, response));
    }

    const std::string payload = "hello_e2e_http_connect";
    co_await net::async_write(socket, net::buffer(payload), net::use_awaitable);

    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(
            net::buffer(echo.data() + got, payload.size() - got), net::use_awaitable);
    }

    if (echo != payload)
    {
        std::string expected_hex, got_hex;
        for (auto c : payload)
            expected_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        for (auto c : echo)
            got_hex += std::format("{:02x} ", static_cast<unsigned char>(c));
        throw psm::exception::network(std::format("{} echo mismatch: expected [{}] got [{}]", tag, expected_hex, got_hex));
    }

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

net::awaitable<void> HttpAuth407Client(tcp::endpoint proxy_ep, const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);

    // 发送无认证的 GET 请求
    const std::string request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    co_await net::async_write(socket, net::buffer(request), net::use_awaitable);

    const std::string response = co_await ReadHttpResponse(socket);

    if (response.find("407") == std::string::npos)
    {
        throw psm::exception::network(std::format("{} expected 407, got: {}", tag, response));
    }
    if (response.find("Proxy-Authenticate") == std::string::npos)
    {
        throw psm::exception::network(std::format("{} missing Proxy-Authenticate header", tag));
    }

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

// ============================================================
// 测试用例
// ============================================================

net::awaitable<void> E2ESocks5EchoImpl(psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    try
    {
        auto &ioc = worker_ctx.io_context;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto echo_ep = echo_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        net::co_spawn(ioc, EchoServer(std::move(echo_acceptor)), net::detached);
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        co_await RawSocks5ClientEcho(proxy_ep, echo_ep, "socks5_echo", "hello_e2e_socks5");
    }
    catch (const std::exception &e)
    {
        ADD_FAILURE() << "E2ESocks5Echo: " << e.what();
    }
}

net::awaitable<void> E2EHttpConnectEchoImpl(psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    try
    {
        auto &ioc = worker_ctx.io_context;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto echo_ep = echo_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        net::co_spawn(ioc, EchoServer(std::move(echo_acceptor)), net::detached);
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        co_await ProxyConnectClientEcho(proxy_ep, echo_ep, "http_connect_echo");
    }
    catch (const std::exception &e)
    {
        ADD_FAILURE() << "E2EHttpConnectEcho: " << e.what();
    }
}

net::awaitable<void> E2ESocks5AuthImpl(psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    try
    {
        auto &ioc = worker_ctx.io_context;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto echo_ep = echo_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        net::co_spawn(ioc, EchoServer(std::move(echo_acceptor)), net::detached);
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        co_await RawSocks5AuthClientEcho(proxy_ep, echo_ep, "testuser", "test_password",
                                         "socks5_auth", "hello_e2e_socks5_auth");
    }
    catch (const std::exception &e)
    {
        ADD_FAILURE() << "E2ESocks5Auth: " << e.what();
    }
}

net::awaitable<void> E2EHttpAuth407Impl(psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    try
    {
        auto &ioc = worker_ctx.io_context;
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto proxy_ep = proxy_acceptor.local_endpoint();

        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        co_await HttpAuth407Client(proxy_ep, "http_407");
    }
    catch (const std::exception &e)
    {
        ADD_FAILURE() << "E2EHttpAuth407: " << e.what();
    }
}

net::awaitable<void> E2EConcurrencyImpl(psm::resource::process &server_ctx, psm::resource::worker &worker_ctx)
{
    try
    {
        auto &ioc = worker_ctx.io_context;
        constexpr int conn_count = 5;

        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto echo_ep = echo_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        net::co_spawn(ioc, MultiEchoServer(std::move(echo_acceptor), conn_count), net::detached);
        net::co_spawn(ioc, MultiProxyAccept(std::move(proxy_acceptor), conn_count, server_ctx, worker_ctx),
                      net::detached);

        auto completed = std::make_shared<std::atomic<int>>(0);
        auto succeeded = std::make_shared<std::atomic<int>>(0);
        auto all_done = std::make_shared<std::atomic_bool>(false);

        for (int i = 0; i < conn_count; ++i)
        {
            auto payload = std::format("client_{}", i);
            auto client_task = [proxy_ep, echo_ep, payload = std::move(payload), completed, succeeded, all_done, i]() -> net::awaitable<void>
            {
                              try
                              {
                                  co_await RawSocks5ClientEcho(
                                      proxy_ep, echo_ep,
                                      std::format("conc_{}", i), payload);
                                  succeeded->fetch_add(1);
                              }
                              catch (const std::exception &e)
                              {
                                  // Individual client failure recorded in succeeded count
                              }
                              if (completed->fetch_add(1) + 1 == conn_count)
                              {
                                  all_done->store(true);
                              }
                          };
            net::co_spawn(ioc, std::move(client_task), net::detached);
        }

        co_await WaitUntilTrue(all_done, std::chrono::milliseconds(5000));

        EXPECT_TRUE(succeeded->load() == conn_count)
            << std::format("E2EConcurrency: {}/{} succeeded", succeeded->load(), conn_count);
    }
    catch (const std::exception &e)
    {
        ADD_FAILURE() << "E2EConcurrency: " << e.what();
    }
}

// ============================================================
// GTest 入口 — 每个场景一个 TEST
// ============================================================

TEST(E2E, Socks5Echo)
{
    const auto ioc_ptr = std::make_unique<net::io_context>();
    auto &ioc = *ioc_ptr;

    const auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
    psm::dns::config dns_cfg;
    auto dist = std::make_unique<psm::connect::router>(psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    ssl_ctx->set_verify_mode(ssl::verify_none);

    psm::config no_auth_cfg;

    psm::resource::process no_auth_server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{std::make_shared<const psm::config>(no_auth_cfg)},
        ssl_ctx, std::make_shared<psm::account::directory>(psm::memory::system::global_pool())};

    auto mr = psm::memory::system::local_pool();
    psm::resource::worker worker_ctx{ioc, std::weak_ptr<psm::resource::worker>{}, mr};

    std::exception_ptr test_error;
    auto function = [&no_auth_server_ctx, &worker_ctx]() -> net::awaitable<void>
    {
        co_await E2ESocks5EchoImpl(no_auth_server_ctx, worker_ctx);
    };

    auto token = [&ioc, &test_error](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    };
    net::co_spawn(ioc, function(), token);
    ioc.run();

    if (test_error)
    {
        std::rethrow_exception(test_error);
    }
}

TEST(E2E, HttpConnectEcho)
{
    const auto ioc_ptr = std::make_unique<net::io_context>();
    auto &ioc = *ioc_ptr;

    const auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
    psm::dns::config dns_cfg;
    auto dist = std::make_unique<psm::connect::router>(psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    ssl_ctx->set_verify_mode(ssl::verify_none);

    psm::config no_auth_cfg;

    psm::resource::process no_auth_server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{std::make_shared<const psm::config>(no_auth_cfg)},
        ssl_ctx, std::make_shared<psm::account::directory>(psm::memory::system::global_pool())};

    auto mr = psm::memory::system::local_pool();
    psm::resource::worker worker_ctx{ioc, std::weak_ptr<psm::resource::worker>{}, mr};

    std::exception_ptr test_error;
    auto function = [&no_auth_server_ctx, &worker_ctx]() -> net::awaitable<void>
    {
        co_await E2EHttpConnectEchoImpl(no_auth_server_ctx, worker_ctx);
    };

    auto token = [&ioc, &test_error](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    };
    net::co_spawn(ioc, function(), token);
    ioc.run();

    if (test_error)
    {
        std::rethrow_exception(test_error);
    }
}

TEST(E2E, Socks5Auth)
{
    const auto ioc_ptr = std::make_unique<net::io_context>();
    auto &ioc = *ioc_ptr;

    const auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
    psm::dns::config dns_cfg;
    auto dist = std::make_unique<psm::connect::router>(psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    ssl_ctx->set_verify_mode(ssl::verify_none);

    // 认证配置: password="test_password", credential=sha224("test_password")
    psm::config auth_cfg;
    auth_cfg.protocol.socks5.enable_auth = true;
    psm::runtime::authentication::user test_user{};
    test_user.password = "test_password";
    test_user.max_connections = 0;
    auth_cfg.instance.auth.users.push_back(std::move(test_user));

    auto account_dir = std::make_shared<psm::account::directory>(psm::memory::system::global_pool());
    const auto credential = psm::crypto::sha224("test_password");
    account_dir->upsert(credential, 0);

    psm::resource::process auth_server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{std::make_shared<const psm::config>(auth_cfg)},
        ssl_ctx, account_dir};

    auto mr = psm::memory::system::local_pool();
    psm::resource::worker worker_ctx{ioc, std::weak_ptr<psm::resource::worker>{}, mr};

    std::exception_ptr test_error;
    auto function = [&auth_server_ctx, &worker_ctx]() -> net::awaitable<void>
    {
        co_await E2ESocks5AuthImpl(auth_server_ctx, worker_ctx);
    };

    auto token = [&ioc, &test_error](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    };
    net::co_spawn(ioc, function(), token);
    ioc.run();

    if (test_error)
    {
        std::rethrow_exception(test_error);
    }
}

TEST(E2E, HttpAuth407)
{
    const auto ioc_ptr = std::make_unique<net::io_context>();
    auto &ioc = *ioc_ptr;

    const auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
    psm::dns::config dns_cfg;
    auto dist = std::make_unique<psm::connect::router>(psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    ssl_ctx->set_verify_mode(ssl::verify_none);

    psm::config auth_cfg;
    auth_cfg.protocol.socks5.enable_auth = true;
    psm::runtime::authentication::user test_user{};
    test_user.password = "test_password";
    test_user.max_connections = 0;
    auth_cfg.instance.auth.users.push_back(std::move(test_user));

    auto account_dir = std::make_shared<psm::account::directory>(psm::memory::system::global_pool());
    const auto credential = psm::crypto::sha224("test_password");
    account_dir->upsert(credential, 0);

    psm::resource::process auth_server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{std::make_shared<const psm::config>(auth_cfg)},
        ssl_ctx, account_dir};

    auto mr = psm::memory::system::local_pool();
    psm::resource::worker worker_ctx{ioc, std::weak_ptr<psm::resource::worker>{}, mr};

    std::exception_ptr test_error;
    auto function = [&auth_server_ctx, &worker_ctx]() -> net::awaitable<void>
    {
        co_await E2EHttpAuth407Impl(auth_server_ctx, worker_ctx);
    };

    auto token = [&ioc, &test_error](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    };
    net::co_spawn(ioc, function(), token);
    ioc.run();

    if (test_error)
    {
        std::rethrow_exception(test_error);
    }
}

TEST(E2E, Concurrency)
{
    const auto ioc_ptr = std::make_unique<net::io_context>();
    auto &ioc = *ioc_ptr;

    const auto pool = std::make_unique<psm::connect::connection_pool>(ioc);
    psm::dns::config dns_cfg;
    auto dist = std::make_unique<psm::connect::router>(psm::connect::router_options{*pool, ioc, std::move(dns_cfg)});

    auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    ssl_ctx->set_verify_mode(ssl::verify_none);

    psm::config no_auth_cfg;

    psm::resource::process no_auth_server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{std::make_shared<const psm::config>(no_auth_cfg)},
        ssl_ctx, std::make_shared<psm::account::directory>(psm::memory::system::global_pool())};

    auto mr = psm::memory::system::local_pool();
    psm::resource::worker worker_ctx{ioc, std::weak_ptr<psm::resource::worker>{}, mr};

    std::exception_ptr test_error;
    auto function = [&no_auth_server_ctx, &worker_ctx]() -> net::awaitable<void>
    {
        co_await E2EConcurrencyImpl(no_auth_server_ctx, worker_ctx);
    };

    auto token = [&ioc, &test_error](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    };
    net::co_spawn(ioc, function(), token);
    ioc.run();

    if (test_error)
    {
        std::rethrow_exception(test_error);
    }
}

} // namespace
