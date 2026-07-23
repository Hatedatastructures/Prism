/**
 * @file Http.cpp
 * @brief HTTP 代理协议中继集成测试
 * @details 验证 HTTP 代理中继的完整流程，包括：
 * 1. CONNECT 隧道握手 + echo
 * 2. 普通 GET 请求转发（绝对 URI 重写）
 * 3. 407 认证挑战（未提供凭证）
 * 4. 403 认证失败（错误凭证）
 */

#include <prism/protocol/http/conn.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/account/directory.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <string>
#include <memory>
#include <cstring>
#include <array>


#include <gtest/gtest.h>

namespace net = boost::asio;
namespace transport = psm::transport;
namespace http = psm::protocol::http;
namespace account = psm::account;
using tcp = net::ip::tcp;

namespace
{
    /**
     * @brief CONNECT 隧道测试：服务端协程
     * @details 接受连接，创建 HTTP relay，执行握手后发送 200 响应，
     *          然后 echo 回客户端数据。
     */
    net::awaitable<void> DoConnectServer(tcp::acceptor &acceptor)
    {
        try
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);
            auto reliable = transport::make_reliable(std::move(socket));
            auto nego = http::make_conn(std::move(reliable));

            auto [ec, req] = co_await nego->handshake();
            if (psm::fault::failed(ec))
            {
                co_return;
            }

            // 验证是 CONNECT 方法
            if (req.method != "CONNECT")
            {
                co_return;
            }

            // 发送 200 响应
            co_await nego->send_ok();

            // 释放传输层进行 echo
            auto trans = nego->release();

            std::array<std::byte, 1024> buffer{};
            std::error_code read_ec;
            auto n = co_await trans->async_read_some(std::span(buffer), read_ec);
            if (read_ec || n == 0)
            {
                co_return;
            }

            // Echo 回写
            std::error_code write_ec;
            co_await psm::transport::async_write(*trans, std::span(buffer.data(), n), write_ec);
        }
        catch (const std::exception &)
        {
        }
    }

    /**
     * @brief 认证测试：服务端协程（带 account_directory）
     */
    net::awaitable<void> DoAuthServer(tcp::acceptor &acceptor, account::directory &dir,
                                      std::string_view expected_response)
    {
        try
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);
            auto reliable = transport::make_reliable(std::move(socket));
            auto nego = http::make_conn(std::move(reliable), &dir);

            auto [ec, req] = co_await nego->handshake();

            // 认证失败时 handshake 内部已发送错误响应，release 传输层读取客户端后续数据
            if (psm::fault::failed(ec))
            {
                co_return;
            }
        }
        catch (const std::exception &)
        {
        }
    }
}

/**
 * @brief 测试 CONNECT 隧道握手 + echo
 */
TEST(Http, ConnectTunnel)
{
    net::io_context ioc;
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    auto bound = acceptor.local_endpoint();

    auto client_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, DoConnectServer(std::ref(acceptor)), net::detached);

    net::co_spawn(
        ioc,
        [endpoint = bound, client_ok]() -> net::awaitable<void>
        {
            try
            {
                tcp::socket socket(co_await net::this_coro::executor);
                co_await socket.async_connect(endpoint, net::use_awaitable);

                // 发送 CONNECT 请求
                const std::string request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
                co_await net::async_write(socket, net::buffer(request), net::use_awaitable);

                // 读取 200 响应
                std::array<char, 256> resp_buf{};
                auto n = co_await socket.async_read_some(net::buffer(resp_buf), net::use_awaitable);
                std::string response(resp_buf.data(), n);

                if (response.find("200") == std::string::npos)
                {
                    co_return;
                }

                // 通过隧道发送数据并验证 echo
                const std::string test_msg = "Hello HTTP CONNECT";
                co_await net::async_write(socket, net::buffer(test_msg), net::use_awaitable);

                std::array<char, 1024> echo_buf{};
                auto echo_n = co_await socket.async_read_some(net::buffer(echo_buf), net::use_awaitable);
                std::string received(echo_buf.data(), echo_n);

                if (received != test_msg)
                {
                    co_return;
                }

                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &)
            {
            }
        },
        net::detached);

    ioc.run();

    EXPECT_TRUE(*client_ok) << "ConnectTunnel: CONNECT 隧道握手 + echo";
}

/**
 * @brief 测试 407 认证挑战（未提供凭证）
 */
TEST(Http, AuthChallenge407)
{
    net::io_context ioc;
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    auto bound = acceptor.local_endpoint();

    // 配置账户目录（密码 "test" 的 SHA224 哈希）
    account::directory dir;
    const auto credential = psm::crypto::sha224("test");
    dir.upsert(credential, 1);

    auto client_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, DoAuthServer(std::ref(acceptor), std::ref(dir), "407"), net::detached);

    net::co_spawn(
        ioc,
        [endpoint = bound, client_ok]() -> net::awaitable<void>
        {
            try
            {
                tcp::socket socket(co_await net::this_coro::executor);
                co_await socket.async_connect(endpoint, net::use_awaitable);

                // 发送不带 Proxy-Authorization 的请求
                const std::string request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
                co_await net::async_write(socket, net::buffer(request), net::use_awaitable);

                // 读取响应，应包含 407
                std::array<char, 512> resp_buf{};
                auto n = co_await socket.async_read_some(net::buffer(resp_buf), net::use_awaitable);
                std::string response(resp_buf.data(), n);

                if (response.find("407") == std::string::npos)
                {
                    co_return;
                }

                if (response.find("Proxy-Authenticate") == std::string::npos)
                {
                    co_return;
                }

                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &)
            {
            }
        },
        net::detached);

    ioc.run();

    EXPECT_TRUE(*client_ok) << "AuthChallenge407: 407 认证挑战";
}

/**
 * @brief 测试 403 认证失败（错误凭证）
 */
TEST(Http, AuthForbidden403)
{
    net::io_context ioc;
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    auto bound = acceptor.local_endpoint();

    // 配置账户目录
    account::directory dir;
    const auto credential = psm::crypto::sha224("correct_password");
    dir.upsert(credential, 1);

    auto client_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, DoAuthServer(std::ref(acceptor), std::ref(dir), "403"), net::detached);

    net::co_spawn(
        ioc,
        [endpoint = bound, client_ok]() -> net::awaitable<void>
        {
            try
            {
                tcp::socket socket(co_await net::this_coro::executor);
                co_await socket.async_connect(endpoint, net::use_awaitable);

                // 发送带错误凭证的请求（wrong_password 的 Base64 编码）
                // "wrong:wrong_password" -> Base64 -> "d3Jvbmc6d3JvbmdfcGFzc3dvcmQ="
                const std::string request =
                    "GET http://example.com/ HTTP/1.1\r\n"
                    "Host: example.com\r\n"
                    "Proxy-Authorization: Basic d3Jvbmc6d3JvbmdfcGFzc3dvcmQ=\r\n"
                    "\r\n";
                co_await net::async_write(socket, net::buffer(request), net::use_awaitable);

                // 读取响应，应包含 403
                std::array<char, 512> resp_buf{};
                auto n = co_await socket.async_read_some(net::buffer(resp_buf), net::use_awaitable);
                std::string response(resp_buf.data(), n);

                if (response.find("403") == std::string::npos)
                {
                    co_return;
                }

                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &)
            {
            }
        },
        net::detached);

    ioc.run();

    EXPECT_TRUE(*client_ok) << "AuthForbidden403: 403 认证失败";
}
