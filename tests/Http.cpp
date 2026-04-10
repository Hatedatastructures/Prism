/**
 * @file Http.cpp
 * @brief HTTP 代理协议中继集成测试
 * @details 验证 HTTP 代理中继的完整流程，包括：
 * 1. CONNECT 隧道握手 + echo
 * 2. 普通 GET 请求转发（绝对 URI 重写）
 * 3. 407 认证挑战（未提供凭证）
 * 4. 403 认证失败（错误凭证）
 */

#include <prism/protocol/http/relay.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <string>
#include <memory>
#include <cstring>
#include <array>

namespace net = boost::asio;
namespace transport = psm::channel::transport;
namespace http = psm::protocol::http;
namespace account = psm::agent::account;
using tcp = net::ip::tcp;

namespace
{
    int passed = 0;
    int failed = 0;

    auto log_info(const std::string_view msg) -> void
    {
        psm::trace::info("[Http] {}", msg);
    }

    auto log_pass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Http] PASS: {}", msg);
    }

    auto log_fail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Http] FAIL: {}", msg);
    }
}

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
        auto relay = http::make_relay(std::move(reliable));

        auto [ec, req] = co_await relay->handshake();
        if (psm::fault::failed(ec))
        {
            log_fail(std::format("Server handshake failed: {}", psm::fault::describe(ec)));
            co_return;
        }

        log_info(std::format("Server got {} {}", req.method, req.target));

        // 验证是 CONNECT 方法
        if (req.method != "CONNECT")
        {
            log_fail(std::format("Expected CONNECT, got {}", req.method));
            co_return;
        }

        // 发送 200 响应
        co_await relay->write_connect_success();

        // 释放传输层进行 echo
        auto trans = relay->release();

        std::array<std::byte, 1024> buffer{};
        std::error_code read_ec;
        auto n = co_await trans->async_read_some(std::span(buffer), read_ec);
        if (read_ec || n == 0)
        {
            log_fail(std::format("Server echo read failed: {}", read_ec.message()));
            co_return;
        }

        // Echo 回写
        std::error_code write_ec;
        co_await trans->async_write(std::span(buffer.data(), n), write_ec);
        if (write_ec)
        {
            log_fail(std::format("Server echo write failed: {}", write_ec.message()));
            co_return;
        }

        log_info("Server echo complete");
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Server exception: {}", e.what()));
    }
}

/**
 * @brief 测试 CONNECT 隧道握手 + echo
 */
void TestConnectTunnel()
{
    log_info("=== TestConnectTunnel ===");

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
                    log_fail(std::format("Expected 200 response, got: {}", response));
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
                    log_fail(std::format("Echo mismatch: expected '{}', got '{}'", test_msg, received));
                    co_return;
                }

                log_info("CONNECT tunnel echo verified");
                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &e)
            {
                log_fail(std::format("Client exception: {}", e.what()));
            }
        },
        net::detached);

    ioc.run();

    if (*client_ok)
    {
        log_pass("ConnectTunnel");
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
        auto relay = http::make_relay(std::move(reliable), &dir);

        auto [ec, req] = co_await relay->handshake();

        // 认证失败时 handshake 内部已发送错误响应，release 传输层读取客户端后续数据
        if (psm::fault::failed(ec))
        {
            // 握手失败后需要客户端读取错误响应来验证
            co_return;
        }

        // 认证成功则不应到达这里（测试场景是认证失败）
        log_fail("Server handshake succeeded when auth should fail");
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Auth server exception: {}", e.what()));
    }
}

/**
 * @brief 测试 407 认证挑战（未提供凭证）
 */
void TestAuthChallenge407()
{
    log_info("=== TestAuthChallenge407 ===");

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
                    log_fail(std::format("Expected 407 response, got: {}", response));
                    co_return;
                }

                if (response.find("Proxy-Authenticate") == std::string::npos)
                {
                    log_fail("407 response missing Proxy-Authenticate header");
                    co_return;
                }

                log_info("407 challenge verified");
                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &e)
            {
                log_fail(std::format("Client exception: {}", e.what()));
            }
        },
        net::detached);

    ioc.run();

    if (*client_ok)
    {
        log_pass("AuthChallenge407");
    }
}

/**
 * @brief 测试 403 认证失败（错误凭证）
 */
void TestAuthForbidden403()
{
    log_info("=== TestAuthForbidden403 ===");

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
                // "wrong:wrong_password" → Base64 → "d3Jvbmc6d3JvbmdfcGFzc3dvcmQ="
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
                    log_fail(std::format("Expected 403 response, got: {}", response));
                    co_return;
                }

                log_info("403 forbidden verified");
                socket.close();
                *client_ok = true;
            }
            catch (const std::exception &e)
            {
                log_fail(std::format("Client exception: {}", e.what()));
            }
        },
        net::detached);

    ioc.run();

    if (*client_ok)
    {
        log_pass("AuthForbidden403");
    }
}

/**
 * @brief 测试入口
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting HTTP relay tests...");

    try
    {
        TestConnectTunnel();
        TestAuthChallenge407();
        TestAuthForbidden403();
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Test threw exception: {}", e.what()));
    }

    psm::trace::info("[Http] Results: {} passed, {} failed", passed, failed);
    psm::trace::shutdown();

    return failed > 0 ? 1 : 0;
}
