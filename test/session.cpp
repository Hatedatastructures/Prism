#include <array>
#include <atomic>
#include <chrono>
#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/agent/session.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/abnormal/network.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/memory.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <trace/spdlog.hpp>

// #include "agent/worker.hpp" // worker.hpp 似乎已被移除或整合

#ifdef WIN32
#include <windows.h>
#endif

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

#include <forward-engine/agent/detection.hpp>

namespace agent = ngx::agent;

namespace
{
    void info(const std::string_view msg)
    {
        ngx::trace::info("{}", msg);
    }
}

/**
 * @brief 回显服务器
 * @param acceptor 监听 acceptor (按值传递以接管所有权)
 * @note 回显服务器会持续监听 acceptor，直到发生错误
 */
net::awaitable<void> echo_server(tcp::acceptor acceptor)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 循环接受连接，防止仅处理一个连接后退出（如果测试用例有多次连接需求）
    // 但根据原逻辑只接受一次。如果需要持续运行，保持原样即可。
    // 原逻辑是 accept 一次。
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

/**
 * @brief 代理服务器接受连接
 * @param acceptor 监听 acceptor (按值传递以接管所有权)
 * @param ioc io_context
 * @param dist 分发器
 * @param ssl_ctx ssl 上下文
 * @note 代理服务器会持续监听 acceptor，直到发生错误
 */
net::awaitable<void> proxy_accept_one(tcp::acceptor acceptor, net::io_context &ioc,
                                      agent::distributor &dist, std::shared_ptr<ssl::context> ssl_ctx)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }
    auto inbound = ngx::transport::make_reliable(std::move(socket));
    auto session_ptr = std::make_shared<agent::session>(ioc,
                                                        std::move(inbound), dist, std::move(ssl_ctx), ngx::memory::current_resource());
    session_ptr->start();
}

/**
 * @brief 读取代理服务器连接响应
 * @param socket 连接 socket
 * @return std::string 响应字符串
 * @note 响应字符串必须包含 "\r\n\r\n" 才能结束读取
 */
net::awaitable<std::string> read_proxy_connect_response(tcp::socket &socket)
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
            throw ngx::abnormal::security("proxy response read failed: " + ec.message());
        }
        if (n == 0)
        {
            throw ngx::abnormal::security("proxy response eof");
        }
        response.append(buf.data(), n);
        if (response.size() > 8192)
        {
            throw ngx::abnormal::security("proxy response too large");
        }
    }

    if (!response.starts_with("HTTP/1.1 200"))
    {
        throw ngx::abnormal::network("proxy connect failed: " + response);
    }

    co_return response;
}

/**
 * @brief 发送取消信号
 * @param signal 取消信号
 * @param timeout 超时时间
 * @note 超时时间内未发送取消信号，会自动发送取消信号
 */
net::awaitable<void> emit_cancel_after(std::shared_ptr<net::cancellation_signal> signal, const std::chrono::milliseconds timeout)
{ // 获取当前协程的 executor
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

/**
 * @brief 等待直到标志位为 true
 * @param flag 标志位
 * @param timeout 超时时间
 * @note 超时时间内未标志位为 true，会抛出异常
 */
net::awaitable<void> wait_until_true(std::shared_ptr<std::atomic_bool> flag, const std::chrono::milliseconds timeout)
{
    auto executor = co_await net::this_coro::executor;
    net::steady_timer timer(executor);

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag->load())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            throw ngx::abnormal::network("timeout waiting for expected shutdown");
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

/**
 * @brief 代理服务器连接 echo 服务器
 * @param proxy_ep 代理服务器 endpoint
 * @param echo_ep echo 服务器 endpoint
 * @param tag 日志前缀
 * @note 会发送 CONNECT 请求，然后等待响应，最后发送 payload 并等待 echo
 */
net::awaitable<void> proxy_connect_client_echo(const tcp::endpoint proxy_ep, const tcp::endpoint echo_ep,
                                               const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: 已连接代理", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    echo_ep.address().to_string(), echo_ep.port(), echo_ep.address().to_string(), echo_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);
    info(std::format("{} client: 已发送 CONNECT", tag));

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 响应 `{}`", tag, first_line));

    const std::string payload = "hello_forward_engine";
    co_await net::async_write(socket, net::buffer(payload), net::use_awaitable);
    info(std::format("{} client: 已发送 payload,等待回显", tag));

    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(net::buffer(echo.data() + got, payload.size() - got),
                                               net::use_awaitable);
    }

    if (echo != payload)
    {
        throw ngx::abnormal::network("echo mismatch");
    }

    info(std::format("{} client: 回显校验通过，关闭连接", tag));

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

/**
 * @brief 等待 acceptor 接受连接后，延迟关闭 socket
 * @param acceptor acceptor (按值传递以接管所有权)
 * @param delay 延迟时间
 * @note 超时时间内未关闭 socket，会自动关闭 socket
 */
net::awaitable<void> upstream_close_after_accept(tcp::acceptor acceptor, const std::chrono::milliseconds delay)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(delay);
    boost::system::error_code wait_ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));

    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 等待 acceptor 接受连接后，等待 peer 关闭连接
 * @param acceptor acceptor (按值传递以接管所有权)
 * @param closed_flag 标志位，peer 关闭连接后会设置为 true
 * @param timeout 超时时间
 * @note 超时时间内未关闭连接，会自动设置标志位为 true
 */
net::awaitable<void> upstream_wait_peer_close(tcp::acceptor acceptor, std::shared_ptr<std::atomic_bool> closed_flag,
                                              const std::chrono::milliseconds timeout)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    net::co_spawn(co_await net::this_coro::executor, emit_cancel_after(timeout_signal, timeout), net::detached);

    std::array<char, 1> buf{};
    boost::system::error_code ec;
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));

    while (true)
    {
        ec.clear();
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec == net::error::operation_aborted)
        {
            co_return;
        }
        if (n == 0 || ec)
        {
            closed_flag->store(true);
            co_return;
        }
    }
}

/**
 * @brief 代理服务器连接 echo 服务器，等待 peer 关闭连接
 * @param proxy_ep 代理服务器 endpoint
 * @param upstream_ep echo 服务器 endpoint
 * @param tag 日志前缀
 * @note 会发送 CONNECT 请求，然后等待响应，最后等待 peer 关闭连接
 */
net::awaitable<void> proxy_connect_client_expect_close(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                       const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: 已连接代理，准备等待代理主动关闭", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(), upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 响应 `{}`", tag, first_line));

    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    net::co_spawn(co_await net::this_coro::executor,
                  emit_cancel_after(timeout_signal, std::chrono::milliseconds(1500)),
                  net::detached);

    std::array<char, 1> one{};
    boost::system::error_code ec;
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));
    const std::size_t n = co_await socket.async_read_some(net::buffer(one), token);

    if (ec == net::error::operation_aborted)
    {
        throw ngx::abnormal::security("timeout waiting for proxy to close client");
    }

    if (!ec && n != 0)
    {
        throw ngx::abnormal::security("expected close but received data");
    }

    info(std::format("{} client: 已观察到代理关闭", tag));

    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 代理服务器连接 echo 服务器，等待 peer 关闭连接后，关闭 socket
 * @param proxy_ep 代理服务器 endpoint
 * @param upstream_ep echo 服务器 endpoint
 * @param tag 日志前缀
 * @note 会发送 CONNECT 请求，然后等待响应，最后等待 peer 关闭连接后，关闭 socket
 */
net::awaitable<void> proxy_connect_client_then_close(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                     const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: 已连接代理，将主动关闭以触发对向退出", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(), upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 响应 `{}`", tag, first_line));

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);

    info(std::format("{} client: 已主动关闭连接", tag));
}

/**
 * @brief 测试 echo 服务器
 * @param ioc io_context
 * @param dist distributor
 * @param ssl_ctx ssl context
 * @param tag 日志前缀
 * @note 会启动 echo 服务器和代理服务器，然后连接代理服务器，最后关闭连接
 */
net::awaitable<void> run_case_echo(net::io_context &ioc, agent::distributor &dist, std::shared_ptr<ssl::context> ssl_ctx,
                                   const std::string_view tag)
{
    info(std::format("{} === case: echo ===", tag));

    tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto echo_ep = echo_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    net::co_spawn(ioc, echo_server(std::move(echo_acceptor)), net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), ioc, dist, std::move(ssl_ctx)), net::detached);
    co_await proxy_connect_client_echo(proxy_ep, echo_ep, tag);

    info(std::format("{} === case: echo done ===", tag));
}

/**
 * @brief 测试 echo 服务器，当上游关闭连接后，代理服务器应该关闭客户端连接
 * @param ioc io_context
 * @param dist distributor
 * @param ssl_ctx ssl context
 * @param tag 日志前缀
 * @note 会启动 echo 服务器和代理服务器，然后连接代理服务器，最后关闭连接
 */
net::awaitable<void> run_case_upstream_close_should_close_client(net::io_context &ioc, agent::distributor &dist,
                                                                 std::shared_ptr<ssl::context> ssl_ctx, const std::string_view tag)
{
    info(std::format("{} === case: upstream_close_should_close_client ===", tag));

    tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto upstream_ep = upstream_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    net::co_spawn(ioc, upstream_close_after_accept(std::move(upstream_acceptor), std::chrono::milliseconds(50)), net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), ioc, dist, std::move(ssl_ctx)), net::detached);

    co_await proxy_connect_client_expect_close(proxy_ep, upstream_ep, tag);

    info(std::format("{} === case: upstream_close_should_close_client done ===", tag));
}

/**
 * @brief 测试 echo 服务器，当客户端关闭连接后，代理服务器应该关闭上游连接
 * @param ioc io_context
 * @param dist distributor
 * @param ssl_ctx ssl context
 * @param tag 日志前缀
 * @note 会启动 echo 服务器和代理服务器，然后连接代理服务器，最后关闭连接
 */
net::awaitable<void> run_case_client_close_should_close_upstream(net::io_context &ioc, agent::distributor &dist,
                                                                 std::shared_ptr<ssl::context> ssl_ctx, const std::string_view tag)
{
    info(std::format("{} === case: client_close_should_close_upstream ===", tag));

    tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto upstream_ep = upstream_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    constexpr auto EXPECTED_SHUTDOWN_TIMEOUT = std::chrono::milliseconds(1500);
    auto upstream_closed = std::make_shared<std::atomic_bool>(false);

    net::co_spawn(ioc, upstream_wait_peer_close(std::move(upstream_acceptor), upstream_closed, EXPECTED_SHUTDOWN_TIMEOUT),
                  net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), ioc, dist, std::move(ssl_ctx)), net::detached);

    co_await proxy_connect_client_then_close(proxy_ep, upstream_ep, tag);
    co_await wait_until_true(upstream_closed, EXPECTED_SHUTDOWN_TIMEOUT);

    info(std::format("{} === case: client_close_should_close_upstream done ===", tag));
}

net::awaitable<void> run_all_tests(net::io_context &ioc, agent::distributor &dist, std::shared_ptr<ssl::context> ssl_ctx,
                                   const std::string_view tag)
{
    co_await run_case_echo(ioc, dist, ssl_ctx, tag);
    co_await run_case_upstream_close_should_close_client(ioc, dist, ssl_ctx, tag);
    co_await run_case_client_close_should_close_upstream(ioc, dist, ssl_ctx, tag);

    // 给分离的 session 协程一点时间进行清理和自我销毁，防止 ioc.stop() 导致的析构竞态崩溃
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(std::chrono::milliseconds(200));
    co_await timer.async_wait(net::use_awaitable);
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    try
    {
        ngx::memory::system::enable_global_pooling();
        {
            ngx::trace::config cfg;
            cfg.path_name = (std::filesystem::path("test_logs") / "session").string();
            cfg.file_name = "session_test.log";
            cfg.max_size = 4U * 1024U * 1024U;
            cfg.max_files = 2U;
            cfg.queue_size = 8192U;
            cfg.thread_count = 1U;
            cfg.enable_console = true;
            cfg.enable_file = false;
            cfg.log_level = "debug";
            cfg.trace_name = "session_test";
            ngx::trace::init(cfg);
        }

        // 1. ioc 必须最先声明（最后析构）
        // 确保 socket/pool/dist 析构时 ioc 仍然有效
        const auto ioc_ptr = std::make_unique<net::io_context>();
        auto &ioc = *ioc_ptr;

        // 2. 依赖资源声明（在 ioc 之后，先析构）

        // 初始化
        const auto pool = std::make_unique<ngx::transport::source>(ioc);
        auto dist = std::make_unique<agent::distributor>(*pool, ioc);

        auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        ssl_ctx->set_verify_mode(ssl::verify_none);

        // 注册协议处理器
        // 注意：这里的 arena 仅用于 handler 构造，实际处理时会使用 session 的 arena
        // 但由于 handler 工厂设计问题，我们需要提供一个临时的 arena
        // 必须保证 arena 在测试期间存活
        auto mr = ngx::memory::system::thread_local_pool();
        ngx::memory::frame_arena dummy_arena;
        // frame_arena 默认构造使用 thread_local_pool，不需要 mr 参数
        // 之前的 mr 变量其实没用，frame_arena 内部自己获取

        agent::register_handlers();

        std::exception_ptr test_error;

        {
            auto function = [&ioc, &dist, &ssl_ctx]() -> net::awaitable<void>
            {
                info("session_test: start");
                co_await run_all_tests(ioc, *dist, ssl_ctx, "session_test");
                info("session_test: done");
            };

            auto token = [&ioc, &test_error](const std::exception_ptr &ep)
            {
                test_error = ep;
                ioc.stop();
            };
            net::co_spawn(ioc, function(), token);

            ioc.run();
        }

        if (test_error)
        {
            std::rethrow_exception(test_error);
        }

        ngx::trace::shutdown();
    }
    catch (const std::exception &e)
    {
        ngx::trace::shutdown();
        std::cerr << std::format("session_test failed: {}", e.what()) << std::endl;
        return 1;
    }

    std::cout << "session_test passed" << std::endl;
    return 0;
}
