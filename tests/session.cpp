/**
 * @file Session.cpp
 * @brief Session 生命周期集成测试
 * @details 验证完整代理会话生命周期的三个关键场景：
 * 1. CONNECT + echo 往返 (TestSessionEcho)
 * 2. 上游关闭后客户端被关闭 (TestSessionUpstreamClose)
 * 3. 客户端关闭后上游检测到 (TestSessionClientClose)
 */

#include <prism/agent/config.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/channel/connection/pool.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/resolve/router.hpp>
#include <prism/exception/network.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <format>
#include <memory>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

namespace agent = psm::agent;

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    void log_info(const std::string_view msg)
    {
        // 通过 spdlog 后端输出信息级别日志
        psm::trace::info("[Session] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        // 递增通过计数器并记录日志
        ++passed;
        psm::trace::info("[Session] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        // 递增失败计数器并记录错误日志
        ++failed;
        psm::trace::error("[Session] FAIL: {}", msg);
    }
} // namespace

// ============================================================
// 辅助协程
// ============================================================

/**
 * @brief 回显服务器协程
 * @details 接受一个 TCP 连接，循环读取数据并原样回显，直到对端关闭或出错。
 * @param acceptor 接收器（按值接管所有权，接受一个连接后停止）
 * @return net::awaitable<void>
 */
net::awaitable<void> EchoServer(tcp::acceptor acceptor)
{
    // 将错误码重定向到 accept_ec，避免 accept 失败时抛异常
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 异步等待一个入站连接，只服务一个客户端
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    // 8KB 栈缓冲区，足够承载典型代理帧
    std::array<char, 8192> buf{};
    // 循环读取并原样回写，直到对端关闭或发生错误
    while (true)
    {
        // 将读取错误重定向到 ec，便于统一判断
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec || n == 0)
        {
            break;
        }
        // 将读到的数据完整写回，async_write 保证全部发送
        co_await net::async_write(socket, net::buffer(buf.data(), n), token);
        if (ec)
        {
            break;
        }
    }
}

/**
 * @brief 代理接受一个连接并启动会话
 * @details 通过 acceptor 接受一个入站连接，包装为 reliable 传输层后
 *          创建 session 实例并调用 start() 启动代理会话生命周期。
 * @param acceptor 代理监听接收器（按值接管所有权）
 * @param server_ctx 服务端共享上下文（配置、SSL、账户存储）
 * @param worker_ctx 工作线程上下文（io_context、DNS 路由、PMR 资源）
 * @return net::awaitable<void>
 */
net::awaitable<void> ProxyAcceptOne(tcp::acceptor acceptor, agent::server_context &server_ctx,
                                    agent::worker_context &worker_ctx)
{
    // 将错误码重定向到 accept_ec，避免 accept 失败时抛异常
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 异步等待一个入站连接
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }
    // 将裸 socket 包装为 reliable 传输层，提供统一的读写接口
    auto inbound = psm::channel::transport::make_reliable(std::move(socket));

    // 组装会话参数：服务端上下文、工作线程上下文、入站传输层
    agent::session::session_params params{server_ctx, worker_ctx, std::move(inbound)};
    // 创建会话实例并启动代理生命周期（嗅探、分发、转发）
    auto session_ptr = agent::session::make_session(std::move(params));
    session_ptr->start();
}

/**
 * @brief 读取并验证 HTTP CONNECT 代理响应
 * @details 循环读取直到收到完整的 HTTP 响应头（以 \\r\\n\\r\\n 结尾），
 *          验证状态行为 200，否则抛出 network 异常。设置 8KB 上限防止恶意输入。
 * @param socket 已连接的 TCP socket
 * @return net::awaitable<std::string> 完整的 HTTP 响应头字符串
 */
net::awaitable<std::string> ReadProxyConnectResponse(tcp::socket &socket)
{
    // 预分配响应缓冲区，减少小数据时的重分配
    std::string response;
    response.reserve(256);
    std::array<char, 512> buf{};
    // 循环读取直到收到完整 HTTP 响应头（以 \r\n\r\n 结尾）
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
        // 设置 8KB 上限，防止恶意代理返回超大响应撑爆内存
        if (response.size() > 8192)
        {
            throw psm::exception::network("proxy response too large");
        }
    }

    // 验证状态行必须为 200，否则 CONNECT 隧道建立失败
    if (!response.starts_with("HTTP/1.1 200"))
    {
        throw psm::exception::network("proxy connect failed: " + response);
    }

    co_return response;
}

/**
 * @brief 延迟发射取消信号
 * @details 等待指定超时后向 cancellation_signal 发射 all 类型取消。
 *          用于为异步读操作设置超时兜底，避免测试因协程悬挂而永不退出。
 * @param signal 共享的取消信号指针
 * @param timeout 延迟时长
 * @return net::awaitable<void>
 */
net::awaitable<void> EmitCancelAfter(std::shared_ptr<net::cancellation_signal> signal, const std::chrono::milliseconds timeout)
{
    // 获取当前协程所在执行器，用于创建定时器
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(timeout);

    // 等待超时，若定时器未被取消则发射取消信号
    boost::system::error_code ec;
    auto token = net::redirect_error(net::use_awaitable, ec);
    co_await timer.async_wait(token);
    if (!ec)
    {
        // 向所有绑定该信号的异步操作发送取消通知
        signal->emit(net::cancellation_type::all);
    }
}

/**
 * @brief 轮询等待原子标志变为 true
 * @details 以 10ms 间隔异步轮询，直到 flag 为 true 或超过 deadline 时抛出异常。
 *          用于等待远端关闭检测完成等异步条件。
 * @param flag 共享的原子布尔标志
 * @param timeout 最大等待时长
 * @return net::awaitable<void>
 */
net::awaitable<void> WaitUntilTrue(std::shared_ptr<std::atomic_bool> flag, const std::chrono::milliseconds timeout)
{
    auto executor = co_await net::this_coro::executor;
    net::steady_timer timer(executor);

    // 计算绝对截止时间，用于每次轮询时判断是否超时
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    // 以 10ms 间隔异步轮询，避免忙等待阻塞 io_context
    while (!flag->load())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            throw psm::exception::network("timeout waiting for expected shutdown");
        }

        timer.expires_after(std::chrono::milliseconds(10));
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        // 异步等待 10ms 后再次检查，让出执行权给其他协程
        co_await timer.async_wait(token);
        if (ec)
        {
            co_return;
        }
    }
}

/**
 * @brief 客户端通过代理 CONNECT 隧道发送数据并验证回显
 * @details 向代理发送 HTTP CONNECT 请求建立隧道，通过隧道发送固定载荷，
 *          循环读取直到收齐完整回显后比对，验证代理双向转发正确性。
 * @param proxy_ep 代理监听端点
 * @param echo_ep 上游回显服务器端点
 * @param tag 测试标签，用于日志区分
 * @return net::awaitable<void>
 */
net::awaitable<void> ProxyConnectClientEcho(const tcp::endpoint proxy_ep, const tcp::endpoint echo_ep,
                                            const std::string_view tag)
{
    // 在当前协程执行器上创建 TCP socket
    tcp::socket socket(co_await net::this_coro::executor);
    // 连接到代理服务器
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    log_info(std::format("{} client: connected to proxy", tag));

    // 构造 HTTP CONNECT 请求，请求代理建立到回显服务器的隧道
    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    echo_ep.address().to_string(), echo_ep.port(),
                                                    echo_ep.address().to_string(), echo_ep.port());

    // 发送 CONNECT 请求
    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);
    log_info(std::format("{} client: sent CONNECT", tag));

    // 读取并验证代理返回的 CONNECT 响应
    const std::string response = co_await ReadProxyConnectResponse(socket);
    log_info(std::format("{} client: CONNECT response `{}`", tag, response.substr(0, response.find("\r\n"))));

    // 通过隧道发送固定载荷
    const std::string payload = "hello_forward_engine";
    co_await net::async_write(socket, net::buffer(payload), net::use_awaitable);

    // 循环读取直到收齐与载荷等长的回显数据
    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(net::buffer(echo.data() + got, payload.size() - got), net::use_awaitable);
    }

    // 比对回显内容与原始载荷，验证双向转发正确性
    if (echo != payload)
    {
        throw psm::exception::network("echo mismatch");
    }

    log_info(std::format("{} client: echo verified", tag));

    // 双向关闭连接，忽略可能的错误（对端可能已关闭）
    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

/**
 * @brief 上游接受连接后延迟关闭
 * @details 模拟上游服务在建立连接后因超时或异常主动断开的场景。
 *          接受连接后等待指定延迟，然后 shutdown + close。
 * @param acceptor 上游监听接收器（按值接管所有权）
 * @param delay 关闭前的等待时长
 * @return net::awaitable<void>
 */
net::awaitable<void> UpstreamCloseAfterAccept(tcp::acceptor acceptor, const std::chrono::milliseconds delay)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 接受一个入站连接
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    // 延迟指定时间后关闭，模拟上游超时或异常断开
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(delay);
    boost::system::error_code wait_ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));

    // 主动关闭连接，触发代理侧检测到上游断开
    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 上游等待对端关闭
 * @details 接受一个连接后持续读取，直到读到 EOF/错误（表示对端关闭）
 *          或超时被取消。关闭检测结果通过 closed_flag 通知调用方。
 * @param acceptor 上游监听接收器（按值接管所有权）
 * @param closed_flag 共享原子标志，检测到关闭时置 true
 * @param timeout 最大等待时长，超时后取消信号触发
 * @return net::awaitable<void>
 */
net::awaitable<void> UpstreamWaitPeerClose(tcp::acceptor acceptor, std::shared_ptr<std::atomic_bool> closed_flag,
                                           const std::chrono::milliseconds timeout)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 接受一个入站连接
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    // 创建取消信号，用于超时后中断阻塞的读操作
    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    // 在独立协程中延迟发射取消信号，超时兜底防止永久阻塞
    net::co_spawn(co_await net::this_coro::executor, EmitCancelAfter(timeout_signal, timeout), net::detached);

    // 只读 1 字节即可判断对端是否关闭
    std::array<char, 1> buf{};
    boost::system::error_code ec;
    // 将取消信号绑定到后续的读操作 token 上
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));

    // 持续读取直到收到 EOF（对端关闭）或被超时取消
    while (true)
    {
        ec.clear();
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        // 超时取消，正常退出
        if (ec == net::error::operation_aborted)
        {
            co_return;
        }
        // 读到 0 字节或错误，说明对端已关闭连接
        if (n == 0 || ec)
        {
            closed_flag->store(true);
            co_return;
        }
    }
}

/**
 * @brief 客户端通过代理连接后等待代理主动关闭
 * @details 建立 CONNECT 隧道后不再发送数据，等待代理/上游关闭导致连接中断。
 *          使用 cancellation_signal 设置 1500ms 超时兜底。
 * @param proxy_ep 代理监听端点
 * @param upstream_ep 上游服务端点（用于构造 CONNECT 请求）
 * @param tag 测试标签，用于日志区分
 * @return net::awaitable<void>
 */
net::awaitable<void> ProxyConnectClientExpectClose(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                   const std::string_view tag)
{
    // 创建 socket 并连接到代理
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    log_info(std::format("{} client: connected, waiting for proxy close", tag));

    // 构造 CONNECT 请求，建立到上游的隧道
    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(),
                                                    upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    // 等待代理返回 200 确认隧道建立
    const std::string response = co_await ReadProxyConnectResponse(socket);
    log_info(std::format("{} client: CONNECT response `{}`", tag, response.substr(0, response.find("\r\n"))));

    // 设置 1500ms 超时取消信号，防止代理永不关闭导致测试悬挂
    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    net::co_spawn(co_await net::this_coro::executor,
                  EmitCancelAfter(timeout_signal, std::chrono::milliseconds(1500)),
                  net::detached);

    // 尝试读取，预期代理会因上游关闭而中断连接
    std::array<char, 1> one{};
    boost::system::error_code ec;
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));
    const std::size_t n = co_await socket.async_read_some(net::buffer(one), token);

    // 超时仍未关闭，测试失败
    if (ec == net::error::operation_aborted)
    {
        throw psm::exception::network("timeout waiting for proxy to close client");
    }

    // 预期收到 EOF，若收到数据则说明代理行为异常
    if (!ec && n != 0)
    {
        throw psm::exception::network("expected close but received data");
    }

    log_info(std::format("{} client: detected proxy close", tag));

    // 清理连接
    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 客户端通过代理连接后主动关闭
 * @details 建立 CONNECT 隧道后立即 shutdown + close，模拟客户端主动断开场景。
 * @param proxy_ep 代理监听端点
 * @param upstream_ep 上游服务端点（用于构造 CONNECT 请求）
 * @param tag 测试标签，用于日志区分
 * @return net::awaitable<void>
 */
net::awaitable<void> ProxyConnectClientThenClose(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                 const std::string_view tag)
{
    // 创建 socket 并连接到代理
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    log_info(std::format("{} client: connected, will close actively", tag));

    // 构造 CONNECT 请求，建立到上游的隧道
    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(),
                                                    upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    // 等待代理确认隧道建立
    const std::string response = co_await ReadProxyConnectResponse(socket);
    log_info(std::format("{} client: CONNECT response `{}`", tag, response.substr(0, response.find("\r\n"))));

    // 隧道建立后立即主动关闭，模拟客户端断开场景
    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);

    log_info(std::format("{} client: closed", tag));
}

// ============================================================
// 测试用例
// ============================================================

/**
 * @brief 测试 CONNECT + echo 完整往返
 * @details 启动回显服务器和代理，客户端通过代理建立隧道发送数据并验证回显。
 * @param server_ctx 服务端共享上下文
 * @param worker_ctx 工作线程上下文
 * @return net::awaitable<void>
 */
net::awaitable<void> TestSessionEcho(agent::server_context &server_ctx, agent::worker_context &worker_ctx)
{
    log_info("=== TestSessionEcho ===");

    try
    {
        auto &ioc = worker_ctx.io_context;
        // 在随机端口上绑定回显服务器和代理监听器
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        // 获取操作系统分配的实际端口号，供客户端连接使用
        const auto echo_ep = echo_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        // 启动回显服务器协程，接受一个连接后循环回显
        net::co_spawn(ioc, EchoServer(std::move(echo_acceptor)), net::detached);
        // 启动代理接受协程，接受一个连接后创建代理会话
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);
        // 以客户端身份通过代理发送数据并验证回显
        co_await ProxyConnectClientEcho(proxy_ep, echo_ep, "echo");

        log_pass("SessionEcho");
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("SessionEcho: {}", e.what()));
    }
}

/**
 * @brief 测试上游关闭后客户端被关闭
 * @details 上游接受连接后 50ms 主动断开，验证客户端能检测到代理侧的关闭。
 * @param server_ctx 服务端共享上下文
 * @param worker_ctx 工作线程上下文
 * @return net::awaitable<void>
 */
net::awaitable<void> TestSessionUpstreamClose(agent::server_context &server_ctx, agent::worker_context &worker_ctx)
{
    log_info("=== TestSessionUpstreamClose ===");

    try
    {
        auto &ioc = worker_ctx.io_context;
        // 在随机端口上绑定上游和代理监听器
        tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto upstream_ep = upstream_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        // 上游接受连接后 50ms 主动断开，模拟服务端异常
        net::co_spawn(ioc, UpstreamCloseAfterAccept(std::move(upstream_acceptor), std::chrono::milliseconds(50)), net::detached);
        // 启动代理，桥接客户端与上游
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        // 客户端等待代理因上游关闭而断开连接
        co_await ProxyConnectClientExpectClose(proxy_ep, upstream_ep, "upstream_close");

        log_pass("SessionUpstreamClose");
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("SessionUpstreamClose: {}", e.what()));
    }
}

/**
 * @brief 测试客户端关闭后上游能检测到
 * @details 客户端建立隧道后主动关闭，验证上游通过读操作能检测到对端关闭。
 * @param server_ctx 服务端共享上下文
 * @param worker_ctx 工作线程上下文
 * @return net::awaitable<void>
 */
net::awaitable<void> TestSessionClientClose(agent::server_context &server_ctx, agent::worker_context &worker_ctx)
{
    log_info("=== TestSessionClientClose ===");

    try
    {
        auto &ioc = worker_ctx.io_context;
        // 在随机端口上绑定上游和代理监听器
        tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

        const auto upstream_ep = upstream_acceptor.local_endpoint();
        const auto proxy_ep = proxy_acceptor.local_endpoint();

        // 上游等待对端关闭的最大时长
        constexpr auto timeout = std::chrono::milliseconds(1500);
        // 原子标志：上游检测到对端关闭时置 true
        auto upstream_closed = std::make_shared<std::atomic_bool>(false);

        // 上游协程持续读取，等待客户端关闭传播到上游
        net::co_spawn(ioc, UpstreamWaitPeerClose(std::move(upstream_acceptor), upstream_closed, timeout), net::detached);
        // 启动代理，桥接客户端与上游
        net::co_spawn(ioc, ProxyAcceptOne(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

        // 客户端建立隧道后立即关闭
        co_await ProxyConnectClientThenClose(proxy_ep, upstream_ep, "client_close");
        // 轮询等待上游检测到对端关闭，验证关闭信号正确传播
        co_await WaitUntilTrue(upstream_closed, timeout);

        log_pass("SessionClientClose");
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("SessionClientClose: {}", e.what()));
    }
}

/**
 * @brief 顺序运行所有 Session 测试
 * @details 依次执行 TestSessionEcho、TestSessionUpstreamClose、TestSessionClientClose，
 *          最后等待 200ms 让 session 协程完成清理。
 * @param server_ctx 服务端共享上下文
 * @param worker_ctx 工作线程上下文
 * @return net::awaitable<void>
 */
net::awaitable<void> RunAllTests(agent::server_context &server_ctx, agent::worker_context &worker_ctx)
{
    // 顺序执行三个测试场景，确保互不干扰
    co_await TestSessionEcho(server_ctx, worker_ctx);
    co_await TestSessionUpstreamClose(server_ctx, worker_ctx);
    co_await TestSessionClientClose(server_ctx, worker_ctx);

    // 等待 session 协程清理
    // 留出 200ms 让 detached 协程完成资源释放，避免 io_context 提前销毁
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(std::chrono::milliseconds(200));
    co_await timer.async_wait(net::use_awaitable);
}

// ============================================================
// main
// ============================================================

/**
 * @brief 测试入口
 * @details 初始化全局内存池、日志系统和协议处理器，构造 server/worker 上下文，
 *          通过 co_spawn 在 io_context 上运行全部测试协程。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    try
    {
        // 开启全局 PMR 内存池，为所有 PMR 容器提供底层分配
        psm::memory::system::enable_global_pooling();
        // 初始化日志系统，使用默认配置
        psm::trace::init({});
        // 注册所有协议处理器（HTTP/SOCKS5/Trojan/Unknown）
        psm::agent::dispatch::register_handlers();

        // 创建单线程 io_context 驱动所有测试协程
        const auto ioc_ptr = std::make_unique<net::io_context>();
        auto &ioc = *ioc_ptr;

        // 创建连接池，管理到上游的出站连接
        const auto pool = std::make_unique<psm::channel::connection_pool>(ioc);
        // 使用空 DNS 配置创建路由器（测试中使用直连，无需上游 DNS）
        psm::resolve::config dns_cfg;
        auto dist = std::make_unique<psm::resolve::router>(*pool, ioc, std::move(dns_cfg));

        // 创建 SSL 上下文，测试中跳过证书验证
        auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        ssl_ctx->set_verify_mode(ssl::verify_none);

        // 构造服务端上下文：配置、SSL、账户存储
        agent::config cfg;
        auto account_store = std::make_shared<agent::account::directory>(psm::memory::system::global_pool());
        agent::server_context server_ctx{cfg, ssl_ctx, account_store};

        // 构造工作线程上下文：io_context、DNS 路由、线程本地内存池
        auto mr = psm::memory::system::thread_local_pool();
        agent::worker_context worker_ctx{ioc, *dist, mr};

        // 预分配帧竞技场（测试中未使用，但 worker_context 可能需要）
        psm::memory::frame_arena dummy_arena;

        // 用于捕获协程中未处理的异常
        std::exception_ptr test_error;

        {
            // 定义测试协程入口，顺序运行所有测试
            auto function = [&server_ctx, &worker_ctx]() -> net::awaitable<void>
            {
                co_await RunAllTests(server_ctx, worker_ctx);
            };

            // 协程完成回调：保存异常并停止事件循环
            auto token = [&ioc, &test_error](const std::exception_ptr &ep)
            {
                test_error = ep;
                ioc.stop();
            };
            // 在 io_context 上派生测试协程
            net::co_spawn(ioc, function(), token);

            // 阻塞运行事件循环，直到所有测试完成或异常退出
            ioc.run();
        }

        // 若协程抛出异常，在此处重新抛出
        if (test_error)
        {
            std::rethrow_exception(test_error);
        }

        // 输出测试结果汇总
        psm::trace::info("[Session] Results: {} passed, {} failed", passed, failed);
        psm::trace::shutdown();
    }
    catch (const std::exception &e)
    {
        psm::trace::shutdown();
        psm::trace::error("[Session] fatal: {}", e.what());
        return 1;
    }

    // 根据失败数返回退出码：0 全部通过，1 存在失败
    return failed > 0 ? 1 : 0;
}
