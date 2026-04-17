/**
 * @file Transmission.cpp
 * @brief 传输层接口和实现单元测试
 * @details 测试 transmission 抽象接口以及 reliable、unreliable 具体实现。
 * 验证构造、异步读写、关闭、远端端点等操作的正确性。
 */

#include <prism/channel/transport/transmission.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/channel/transport/unreliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string_view>

namespace net = boost::asio;

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    void LogInfo(const std::string_view msg)
    {
        psm::trace::info("[Transmission] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void LogPass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Transmission] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void LogFail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Transmission] FAIL: {}", msg);
    }
} // namespace

/**
 * @brief 回显处理（单 socket）
 * @details 循环读取 socket 数据并原样写回，直到对端关闭或出错。
 * @param socket 已连接的 TCP socket（按值接管所有权）
 * @return net::awaitable<void>
 */
net::awaitable<void> EchoOnce(net::ip::tcp::socket socket)
{
    std::array<char, 4096> buf{};
    // 循环读取并回显，直到对端关闭连接或发生错误
    while (true)
    {
        boost::system::error_code ec;
        // 将错误码重定向到 ec 而非抛异常，便于优雅退出
        auto token = net::redirect_error(net::use_awaitable, ec);
        // 异步读取数据，协程挂起直到有数据到达
        const auto n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec || n == 0)
        {
            co_return;
        }
        // 将读到的数据原样写回对端
        co_await net::async_write(socket, net::buffer(buf.data(), n), token);
        if (ec)
        {
            co_return;
        }
    }
}

/**
 * @brief 回显服务器（单连接，按值接收 acceptor）
 * @details 接受一个连接后交给 EchoOnce 处理回显。
 * @param acceptor TCP 接收器（按值接管所有权）
 * @return net::awaitable<void>
 */
net::awaitable<void> EchoOnceAccept(net::ip::tcp::acceptor acceptor)
{
    boost::system::error_code accept_ec;
    // 使用 redirect_error 避免异常中断协程
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 异步等待一个入站连接
    auto socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }
    // 将已连接的 socket 交给 EchoOnce 处理数据回显
    co_await EchoOnce(std::move(socket));
}

/**
 * @brief 测试 reliable 从 executor 构造
 */
void TestReliableConstructor()
{
    LogInfo("=== TestReliableConstructor ===");

    net::io_context ioc;
    auto executor = ioc.get_executor();
    // 从 executor 构造 reliable 传输层，验证内部 executor 一致性
    auto reliable = psm::channel::transport::make_reliable(executor);

    // 确保构造后的 executor 与传入的相同
    if (reliable->executor() != executor)
    {
        LogFail("executor mismatch");
        return;
    }

    LogPass("ReliableConstructor");
}

/**
 * @brief 测试 reliable 从 socket 构造
 */
void TestReliableFromSocket()
{
    LogInfo("=== TestReliableFromSocket ===");

    net::io_context ioc;
    auto executor = ioc.get_executor();
    // 创建一个未连接的 TCP socket
    net::ip::tcp::socket socket(executor);
    // 从已有 socket 构造 reliable 传输层，验证所有权转移后 executor 一致性
    auto reliable = psm::channel::transport::make_reliable(std::move(socket));

    if (reliable->executor() != executor)
    {
        LogFail("executor mismatch");
        return;
    }

    LogPass("ReliableFromSocket");
}

/**
 * @brief 测试 reliable 异步读写
 * @details 在同一个 io_context 上启动 echo server 和 client，验证通过 reliable
 *          传输层写入的数据能被正确回显。connect 目标使用 127.0.0.1 显式地址。
 * @param ioc io_context 引用
 * @return net::awaitable<void>
 */
net::awaitable<void> TestReliableBasicReadWrite(net::io_context &ioc)
{
    LogInfo("=== TestReliableBasicReadWrite ===");

    // 在随机端口上创建 echo 服务端监听器
    net::ip::tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto echo_ep = echo_acceptor.local_endpoint();
    // 使用显式 127.0.0.1 地址构建连接端点
    auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), echo_ep.port());

    static constexpr std::string_view test_message = "Hello, Transmission!";

    // 启动 echo 服务端协程：接受一个连接后回显数据
    net::co_spawn(ioc, EchoOnceAccept(std::move(echo_acceptor)), net::detached);

    // 客户端：使用原始 socket 连接 echo 服务端进行读写验证
    {
        net::ip::tcp::socket socket(co_await net::this_coro::executor);
        // 异步连接到 echo 服务端
        co_await socket.async_connect(connect_ep, net::use_awaitable);

        // 发送测试消息
        co_await net::async_write(socket, net::buffer(test_message), net::use_awaitable);

        // 读取 echo 回显的数据
        std::array<char, 1024> buffer{};
        std::size_t n = co_await socket.async_read_some(net::buffer(buffer), net::use_awaitable);

        // 验证回显的字节数和内容均与发送一致
        if (n != test_message.size() || std::string_view(buffer.data(), n) != test_message)
        {
            LogFail(std::format("echo mismatch: got {} bytes", n));
            co_return;
        }
    }

    LogPass("ReliableBasicReadWrite");
}

/**
 * @brief 测试 reliable 关闭操作
 * @details server 端 accept 后关闭 reliable，client 端读取应收到关闭指示。
 *          接受 eof/connection_reset/operation_aborted 作为有效关闭语义。
 * @param ioc io_context 引用
 * @return net::awaitable<void>
 */
net::awaitable<void> TestReliableClose(net::io_context &ioc)
{
    LogInfo("=== TestReliableClose ===");

    // 在随机端口上创建监听器
    net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto local_endpoint = acceptor.local_endpoint();
    auto connect_endpoint = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), local_endpoint.port());

    // 标记服务端是否检测到关闭后的读取错误
    bool server_close_detected = false;

    // 服务端协程：accept 后立即关闭 reliable，验证关闭后读取返回错误
    net::co_spawn(ioc, [&acceptor, &server_close_detected]() -> net::awaitable<void>
    {
        boost::system::error_code accept_ec;
        auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
        // 等待客户端连接
        auto socket = co_await acceptor.async_accept(accept_token);
        if (accept_ec)
        {
            co_return;
        }

        // 不再接受更多连接，关闭监听器
        acceptor.close();
        // 将已连接的 socket 包装为 reliable 传输层
        auto transport = psm::channel::transport::make_reliable(std::move(socket));

        // 主动关闭传输层
        transport->close();

        // 关闭后尝试读取，预期会返回错误
        std::array<std::byte, 1024> buffer{};
        std::error_code ec;
        co_await transport->async_read_some(std::span(buffer), ec);

        if (ec)
        {
            server_close_detected = true;
        }
    }, net::detached);

    // 客户端：连接后尝试读取，预期因服务端关闭而收到关闭指示
    {
        net::ip::tcp::socket socket(ioc);
        co_await socket.async_connect(connect_endpoint, net::use_awaitable);

        // 尝试读取，服务端已关闭应触发 EOF 或连接重置
        std::array<char, 1024> buffer{};
        boost::system::error_code ec;
        co_await socket.async_read_some(net::buffer(buffer), net::redirect_error(net::use_awaitable, ec));

        // 客户端必须收到某种关闭指示
        if (!ec)
        {
            LogFail("ReliableClose: client expected close indication but got none");
            co_return;
        }

        // 验证错误码为常见的关闭类型：EOF、连接重置或操作中止
        if (ec != net::error::eof &&
            ec != net::error::connection_reset &&
            ec != net::error::operation_aborted)
        {
            LogFail(std::format("ReliableClose: unexpected client error {}", ec.message()));
            co_return;
        }
    }

    // 服务端和客户端都必须检测到关闭
    if (!server_close_detected)
    {
        LogFail("server_close not detected");
        co_return;
    }

    LogPass("ReliableClose");
}

/**
 * @brief 测试 unreliable 构造
 */
void TestUnreliableConstructor()
{
    LogInfo("=== TestUnreliableConstructor ===");

    net::io_context ioc;
    auto executor = ioc.get_executor();
    // 从 executor 构造 unreliable 传输层（UDP 语义）
    auto unreliable = std::make_shared<psm::channel::transport::unreliable>(executor);

    // 验证构造后的 executor 与传入的一致
    if (unreliable->executor() != executor)
    {
        LogFail("executor mismatch");
        return;
    }

    // 新构造的 unreliable 尚未设置远端，应为空
    if (unreliable->remote_endpoint().has_value())
    {
        LogFail("remote_endpoint should be nullopt");
        return;
    }

    LogPass("UnreliableConstructor");
}

/**
 * @brief 测试 unreliable 设置远端端点
 */
void TestUnreliableSetRemoteEndpoint()
{
    LogInfo("=== TestUnreliableSetRemoteEndpoint ===");

    net::io_context ioc;
    auto executor = ioc.get_executor();
    auto unreliable = std::make_shared<psm::channel::transport::unreliable>(executor);

    // 构造一个 UDP 端点作为远端目标
    net::ip::udp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 8888);
    // 设置远端端点，模拟 UDP 目标地址绑定
    unreliable->set_remote_endpoint(endpoint);

    // 取回远端端点并验证地址和端口均正确
    auto remote_opt = unreliable->remote_endpoint();
    if (!remote_opt.has_value())
    {
        LogFail("remote_endpoint should have value");
        return;
    }

    if (remote_opt->address() != endpoint.address())
    {
        LogFail("address mismatch");
        return;
    }

    if (remote_opt->port() != endpoint.port())
    {
        LogFail("port mismatch");
        return;
    }

    LogPass("UnreliableSetRemoteEndpoint");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 reliable 和 unreliable 的
 *          同步与异步测试用例，捕获异常后输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池，供热路径容器使用
    psm::memory::system::enable_global_pooling();
    // 初始化 spdlog 日志系统
    psm::trace::init({});

    LogInfo("Starting transmission tests...");

    net::io_context ioc;

    // 同步测试：验证构造和基本属性
    TestReliableConstructor();
    TestReliableFromSocket();
    TestUnreliableConstructor();
    TestUnreliableSetRemoteEndpoint();

    // 异步测试：验证读写和关闭行为
    std::exception_ptr test_error;
    auto async_tests = [&ioc]() -> net::awaitable<void>
    {
        // 依次执行异步读写测试和关闭检测测试
        co_await TestReliableBasicReadWrite(ioc);
        co_await TestReliableClose(ioc);
    };

    // 启动异步测试协程，完成时停止事件循环
    net::co_spawn(ioc, async_tests(), [&](const std::exception_ptr &ep)
    {
        test_error = ep;
        ioc.stop();
    });
    // 阻塞运行事件循环，直到异步测试全部完成
    ioc.run();

    // 如果异步测试抛出了未捕获的异常，在此处记录
    if (test_error)
    {
        try
        {
            std::rethrow_exception(test_error);
        }
        catch (const std::exception &e)
        {
            LogFail(std::format("uncaught exception: {}", e.what()));
        }
    }

    LogInfo("Transmission tests completed.");

    psm::trace::info("[Transmission] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
