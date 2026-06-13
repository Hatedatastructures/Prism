/**
 * @file Transmission.cpp
 * @brief 传输层接口和实现单元测试
 * @details 测试 transmission 抽象接口以及 reliable、unreliable 具体实现。
 * 验证构造、异步读写、关闭、远端端点等操作的正确性。
 */

#include <prism/net/transport/transmission.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/unreliable.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <memory>
#include <string_view>

namespace net = boost::asio;

namespace
{
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
    TEST(Transmission, ReliableConstructor)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        // 从 executor 构造 reliable 传输层，验证内部 executor 一致性
        auto reliable = psm::transport::make_reliable(executor);

        // 确保构造后的 executor 与传入的相同
        EXPECT_TRUE(reliable->executor() == executor)
            << "executor mismatch";
    }

    /**
     * @brief 测试 reliable 从 socket 构造
     */
    TEST(Transmission, ReliableFromSocket)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        // 创建一个未连接的 TCP socket
        net::ip::tcp::socket socket(executor);
        // 从已有 socket 构造 reliable 传输层，验证所有权转移后 executor 一致性
        auto reliable = psm::transport::make_reliable(std::move(socket));

        EXPECT_TRUE(reliable->executor() == executor)
            << "executor mismatch";
    }

    /**
     * @brief 测试 reliable 异步读写
     * @details 在同一个 io_context 上启动 echo server 和 client，验证通过 reliable
     *          传输层写入的数据能被正确回显。connect 目标使用 127.0.0.1 显式地址。
     */
    TEST(Transmission, ReliableBasicReadWrite)
    {
        net::io_context ioc;

        // 在随机端口上创建 echo 服务端监听器
        net::ip::tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto echo_ep = echo_acceptor.local_endpoint();
        // 使用显式 127.0.0.1 地址构建连接端点
        auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), echo_ep.port());

        static constexpr std::string_view test_message = "Hello, Transmission!";

        // 启动 echo 服务端协程：接受一个连接后回显数据
        net::co_spawn(ioc, EchoOnceAccept(std::move(echo_acceptor)), net::detached);

        std::exception_ptr ep;

        auto coro = [&]() -> net::awaitable<void>
        {
            // 客户端：使用原始 socket 连接 echo 服务端进行读写验证
            net::ip::tcp::socket socket(co_await net::this_coro::executor);
            // 异步连接到 echo 服务端
            co_await socket.async_connect(connect_ep, net::use_awaitable);

            // 发送测试消息
            co_await net::async_write(socket, net::buffer(test_message), net::use_awaitable);

            // 读取 echo 回显的数据
            std::array<char, 1024> buffer{};
            std::size_t n = co_await socket.async_read_some(net::buffer(buffer), net::use_awaitable);

            // 验证回显的字节数和内容均与发送一致
            EXPECT_TRUE(n == test_message.size() && std::string_view(buffer.data(), n) == test_message)
                << std::format("echo mismatch: got {} bytes", n);
        };

        net::co_spawn(ioc, coro(), [&ioc, &ep](const std::exception_ptr &e)
        {
            ep = e;
            ioc.stop();
        });
        ioc.run();

        if (ep)
            std::rethrow_exception(ep);
    }

    /**
     * @brief 测试 reliable 关闭操作
     * @details server 端 accept 后关闭 reliable，client 端读取应收到关闭指示。
     *          接受 eof/connection_reset/operation_aborted 作为有效关闭语义。
     */
    TEST(Transmission, ReliableClose)
    {
        net::io_context ioc;

        // 在随机端口上创建监听器
        net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto local_endpoint = acceptor.local_endpoint();
        auto connect_endpoint = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), local_endpoint.port());

        // 标记服务端是否检测到关闭后的读取错误
        auto server_close_detected = std::make_shared<bool>(false);

        std::exception_ptr ep;

        // 服务端协程：accept 后立即关闭 reliable，验证关闭后读取返回错误
        net::co_spawn(ioc, [&acceptor, server_close_detected]() -> net::awaitable<void>
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
            auto transport = psm::transport::make_reliable(std::move(socket));

            // 主动关闭传输层
            transport->close();

            // 关闭后尝试读取，预期会返回错误
            std::array<std::byte, 1024> buffer{};
            std::error_code ec;
            co_await transport->async_read_some(std::span(buffer), ec);

            if (ec)
            {
                *server_close_detected = true;
            }
        }, net::detached);

        // 客户端协程
        auto client_coro = [&]() -> net::awaitable<void>
        {
            net::ip::tcp::socket socket(co_await net::this_coro::executor);
            co_await socket.async_connect(connect_endpoint, net::use_awaitable);

            // 尝试读取，服务端已关闭应触发 EOF 或连接重置
            std::array<char, 1024> buffer{};
            boost::system::error_code ec;
            co_await socket.async_read_some(net::buffer(buffer), net::redirect_error(net::use_awaitable, ec));

            // 客户端必须收到某种关闭指示
            if (!ec)
            {
                ADD_FAILURE() << "ReliableClose: client expected close indication but got none";
                co_return;
            }

            // 验证错误码为常见的关闭类型：EOF、连接重置或操作中止
            EXPECT_TRUE(ec == net::error::eof ||
                        ec == net::error::connection_reset ||
                        ec == net::error::operation_aborted)
                << std::format("ReliableClose: unexpected client error {}", ec.message());
        };

        net::co_spawn(ioc, client_coro(), [&ioc, &ep](const std::exception_ptr &e)
        {
            ep = e;
            ioc.stop();
        });
        ioc.run();

        if (ep)
            std::rethrow_exception(ep);

        // 服务端和客户端都必须检测到关闭
        EXPECT_TRUE(*server_close_detected) << "server_close not detected";
    }

    /**
     * @brief 测试 unreliable 构造
     */
    TEST(Transmission, UnreliableConstructor)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        // 从 executor 构造 unreliable 传输层（UDP 语义）
        auto unreliable = std::make_shared<psm::transport::unreliable>(executor);

        // 验证构造后的 executor 与传入的一致
        EXPECT_TRUE(unreliable->executor() == executor)
            << "executor mismatch";

        // 新构造的 unreliable 尚未设置远端，应为空
        EXPECT_TRUE(!unreliable->remote_endpoint().has_value())
            << "remote_endpoint should be nullopt";
    }

    /**
     * @brief 测试 unreliable 设置远端端点
     */
    TEST(Transmission, UnreliableSetRemoteEndpoint)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        auto unreliable = std::make_shared<psm::transport::unreliable>(executor);

        // 构造一个 UDP 端点作为远端目标
        net::ip::udp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 8888);
        // 设置远端端点，模拟 UDP 目标地址绑定
        unreliable->set_remote(endpoint);

        // 取回远端端点并验证地址和端口均正确
        auto remote_opt = unreliable->remote_endpoint();
        ASSERT_TRUE(remote_opt.has_value()) << "remote_endpoint should have value";

        EXPECT_TRUE(remote_opt->address() == endpoint.address())
            << "address mismatch";
        EXPECT_TRUE(remote_opt->port() == endpoint.port())
            << "port mismatch";
    }
} // namespace
