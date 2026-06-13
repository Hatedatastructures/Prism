/**
 * @file TransportLayer.cpp
 * @brief 传输层单元测试
 * @details 测试 reliable、preview、encrypted 三种传输层实现。
 * 验证构造、异步读写、预读回放、关闭等操作的正确性。
 */

#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/preview.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <format>
#include <memory>
#include <span>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;
namespace ssl = net::ssl;

namespace
{
    // ============================================================
    // 辅助协程
    // ============================================================

    /**
     * @brief 回显处理（单 socket）
     * @details 循环读取 socket 数据并原样写回，直到对端关闭或出错。
     * @param socket 已连接的 TCP socket（按值接管所有权）
     * @return net::awaitable<void>
     */
    net::awaitable<void> EchoOnce(net::ip::tcp::socket socket)
    {
        std::array<char, 4096> buf{};
        while (true)
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            const auto n = co_await socket.async_read_some(net::buffer(buf), token);
            if (ec || n == 0)
            {
                co_return;
            }
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
        auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
        auto socket = co_await acceptor.async_accept(accept_token);
        if (accept_ec)
        {
            co_return;
        }
        co_await EchoOnce(std::move(socket));
    }

    /**
     * @brief 服务端协程：写入指定数据后关闭
     * @details 接受一个连接，写入指定数据，然后关闭写端。
     * 用于 preview 测试中模拟服务端发送数据。
     * @param acceptor TCP 接收器（按值接管所有权）
     * @param data 要发送的数据
     * @return net::awaitable<void>
     */
    net::awaitable<void> SendOnceAndClose(net::ip::tcp::acceptor acceptor, std::string_view data)
    {
        boost::system::error_code ec;
        auto socket = co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }
        co_await net::async_write(socket, net::buffer(data), net::redirect_error(net::use_awaitable, ec));
        if (!ec)
        {
            socket.shutdown(net::ip::tcp::socket::shutdown_send, ec);
        }
    }

    // ============================================================
    // 异步测试辅助：运行单个协程并检查异常
    // ============================================================

    void run_test_coroutine(net::awaitable<void> coro)
    {
        net::io_context ioc;
        std::exception_ptr test_error;
        net::co_spawn(ioc, std::move(coro), [&](const std::exception_ptr &ep)
        {
            test_error = ep;
            ioc.stop();
        });
        ioc.run();
        if (test_error)
        {
            try
            {
                std::rethrow_exception(test_error);
            }
            catch (const std::exception &e)
            {
                FAIL() << std::format("uncaught exception: {}", e.what());
            }
        }
    }

    // ============================================================
    // Reliable 测试
    // ============================================================

    /**
     * @brief 测试 reliable 从 executor 构造
     */
    TEST(TransportLayer, ReliableConstructor)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        auto reliable = psm::transport::make_reliable(executor);

        EXPECT_TRUE(reliable != nullptr) << "ReliableConstructor: non-null";
        EXPECT_TRUE(reliable->executor() == executor) << "ReliableConstructor: executor matches";
        EXPECT_TRUE(reliable->transport_type() == psm::transport::transmission::type::tcp)
            << "ReliableConstructor: transport type is tcp";
        EXPECT_TRUE(reliable->next_layer() == nullptr) << "ReliableConstructor: next_layer is null";
    }

    /**
     * @brief 测试 reliable 从 socket 构造
     */
    TEST(TransportLayer, ReliableFromSocket)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();
        net::ip::tcp::socket socket(executor);
        auto reliable = psm::transport::make_reliable(std::move(socket));

        EXPECT_TRUE(reliable != nullptr) << "ReliableFromSocket: non-null";
        EXPECT_TRUE(reliable->executor() == executor) << "ReliableFromSocket: executor matches";
    }

    /**
     * @brief 测试 reliable 异步读写
     */
    net::awaitable<void> ReliableReadWriteCoro()
    {
        auto executor = co_await net::this_coro::executor;

        // 在随机端口上创建 echo 服务端监听器
        net::ip::tcp::acceptor echo_acceptor(executor,
                                              net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto echo_ep = echo_acceptor.local_endpoint();
        auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), echo_ep.port());

        static constexpr std::string_view test_message = "Hello, Transport!";

        // 启动 echo 服务端协程
        net::co_spawn(executor, EchoOnceAccept(std::move(echo_acceptor)), net::detached);

        // 客户端：连接 echo 服务器并验证读写
        net::ip::tcp::socket socket(executor);
        co_await socket.async_connect(connect_ep, net::use_awaitable);

        // 包装为 reliable 传输层
        auto transport = psm::transport::make_reliable(std::move(socket));

        // 通过 reliable 写入测试消息
        std::array<std::byte, 64> write_buf{};
        std::memcpy(write_buf.data(), test_message.data(), test_message.size());
        std::error_code write_ec;
        const auto written = co_await psm::transport::async_write(
            *transport, std::span<const std::byte>{write_buf.data(), test_message.size()}, write_ec);

        EXPECT_TRUE(!write_ec) << "ReliableReadWrite: write no error";
        EXPECT_TRUE(written == test_message.size()) << "ReliableReadWrite: write complete";

        // 通过 reliable 读取回显
        std::array<std::byte, 128> read_buf{};
        std::error_code read_ec;
        const auto n = co_await psm::transport::async_read(
            *transport, std::span<std::byte>{read_buf.data(), test_message.size()}, read_ec);

        EXPECT_TRUE(!read_ec) << "ReliableReadWrite: read no error";
        EXPECT_TRUE(n == test_message.size()) << "ReliableReadWrite: read size matches";

        const auto received = std::string_view(
            reinterpret_cast<const char *>(read_buf.data()), n);
        EXPECT_TRUE(received == test_message) << "ReliableReadWrite: echo content matches";

        transport->close();
    }

    TEST(TransportLayer, ReliableReadWrite)
    {
        run_test_coroutine(ReliableReadWriteCoro());
    }

    /**
     * @brief 测试 reliable 关闭操作
     */
    net::awaitable<void> ReliableCloseCoro()
    {
        auto executor = co_await net::this_coro::executor;

        net::ip::tcp::acceptor acceptor(executor,
                                         net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto local_ep = acceptor.local_endpoint();
        auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), local_ep.port());

        bool server_read_error = false;

        // 服务端协程：accept 后关闭 reliable，验证关闭后读取返回错误
        net::co_spawn(executor,
            [&acceptor, &server_read_error]() -> net::awaitable<void>
            {
                auto socket = co_await acceptor.async_accept(net::use_awaitable);
                acceptor.close();

                auto transport = psm::transport::make_reliable(std::move(socket));
                transport->close();

                std::array<std::byte, 64> buf{};
                std::error_code ec;
                co_await transport->async_read_some(std::span(buf), ec);

                if (ec)
                {
                    server_read_error = true;
                }
            }, net::detached);

        // 客户端：连接后尝试读取，预期因服务端关闭而收到关闭指示
        {
            net::ip::tcp::socket socket(executor);
            co_await socket.async_connect(connect_ep, net::use_awaitable);

            std::array<char, 64> buf{};
            boost::system::error_code ec;
            co_await socket.async_read_some(
                net::buffer(buf), net::redirect_error(net::use_awaitable, ec));

            EXPECT_TRUE(ec == net::error::eof ||
                        ec == net::error::connection_reset ||
                        ec == net::error::operation_aborted)
                << "ReliableClose: client detects close";
        }

        // 等待服务端协程完成
        net::steady_timer timer(executor);
        timer.expires_after(std::chrono::milliseconds(50));
        co_await timer.async_wait(net::use_awaitable);

        EXPECT_TRUE(server_read_error) << "ReliableClose: server read after close returns error";
    }

    TEST(TransportLayer, ReliableClose)
    {
        run_test_coroutine(ReliableCloseCoro());
    }

    // ============================================================
    // Preview 测试
    // ============================================================

    /**
     * @brief 测试 preview 构造和基本属性
     */
    TEST(TransportLayer, PreviewConstruction)
    {
        net::io_context ioc;
        auto reliable = psm::transport::make_reliable(ioc.get_executor());

        const std::array<std::byte, 4> preread = {
            std::byte{'A'}, std::byte{'B'}, std::byte{'C'}, std::byte{'D'}};

        auto prev = std::make_shared<psm::transport::preview>(
            reliable, std::span<const std::byte>{preread});

        EXPECT_TRUE(prev != nullptr) << "PreviewConstruction: non-null";
        EXPECT_TRUE(prev->next_layer() != nullptr) << "PreviewConstruction: next_layer non-null";
        EXPECT_TRUE(prev->next_layer() == reliable.get()) << "PreviewConstruction: next_layer is reliable";
        EXPECT_TRUE(prev->transport_type() == psm::transport::transmission::type::tcp)
            << "PreviewConstruction: transport type is tcp";
        EXPECT_TRUE(prev->executor() == reliable->executor()) << "PreviewConstruction: executor matches inner";

        // wrap_with_preview 辅助函数：空数据时应返回原始传输
        auto original = psm::transport::make_reliable(ioc.get_executor());
        auto wrapped = psm::transport::wrap_with_preview(original, {});
        EXPECT_TRUE(wrapped == original) << "PreviewConstruction: wrap_with_preview empty returns original";

        // wrap_with_preview 辅助函数：非空数据应返回 preview
        auto inner = psm::transport::make_reliable(ioc.get_executor());
        auto wrapped2 = psm::transport::wrap_with_preview(inner, std::span<const std::byte>{preread});
        EXPECT_TRUE(wrapped2 != inner) << "PreviewConstruction: wrap_with_preview non-empty returns new";
        EXPECT_TRUE(wrapped2->next_layer() != nullptr) << "PreviewConstruction: wrapped next_layer non-null";
    }

    /**
     * @brief 测试 preview 预读数据回放
     */
    net::awaitable<void> PreviewPrereadReplayCoro()
    {
        auto executor = co_await net::this_coro::executor;

        // 在随机端口上创建服务端
        net::ip::tcp::acceptor acceptor(executor,
                                         net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto server_ep = acceptor.local_endpoint();
        auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), server_ep.port());

        // 服务端发送 10 字节后关闭写端
        static constexpr std::string_view server_data = "ABCDEFGHIJ";
        net::co_spawn(executor, SendOnceAndClose(std::move(acceptor), server_data), net::detached);

        // 客户端：先从原始 socket 读取 4 字节，再用 preview 包装
        net::ip::tcp::socket socket(executor);
        co_await socket.async_connect(connect_ep, net::use_awaitable);

        // 先用原始 socket 读取前 4 字节（模拟协议探测阶段读取）
        std::array<char, 4> probe_buf{};
        boost::system::error_code probe_ec;
        auto token = net::redirect_error(net::use_awaitable, probe_ec);
        auto probe_n = co_await socket.async_read_some(net::buffer(probe_buf), token);

        EXPECT_TRUE(!probe_ec) << "PreviewPrereadReplay: probe read no error";
        EXPECT_TRUE(probe_n == 4) << "PreviewPrereadReplay: probe read 4 bytes";
        EXPECT_TRUE(std::string_view(probe_buf.data(), probe_n) == "ABCD")
            << "PreviewPrereadReplay: probe content is ABCD";

        // 将剩余 socket 包装为 reliable
        auto reliable = psm::transport::make_reliable(std::move(socket));

        // 构造 preread 数据（来自 probe 阶段的 4 字节）
        std::array<std::byte, 4> preread = {
            std::byte{'A'}, std::byte{'B'}, std::byte{'C'}, std::byte{'D'}};

        auto prev = std::make_shared<psm::transport::preview>(
            reliable, std::span<const std::byte>{preread});

        // 第一次读取：应从预读缓冲区返回（最多 min(4, buffer_size)）
        std::array<std::byte, 64> read_buf1{};
        std::error_code read_ec1;
        const auto n1 = co_await prev->async_read_some(std::span<std::byte>{read_buf1}, read_ec1);

        EXPECT_TRUE(!read_ec1) << "PreviewPrereadReplay: first read no error";
        EXPECT_TRUE(n1 == 4) << "PreviewPrereadReplay: first read returns 4 preread bytes";

        const auto got1 = std::string_view(reinterpret_cast<const char *>(read_buf1.data()), n1);
        EXPECT_TRUE(got1 == "ABCD") << "PreviewPrereadReplay: first read content is ABCD";

        // 第二次读取：预读已耗尽，委托给内部 reliable 从 socket 读取
        std::array<std::byte, 64> read_buf2{};
        std::error_code read_ec2;
        const auto n2 = co_await prev->async_read_some(std::span<std::byte>{read_buf2}, read_ec2);

        EXPECT_TRUE(!read_ec2) << "PreviewPrereadReplay: second read no error";
        EXPECT_TRUE(n2 > 0) << "PreviewPrereadReplay: second read returns data";

        const auto got2 = std::string_view(reinterpret_cast<const char *>(read_buf2.data()), n2);
        // 剩余服务端数据为 "EFGHIJ"（6 字节）
        EXPECT_TRUE(got2 == "EFGHIJ") << "PreviewPrereadReplay: second read content is EFGHIJ";

        prev->close();
    }

    TEST(TransportLayer, PreviewPrereadReplay)
    {
        run_test_coroutine(PreviewPrereadReplayCoro());
    }

    /**
     * @brief 测试 preview 写入委托
     */
    net::awaitable<void> PreviewWritePassthroughCoro()
    {
        auto executor = co_await net::this_coro::executor;

        // 创建 echo 服务器
        net::ip::tcp::acceptor echo_acceptor(executor,
                                              net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        auto echo_ep = echo_acceptor.local_endpoint();
        auto connect_ep = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), echo_ep.port());

        net::co_spawn(executor, EchoOnceAccept(std::move(echo_acceptor)), net::detached);

        // 客户端连接
        net::ip::tcp::socket socket(executor);
        co_await socket.async_connect(connect_ep, net::use_awaitable);

        auto reliable = psm::transport::make_reliable(std::move(socket));

        // 空预读数据的 preview（纯透传）
        auto prev = psm::transport::wrap_with_preview(reliable, {});

        // 通过 preview 写入
        static constexpr std::string_view test_msg = "PreviewWrite";
        std::array<std::byte, 64> write_buf{};
        std::memcpy(write_buf.data(), test_msg.data(), test_msg.size());

        std::error_code write_ec;
        const auto written = co_await prev->async_write_some(
            std::span<const std::byte>{write_buf.data(), test_msg.size()}, write_ec);

        EXPECT_TRUE(!write_ec) << "PreviewWritePassthrough: write no error";
        EXPECT_TRUE(written == test_msg.size()) << "PreviewWritePassthrough: write complete";

        // 读取回显
        std::array<std::byte, 128> read_buf{};
        std::error_code read_ec;
        const auto n = co_await psm::transport::async_read(
            *prev, std::span<std::byte>{read_buf.data(), test_msg.size()}, read_ec);

        EXPECT_TRUE(!read_ec) << "PreviewWritePassthrough: read no error";
        EXPECT_TRUE(n == test_msg.size()) << "PreviewWritePassthrough: read size matches";

        const auto received = std::string_view(
            reinterpret_cast<const char *>(read_buf.data()), n);
        EXPECT_TRUE(received == test_msg) << "PreviewWritePassthrough: echo content matches";

        prev->close();
    }

    TEST(TransportLayer, PreviewWritePassthrough)
    {
        run_test_coroutine(PreviewWritePassthroughCoro());
    }

    // ============================================================
    // Encrypted 测试
    // ============================================================

    /**
     * @brief 测试 encrypted 构造和基本属性
     * @details 创建 ssl::stream<connector> 并包装为 encrypted，
     *          验证类型、next_layer、executor 等属性。
     */
    TEST(TransportLayer, EncryptedConstructor)
    {
        net::io_context ioc;
        auto executor = ioc.get_executor();

        // 创建 reliable 传输层（使用未连接的 socket）
        net::ip::tcp::socket socket(executor);
        auto reliable_transport = psm::transport::make_reliable(std::move(socket));

        // 创建 connector 适配器
        auto conn = psm::transport::connector(reliable_transport);

        // 创建 SSL 上下文
        ssl::context ssl_ctx(ssl::context::tlsv12);

        // 创建 TLS 流
        auto ssl_stream = std::make_shared<psm::transport::encrypted::stream_type>(
            std::move(conn), ssl_ctx);

        // 创建 encrypted 传输层
        auto enc = std::make_shared<psm::transport::encrypted>(ssl_stream);

        EXPECT_TRUE(enc != nullptr) << "EncryptedConstructor: non-null";
        EXPECT_TRUE(enc->transport_type() == psm::transport::transmission::type::tcp)
            << "EncryptedConstructor: transport type is tcp";
        EXPECT_TRUE(enc->next_layer() == nullptr) << "EncryptedConstructor: next_layer is null";
        EXPECT_TRUE(enc->executor() == executor) << "EncryptedConstructor: executor matches";

        // 验证 stream 访问器
        EXPECT_TRUE(&enc->stream() == ssl_stream.get()) << "EncryptedConstructor: stream accessor";

        // 验证 release 转移所有权
        auto released = enc->release();
        EXPECT_TRUE(released == ssl_stream) << "EncryptedConstructor: release returns stream";

        // make_encrypted 工厂函数
        auto ssl_stream2 = std::make_shared<psm::transport::encrypted::stream_type>(
            psm::transport::connector(reliable_transport), ssl_ctx);
        auto enc2 = psm::transport::make_encrypted(ssl_stream2);
        EXPECT_TRUE(enc2 != nullptr) << "EncryptedConstructor: make_encrypted non-null";
    }

} // namespace
