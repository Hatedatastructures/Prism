/**
 * @file Socks5.cpp
 * @brief SOCKS5 协议中继握手测试
 * @details 验证 SOCKS5 协议完整握手流程和数据回显功能，包括：
 * 1. 方法协商 (版本5, 无认证)
 * 2. CONNECT 请求解析
 * 3. 成功响应发送
 * 4. Echo 数据双向传输
 */

#include <prism/protocol/socks5.hpp>
#include <prism/exception/network.hpp>
#include <prism/fault/code.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <array>
#include <vector>


#include <gtest/gtest.h>

namespace net = boost::asio;
namespace protocol = psm::protocol;
namespace transport = psm::transport;
using tcp = net::ip::tcp;

namespace
{
    /**
     * @brief SOCKS5 测试服务器协程
     * @details 接受一个连接，执行 SOCKS5 方法协商和 CONNECT 握手，
     *          然后读取客户端数据并原样回显，最后关闭连接。
     * @param acceptor TCP 接收器引用
     * @return net::awaitable<void>
     */
    net::awaitable<void> DoSocks5Server(tcp::acceptor &acceptor)
    {
        try
        {
            // 异步等待客户端连接，协程挂起直到有新连接到达
            auto socket = co_await acceptor.async_accept(net::use_awaitable);

            // 将原始 TCP socket 包装为可靠传输层
            auto reliable = transport::make_reliable(std::move(socket));
            // 基于 reliable 创建 SOCKS5 中继实例
            auto socks5 = std::make_shared<protocol::socks5::conn>(std::move(reliable));

            // 执行 SOCKS5 完整握手（方法协商 + CONNECT 请求解析）
            auto [ec, req] = co_await socks5->handshake();
            if (psm::fault::failed(ec))
            {
                co_return;
            }

            // 向客户端发送 CONNECT 成功响应，告知隧道已建立
            if (psm::fault::failed(co_await socks5->send_success(req)))
            {
                co_return;
            }

            // Echo 测试：读取客户端发送的数据并原样回显
            std::array<std::byte, 1024> buffer;

            // 从 SOCKS5 隧道中异步读取客户端载荷
            std::error_code read_ec;
            auto n = co_await socks5->async_read_some(std::span(buffer), read_ec);
            if (psm::fault::failed(psm::fault::to_code(read_ec)) || n == 0)
            {
                co_return;
            }
            // 将二进制缓冲区转换为字符串以便比对
            std::string received_msg(reinterpret_cast<const char *>(buffer.data()), n);

            // 将收到的消息通过同一隧道回写给客户端
            std::error_code write_ec;
            co_await socks5->async_write_some(
                std::span(reinterpret_cast<const std::byte *>(received_msg.data()), received_msg.size()),
                write_ec);
            if (psm::fault::failed(psm::fault::to_code(write_ec)))
            {
                co_return;
            }

            // 测试完成，关闭 SOCKS5 中继连接
            socks5->close();
        }
        catch (const std::exception &)
        {
        }
        co_return;
    }

    /**
     * @brief 模拟 SOCKS5 客户端握手（原始协议测试）
     * @details 按 RFC 1928 手动构造 SOCKS5 方法协商和 CONNECT 请求字节流，
     *          发送并解析服务端响应。支持 IPv4 地址和域名两种地址类型。
     * @param socket 已连接的 TCP socket 引用
     * @param host 目标主机地址
     * @param port 目标端口号
     * @return net::awaitable<void>
     */
    net::awaitable<void> RawSocks5Handshake(tcp::socket &socket, const std::string &host, uint16_t port)
    {
        // 构造方法协商请求：0x05=SOCKS版本5, 0x01=1种方法, 0x00=无认证
        std::array<uint8_t, 3> method_request = {0x05, 0x01, 0x00};
        co_await net::async_write(socket, net::buffer(method_request), net::use_awaitable);

        // 读取服务端的方法选择响应，应为 2 字节
        std::array<uint8_t, 2> method_response;
        co_await net::async_read(socket, net::buffer(method_response), net::use_awaitable);

        // 验证方法选择响应：版本号必须为 5，选中方法必须为无认证(0x00)
        if (method_response[0] != 0x05 || method_response[1] != 0x00)
        {
            throw psm::exception::network("SOCKS5 method negotiation failed");
        }

        // 构造 CONNECT 请求字节流
        std::vector<uint8_t> connect_request;
        connect_request.push_back(0x05); // SOCKS 版本号 5
        connect_request.push_back(0x01); // CONNECT 命令码
        connect_request.push_back(0x00); // 保留字段，必须为 0

        // 根据地址格式判断 ATYP 并写入对应地址字段
        if (host.find(':') != std::string::npos)
        {
            // 当前不支持 IPv6 地址的测试
            throw psm::exception::network("IPv6 address test not supported");
        }
        else if (host.find('.') != std::string::npos)
        {
            // ATYP=0x01 表示 IPv4 地址，固定 4 字节
            connect_request.push_back(0x01);
            // 硬编码 127.0.0.1 的网络字节序表示
            uint32_t ip = 0x7F000001;
            for (int i = 3; i >= 0; --i)
            {
                connect_request.push_back((ip >> (i * 8)) & 0xFF);
            }
        }
        else
        {
            // ATYP=0x03 表示域名，首字节为域名长度，后续为域名内容
            connect_request.push_back(0x03);
            connect_request.push_back(static_cast<uint8_t>(host.length()));
            connect_request.insert(connect_request.end(), host.begin(), host.end());
        }

        // 追加目标端口，按网络字节序（大端）写入 2 字节
        connect_request.push_back((port >> 8) & 0xFF);
        connect_request.push_back(port & 0xFF);

        co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

        // 读取服务端对 CONNECT 请求的响应
        std::array<uint8_t, 256> response{};
        std::size_t total_read = 0;

        try
        {
            total_read = co_await socket.async_read_some(net::buffer(response), net::use_awaitable);

            // 检查响应前两字节：版本号=5 且 回复码=0 表示成功
            if (total_read >= 4 && response[0] == 0x05 && response[1] == 0x00)
            {
                co_return;
            }
            else
            {
                // 回复码非零表示服务端拒绝了连接请求
                if (total_read > 0 && response[1] != 0x00)
                    throw psm::exception::network("SOCKS5 connection request rejected");
            }
        }
        catch (const boost::system::system_error &e)
        {
            // 如果因 EOF 中断但已收到足够数据，仍视为握手成功
            if (e.code() == boost::asio::error::eof && total_read >= 4)
            {
                if (response[0] == 0x05 && response[1] == 0x00)
                {
                    co_return;
                }
            }
            throw;
        }
        co_return;
    }
}

/**
 * @brief 测试 SOCKS5 协议完整握手与数据回显
 */
TEST(Socks5, RelayHandshake)
{
    // 创建 io_context 驱动异步事件循环
    net::io_context ioc;

    // 绑定到本地回环地址，端口 0 让操作系统自动分配可用端口
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    // 获取实际分配的端口号，供客户端连接使用
    auto bound_endpoint = acceptor.local_endpoint();

    // 用 shared_ptr 标记客户端是否完成全部测试
    auto client_ok = std::make_shared<bool>(false);

    // 启动服务端协程：接受连接并处理 SOCKS5 握手及回显
    net::co_spawn(ioc, DoSocks5Server(acceptor), net::detached);

    // 启动客户端协程：连接服务端并发起原始 SOCKS5 握手
    net::co_spawn(
        ioc,
        [endpoint = bound_endpoint, client_ok]() -> net::awaitable<void>
        {
            try
            {
                // 获取当前协程的执行器来创建 socket
                tcp::socket socket(co_await net::this_coro::executor);
                // 异步连接到测试服务端
                co_await socket.async_connect(endpoint, net::use_awaitable);

                // 执行原始 SOCKS5 握手（方法协商 + CONNECT）
                co_await RawSocks5Handshake(socket, "127.0.0.1", 8080);

                // 握手成功后通过隧道发送测试消息
                std::string test_msg = "Hello SOCKS5";
                co_await net::async_write(socket, net::buffer(test_msg), net::use_awaitable);

                // 读取服务端回显的数据
                std::array<char, 1024> buffer;
                auto n = co_await socket.async_read_some(net::buffer(buffer), net::use_awaitable);
                std::string received_msg(buffer.data(), n);

                // 验证回显内容与发送内容一致
                if (received_msg != test_msg)
                {
                    co_return;
                }

                socket.close();

                // 标记客户端全部流程通过
                *client_ok = true;
            }
            catch (const std::exception &)
            {
            }
        },
        net::detached);

    // 阻塞运行事件循环，直到所有异步操作完成
    ioc.run();

    // 根据客户端标记判定整体测试结果
    EXPECT_TRUE(*client_ok) << "SOCKS5 relay handshake and echo";
}
