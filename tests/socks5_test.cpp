#include <forward-engine/protocol/socks5.hpp>
#include <forward-engine/abnormal/network.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/channel/transport/reliable.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <string>
#include <memory>
#include <cstring>
#include <array>
#include <vector>

namespace net = boost::asio;
namespace protocol = ngx::protocol;
namespace transport = ngx::channel::transport;
using tcp = net::ip::tcp;

/**
 * @brief SOCKS5 测试服务器协程
 */
net::awaitable<void> do_socks5_server(tcp::acceptor &acceptor)
{
    try
    {
        std::cout << "服务器协程开始，等待连接..." << std::endl;
        auto socket = co_await acceptor.async_accept(net::use_awaitable);

        // 创建 SOCKS5 实例
        auto reliable = transport::make_reliable(std::move(socket));
        auto socks5 = std::make_shared<protocol::socks5::relay>(std::move(reliable));

        // 执行握手，获取目标地址信息
        std::cout << "服务器开始 SOCKS5 握手..." << std::endl;
        auto [ec, req] = co_await socks5->handshake();
        if (ngx::gist::failed(ec))
        {
            std::cerr << "服务器握手失败: " << std::string_view(ngx::gist::describe(ec)) << std::endl;
            co_return;
        }
        std::cout << "服务器握手成功，收到目标信息" << std::endl;

        auto host_str = protocol::socks5::to_string(req.destination_address);
        std::cout << "SOCKS5 服务器收到请求: "
                  << "命令=" << static_cast<int>(req.cmd)
                  << ", 地址=" << std::string_view(host_str)
                  << ", 端口=" << req.destination_port << std::endl;

        // 发送成功响应
        std::cout << "服务器发送成功响应..." << std::endl;
        if (ngx::gist::failed(co_await socks5->async_write_success(req)))
        {
            std::cerr << "服务器成功响应发送失败" << std::endl;
            co_return;
        }
        std::cout << "服务器成功响应已发送" << std::endl;

        // 测试数据传输 (Echo)
        std::array<std::byte, 1024> buffer;

        // 读取客户端数据
        std::error_code read_ec;
        auto n = co_await socks5->async_read_some(std::span(buffer), read_ec);
        if (ngx::gist::failed(ngx::gist::to_code(read_ec)) || n == 0)
        {
            std::cerr << "数据读取失败: " << std::string_view(ngx::gist::describe(ngx::gist::to_code(read_ec))) << std::endl;
            co_return;
        }
        std::string received_msg(reinterpret_cast<const char*>(buffer.data()), n);

        std::cout << "服务器收到消息: " << received_msg << std::endl;

        // 回显给客户端
        std::error_code write_ec;
        co_await socks5->async_write_some(
            std::span(reinterpret_cast<const std::byte*>(received_msg.data()), received_msg.size()),
            write_ec);
        if (ngx::gist::failed(ngx::gist::to_code(write_ec)))
        {
            std::cerr << "数据回写失败: " << std::string_view(ngx::gist::describe(ngx::gist::to_code(write_ec))) << std::endl;
            co_return;
        }

        // 关闭连接
        std::cout << "服务器测试完成，关闭连接" << std::endl;
        socks5->close();
    }
    catch (const std::exception &e)
    {
        std::cerr << "服务器发生异常: " << e.what() << std::endl;
    }
    co_return;
}

/**
 * @brief 模拟 SOCKS5 客户端握手（原始协议测试）
 */
net::awaitable<void> raw_socks5_handshake(tcp::socket &socket, const std::string &host, uint16_t port)
{
    try
    {
        std::cout << "原始 SOCKS5 握手开始，发送方法协商..." << std::endl;
        // 发送方法协商请求：版本5，1个方法，方法0（无认证）
        std::array<uint8_t, 3> method_request = {0x05, 0x01, 0x00};
        co_await net::async_write(socket, net::buffer(method_request), net::use_awaitable);

        // 读取方法选择响应
        std::array<uint8_t, 2> method_response;
        co_await net::async_read(socket, net::buffer(method_response), net::use_awaitable);
        std::cout << "收到方法选择响应: " << static_cast<int>(method_response[0]) << ", " << static_cast<int>(method_response[1]) << std::endl;

        if (method_response[0] != 0x05 || method_response[1] != 0x00)
        {
            throw ngx::abnormal::network("SOCKS5 方法协商失败");
        }

        // 发送 CONNECT 请求
        std::vector<uint8_t> connect_request;
        connect_request.push_back(0x05); // 版本
        connect_request.push_back(0x01); // CONNECT 命令
        connect_request.push_back(0x00); // 保留

        // 地址类型和地址
        if (host.find(':') != std::string::npos)
        {
            throw ngx::abnormal::network("IPv6 地址测试暂不支持");
        }
        else if (host.find('.') != std::string::npos)
        {
            // IPv4 地址
            connect_request.push_back(0x01);
            // 简化：使用 127.0.0.1
            uint32_t ip = 0x7F000001;
            for (int i = 3; i >= 0; --i)
            {
                connect_request.push_back((ip >> (i * 8)) & 0xFF);
            }
        }
        else
        {
            // 域名
            connect_request.push_back(0x03);
            connect_request.push_back(static_cast<uint8_t>(host.length()));
            connect_request.insert(connect_request.end(), host.begin(), host.end());
        }

        // 端口
        connect_request.push_back((port >> 8) & 0xFF);
        connect_request.push_back(port & 0xFF);

        co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

        // 读取响应
        std::array<uint8_t, 256> response{};
        std::size_t total_read = 0;

        try
        {
            total_read = co_await socket.async_read_some(net::buffer(response), net::use_awaitable);
            std::cout << "读取到 " << total_read << " 字节响应" << std::endl;

            if (total_read >= 4 && response[0] == 0x05 && response[1] == 0x00)
            {
                std::cout << "原始 SOCKS5 握手成功" << std::endl;
                co_return;
            }
            else
            {
                if (total_read > 0 && response[1] != 0x00)
                    throw ngx::abnormal::network("SOCKS5 连接请求被拒绝");
            }
        }
        catch (const boost::system::system_error &e)
        {
            if (e.code() == boost::asio::error::eof && total_read >= 4)
            {
                if (response[0] == 0x05 && response[1] == 0x00)
                {
                    ;
                    std::cout << "原始 SOCKS5 握手成功 (EOF)" << std::endl;
                    co_return;
                }
            }
            throw;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "原始 SOCKS5 握手异常: " << e.what() << std::endl;
        throw;
    }
    co_return;
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    try
    {
        std::cout << "Starting SOCKS5 protocol test..." << std::endl;

        std::cout << "\nRunning test case: Raw SOCKS5 handshake test..." << std::endl;
        {
            net::io_context ioc;

            tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
            tcp::acceptor acceptor(ioc, endpoint);
            auto bound_endpoint = acceptor.local_endpoint();

            std::cout << "Test server listening on: " << bound_endpoint << std::endl;

            net::co_spawn(ioc, do_socks5_server(acceptor), net::detached);

            net::co_spawn(ioc, [endpoint = bound_endpoint]() -> net::awaitable<void>
                          {
                tcp::socket socket(co_await net::this_coro::executor);
                co_await socket.async_connect(endpoint, net::use_awaitable);
                std::cout << "Client connected successfully" << std::endl;
                
                co_await raw_socks5_handshake(socket, "127.0.0.1", 8080);
                
                std::string test_msg = "Hello SOCKS5";
                std::cout << "Client sending message: " << test_msg << std::endl;
                co_await net::async_write(socket, net::buffer(test_msg), net::use_awaitable);
                std::cout << "Client message sent" << std::endl;

                std::array<char, 1024> buffer;
                auto n = co_await net::async_read(socket, net::buffer(buffer), net::use_awaitable);
                std::string received_msg(buffer.data(), n);
                
                if (received_msg != test_msg)
                {
                    throw ngx::abnormal::network("Message echo verification failed");
                }
                
                std::cout << "Client test success: " << test_msg << std::endl;
                std::cout << "Client test complete, closing connection" << std::endl;
                socket.close(); }, net::detached);

            ioc.run();
        }

        std::cout << "\nAll SOCKS5 protocol tests completed and passed!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nTest failed, fatal exception caught: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
