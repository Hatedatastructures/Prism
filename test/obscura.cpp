#include <forward-engine/transport/obscura.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <iostream>
#include <thread>
#include <string>
#include <memory>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = net::ip::tcp;

/**
 * @brief 使用 obscura 的测试服务器协程
 * @param acceptor TCP 接收器
 * @param ctx SSL 上下文
 * @param expected_path 预期的 WebSocket 请求路径
 * @return net::awaitable<void>
 */
net::awaitable<void> do_server(tcp::acceptor &acceptor, std::shared_ptr<ssl::context> ctx, std::string expected_path)
{
    try 
    {
        auto socket = co_await acceptor.async_accept(net::use_awaitable);
        
        // 创建 obscura 实例并显式指定服务器角色
        auto agent = std::make_shared<ngx::transport::obscura<tcp>>(std::move(socket), ctx, ngx::transport::role::server);

        // 执行握手并获取请求路径
        std::string path = co_await agent->handshake();

        if (path != expected_path)
        {
            std::cerr << "服务器错误: 路径不匹配，收到 " << path << "，预期 " << expected_path << std::endl;
            co_await agent->close();
            co_return;
        }

        // 使用外部缓冲区读取消息
        beast::flat_buffer buffer;
        co_await agent->async_read(buffer);
        std::string msg = beast::buffers_to_string(buffer.data());

        // 将收到消息回显给客户端
        co_await agent->async_write(msg);

        // 优雅地关闭连接
        co_await agent->close();
    }
    catch (const std::exception &e)
    {
        std::cerr << "服务器发生异常: " << e.what() << std::endl;
    }
}

/**
 * @brief 使用 obscura 的测试客户端协程
 * @param endpoint 目标服务器端口
 * @param ctx SSL 上下文
 * @param path 请求的 WebSocket 路径
 * @param expected_msg 发送并预期回显的消息内容
 * @param expect_success 是否预期操作成功
 * @return net::awaitable<void>
 */
net::awaitable<void> do_client(tcp::endpoint endpoint, std::shared_ptr<ssl::context> ctx, std::string path, std::string expected_msg, bool expect_success)
{
    try
    {
        tcp::socket socket(co_await net::this_coro::executor);
        co_await socket.async_connect(endpoint, net::use_awaitable);

        auto agent = std::make_shared<ngx::transport::obscura<tcp>>(std::move(socket), ctx, ngx::transport::role::client);

        // 执行 WebSocket 握手
        try
        {
            // 客户端模式：传递主机和路径
            co_await agent->handshake("127.0.0.1", path);
        }
        catch (const std::exception &e)
        {
            if (expect_success)
            {
                std::cerr << "客户端握手失败: " << e.what() << std::endl;
                throw;
            }
            // 预期内的失败，直接返回
            co_return;
        }

        if (!expect_success)
        {
            try
            {
                co_await agent->async_write(expected_msg);
                beast::flat_buffer buffer;
                co_await agent->async_read(buffer);
                throw std::runtime_error("预期服务器拒绝连接，但读写仍然成功");
            }
            catch (const std::exception &)
            {
                co_return;
            }
        }

        // 发送测试消息
        co_await agent->async_write(expected_msg);

        // 读取服务器回显的消息
        beast::flat_buffer buffer;
        co_await agent->async_read(buffer);

        std::string reply = beast::buffers_to_string(buffer.data());
        if (reply != expected_msg)
        {
            throw std::runtime_error("消息回显校验失败: 收到 " + reply + "，预期 " + expected_msg);
        }

        // 优雅地关闭连接
        co_await agent->close();
    }
    catch (const std::exception &e)
    {
        if (expect_success)
        {
            std::cerr << "客户端发生异常: " << e.what() << std::endl;
            throw;
        }
    }
}

/**
 * @brief 测试入口函数
 * @return int 状态码
 */
int main()
{
    std::cout << "正在启动 Obscura 协议测试..." << std::endl;
    try
    {
        net::io_context ioc;

        // 初始化服务器 SSL 上下文
        auto server_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        // 使用相对路径或假设文件存在
        server_ctx->use_certificate_chain_file("cert.pem");
        server_ctx->use_private_key_file("key.pem", ssl::context::pem);

        // 初始化客户端 SSL 上下文，忽略证书验证（用于自签名证书测试）
        auto client_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        client_ctx->set_verify_mode(ssl::verify_none);

        // 绑定本地地址并启动接收器
        tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
        tcp::acceptor acceptor(ioc, endpoint);
        auto bound_endpoint = acceptor.local_endpoint();

        std::string secret_path = "/secret";

        // 测试用例 1：正常的握手、读写和关闭
        std::cout << "运行测试用例 1: 正常连接测试..." << std::endl;
        net::co_spawn(ioc, do_server(acceptor, server_ctx, secret_path), net::detached);
        net::co_spawn(ioc, do_client(bound_endpoint, client_ctx, secret_path, "Hello ForwardEngine", true), net::detached);

        // 测试用例 2：错误的请求路径，验证服务器是否正确拒绝
        std::cout << "运行测试用例 2: 错误路径拒绝测试..." << std::endl;
        net::co_spawn(ioc, do_server(acceptor, server_ctx, secret_path), net::detached);
        net::co_spawn(ioc, do_client(bound_endpoint, client_ctx, "/wrong_path", "Should fail", false), net::detached);

        // 运行 I/O 事件循环
        ioc.run();

        std::cout << "\n所有 Obscura 协议测试已完成并通过！" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "\n测试失败，捕获到致命异常: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
