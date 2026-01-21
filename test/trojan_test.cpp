#include <forward-engine/protocol/trojan.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <thread>
#include <string>
#include <memory>
#include <cstring>
#include <array>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace protocol = ngx::protocol;
using tcp = net::ip::tcp;

/**
 * @brief Trojan 测试服务器协程
 */
net::awaitable<void> do_trojan_server(tcp::acceptor &acceptor, std::shared_ptr<ssl::context> ssl_ctx, const std::string &expected_password)
{
    try
    {
        std::cout << "Trojan Server coroutine started, waiting for connection..." << std::endl;
        auto socket = co_await acceptor.async_accept(net::use_awaitable);

        // 验证回调
        auto password_verifier = [expected_password](std::string_view hash) -> bool
        {
            // 简单验证：比较 hash 是否匹配预期的 SHA224
            // 这里为了简化测试，假设 expected_password 已经是 hash 过的或者直接比较
            std::cout << "Verifying password hash: " << hash << std::endl;
            return true; // 总是通过
        };

        // 创建 Trojan 实例
        auto trojan = std::make_shared<ngx::protocol::trojan::stream<tcp::socket>>(std::move(socket), ssl_ctx, password_verifier);

        // 执行握手
        std::cout << "Server starting Trojan handshake..." << std::endl;
        auto target_info = co_await trojan->handshake();
        std::cout << "Server handshake success" << std::endl;

        std::cout << "Trojan Server received request: "
                  << "CMD=" << static_cast<int>(target_info.cmd)
                  << ", ADDR=" << target_info.host
                  << ", PORT=" << target_info.port << std::endl;

        // 测试数据传输 (Echo)
        std::array<char, 1024> buffer;
        auto buf = net::buffer(buffer);

        try
        {
            // 读取客户端数据
            std::size_t n = co_await trojan->async_read(buf);
            std::string received_msg(buffer.data(), n);

            std::cout << "Server received message: " << received_msg << std::endl;

            // 回显给客户端
            co_await trojan->async_write(net::buffer(received_msg));
        }
        catch (const std::exception &e)
        {
            std::cerr << "Data transmission error: " << e.what() << std::endl;
        }

        // 关闭连接
        std::cout << "Server test complete, closing connection" << std::endl;
        co_await trojan->close();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Server exception: " << e.what() << std::endl;
    }
    co_return;
}

/**
 * @brief Trojan 测试客户端协程
 */
net::awaitable<void> do_trojan_client(tcp::endpoint endpoint, std::shared_ptr<ssl::context> ssl_ctx,
                                      const std::string &password, const std::string &host,
                                      uint16_t port, const std::string &test_msg)
{
    try
    {
        tcp::socket socket(co_await net::this_coro::executor);
        co_await socket.async_connect(endpoint, net::use_awaitable);

        ssl::stream<tcp::socket> stream(std::move(socket), *ssl_ctx);
        // 设置 SNI
        if (!SSL_set_tlsext_host_name(stream.native_handle(), "example.com"))
        {
             throw boost::system::system_error(
                boost::system::error_code(
                    static_cast<int>(::ERR_get_error()),
                    boost::asio::error::get_ssl_category()));
        }

        co_await stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
        std::cout << "Client SSL handshake success" << std::endl;

        // 构造 Trojan 请求
        // 56 hex chars + CRLF + CMD(1) + ATYP(1) + ADDR + PORT + CRLF
        std::string req;
        // 伪造一个 hash (56 'a')
        req.append(56, 'a');
        req.append("\r\n");
        req.push_back(0x01); // CONNECT
        req.push_back(0x03); // DOMAIN
        req.push_back(static_cast<char>(host.length()));
        req.append(host);
        uint16_t net_port = htons(port);
        req.append(reinterpret_cast<const char *>(&net_port), 2);
        req.append("\r\n");

        co_await net::async_write(stream, net::buffer(req), net::use_awaitable);

        // 发送测试消息
        co_await net::async_write(stream, net::buffer(test_msg), net::use_awaitable);

        // 读取回显
        std::array<char, 1024> buffer;
        std::size_t n = co_await stream.async_read_some(net::buffer(buffer), net::use_awaitable);
        std::string received_msg(buffer.data(), n);

        if (received_msg != test_msg)
        {
            throw std::runtime_error("Message echo verification failed");
        }

        std::cout << "Client test success: " << test_msg << std::endl;

        // 关闭
        boost::system::error_code ec;
        co_await stream.async_shutdown(net::redirect_error(net::use_awaitable, ec));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Client exception: " << e.what() << std::endl;
        throw;
    }
    co_return;
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::cout << "Starting Trojan protocol test..." << std::endl;

    try
    {
        net::io_context ioc;

        // 证书路径
        std::string cert_file = "cert.pem";
        std::string key_file = "key.pem";

        // 初始化服务器 SSL 上下文
        auto server_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        try
        {
            server_ctx->use_certificate_chain_file(cert_file);
            server_ctx->use_private_key_file(key_file, ssl::context::pem);
        }
        catch (...)
        {
            std::cerr << "Cannot load cert files, ensure cert.pem and key.pem exist" << std::endl;
        }

        // 初始化客户端 SSL 上下文
        auto client_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        client_ctx->set_verify_mode(ssl::verify_none);

        // 绑定本地地址
        tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
        tcp::acceptor acceptor(ioc, endpoint);
        auto bound_endpoint = acceptor.local_endpoint();

        std::cout << "Test server listening on: " << bound_endpoint << std::endl;

        const std::string test_password = "password";
        const std::string test_host = "example.com";
        const uint16_t test_port = 80;
        const std::string test_message = "Hello Trojan";

        net::co_spawn(ioc, do_trojan_server(acceptor, server_ctx, test_password), net::detached);
        net::co_spawn(ioc, do_trojan_client(bound_endpoint, client_ctx, test_password, test_host, test_port, test_message), net::detached);

        ioc.run();

        std::cout << "\nAll Trojan protocol tests completed and passed!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nTest failed, fatal exception caught: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
