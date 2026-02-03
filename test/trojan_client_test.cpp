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
using tcp = net::ip::tcp;

/**
 * @brief Trojan 真实网站访问测试客户端
 */
net::awaitable<void> do_trojan_request(std::string host, uint16_t port, std::string credential)
{
    try
    {
        auto executor = co_await net::this_coro::executor;
        tcp::socket socket(executor);

        // 连接到本地 Trojan 服务器 (Forward.exe 监听 8081)
        tcp::endpoint server_endpoint(net::ip::make_address("127.0.0.1"), 8081);

        std::cout << "Connecting to local Trojan server at 127.0.0.1:8081..." << std::endl;
        co_await socket.async_connect(server_endpoint, net::use_awaitable);

        // SSL 上下文
        ssl::context ssl_ctx(ssl::context::tlsv12_client);
        ssl_ctx.set_verify_mode(ssl::verify_none); // 测试用的自签名证书，跳过验证

        ssl::stream<tcp::socket> stream(std::move(socket), ssl_ctx);

        // 设置 SNI (必须，Trojan 协议要求)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), "localhost"))
        {
            throw boost::system::system_error(
                boost::system::error_code(
                    static_cast<int>(::ERR_get_error()),
                    boost::asio::error::get_ssl_category()));
        }

        std::cout << "Performing SSL handshake..." << std::endl;
        co_await stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
        std::cout << "SSL handshake success." << std::endl;

        // 构造 Trojan 请求头
        std::string req_header;
        req_header.append(credential); // 56 bytes hash
        req_header.append("\r\n");
        req_header.push_back(0x01); // CMD: CONNECT
        req_header.push_back(0x03); // ATYP: DOMAIN
        req_header.push_back(static_cast<char>(host.length()));
        req_header.append(host);

        uint16_t net_port = htons(port);
        req_header.append(reinterpret_cast<const char *>(&net_port), 2);
        req_header.append("\r\n");

        std::cout << "Sending Trojan header for target: " << host << ":" << port << std::endl;
        co_await net::async_write(stream, net::buffer(req_header), net::use_awaitable);

        // 构造 HTTP 请求
        std::string http_req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: xray-test-client\r\nConnection: close\r\n\r\n";
        std::cout << "Sending HTTP GET request..." << std::endl;
        co_await net::async_write(stream, net::buffer(http_req), net::use_awaitable);

        // 读取响应
        std::cout << "Waiting for response..." << std::endl;
        std::array<char, 8192> buffer;
        std::size_t n = co_await stream.async_read_some(net::buffer(buffer), net::use_awaitable);

        std::string response(buffer.data(), n);
        std::cout << "Received " << n << " bytes. Content snippet:\n"
                  << std::endl;
        std::cout << response.substr(0, 500) << "..." << std::endl;

        // 继续读取剩余数据 (可选)
        /*
        while (true) {
            n = co_await stream.async_read_some(net::buffer(buffer), net::use_awaitable);
            std::cout << std::string(buffer.data(), n);
        }
        */
    }
    catch (const std::exception &e)
    {
        std::cerr << "Client exception: " << e.what() << std::endl;
    }
    co_return;
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::cout << "Starting Trojan Client for Website Access Test..." << std::endl;

    try
    {
        net::io_context ioc;

        // 目标网站
        std::string target_host = "apple.com";
        uint16_t target_port = 443;

        // 凭据 (必须与 Server 配置一致)
        std::string credential(56, 'a');

        net::co_spawn(ioc, do_trojan_request(target_host, target_port, credential), net::detached);

        ioc.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Main exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
