#include <prism/protocol/trojan.hpp>
#include <prism/transformer.hpp>
#include <prism/memory.hpp>
#include <prism/exception.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <iostream>
#include <string>
#include <array>
#include <format>
#include <fstream>
#include <string_view>
#include <vector>
#include <chrono>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;
namespace json = psm::transformer::json;

const std::string credential(56, 'a');

struct http_endpoint
{
    std::string host;
    std::uint16_t port{};
};

struct trojan_endpoint
{
    std::string host = "127.0.0.1";
    std::uint16_t port = 8081;
};

template <>
struct glz::meta<http_endpoint>
{
    using T = http_endpoint;
    static constexpr auto value = glz::object(
        "host", &T::host,
        "port", &T::port);
};

auto load_file_data(std::string_view path)
    -> psm::memory::string
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw psm::exception::security("system error : {}", "file open failed");
    }
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    psm::memory::string content(size, '\0');
    file.read(content.data(), size);
    return content;
}

template <typename Stream>
auto read_some_with_timeout(Stream &stream, const net::mutable_buffer buffer, const std::chrono::milliseconds timeout,
                            boost::system::error_code &out_ec)
    -> net::awaitable<std::size_t>
{
    using namespace boost::asio::experimental::awaitable_operators;
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(timeout);

    boost::system::error_code read_ec;
    boost::system::error_code wait_ec;
    auto read_op = stream.async_read_some(buffer, net::redirect_error(net::use_awaitable, read_ec));
    auto timer_op = timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));

    const auto result = co_await (std::move(read_op) || std::move(timer_op));
    if (result.index() == 1)
    {
        out_ec = net::error::timed_out;
        co_return 0;
    }

    out_ec = read_ec;
    co_return std::get<0>(result);
}

auto trojan_https_request(const http_endpoint &http, const std::string &http_request, const trojan_endpoint &trojan = {})
    -> net::awaitable<void>
{
    try
    {
        if (http.host.empty() || http.port == 0)
        {
            std::cerr << "Invalid http endpoint" << std::endl;
            co_return;
        }
        auto executor = co_await net::this_coro::executor;
        tcp::socket socket(executor);

        tcp::endpoint server_endpoint(net::ip::make_address(trojan.host), trojan.port);

        std::cout << "Connecting to local Trojan server at " << trojan.host << ":" << trojan.port << "..." << std::endl;
        co_await socket.async_connect(server_endpoint, net::use_awaitable);

        ssl::context ssl_ctx(ssl::context::tlsv12_client);
        ssl_ctx.set_verify_mode(ssl::verify_none);

        ssl::stream<tcp::socket> stream(std::move(socket), ssl_ctx);

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

        std::string req_header;
        req_header.append(credential);
        req_header.append("\r\n");
        req_header.push_back(0x01);
        req_header.push_back(0x03);
        req_header.push_back(static_cast<char>(http.host.length()));
        req_header.append(http.host);

        uint16_t net_port = htons(http.port);
        req_header.append(reinterpret_cast<const char *>(&net_port), 2);
        req_header.append("\r\n");

        std::cout << "Sending Trojan header for target: " << http.host << ":" << http.port << std::endl;
        co_await net::async_write(stream, net::buffer(req_header), net::use_awaitable);

        auto transfer = [&](auto &active_stream, const std::string_view label) -> net::awaitable<void>
        {
            std::cout << "Sending " << label << " request..." << std::endl;
            co_await net::async_write(active_stream, net::buffer(http_request), net::use_awaitable);

            std::cout << "Waiting for response..." << std::endl;
            std::array<char, 8192> buffer{};
            std::size_t total_bytes = 0;
            bool printed_snippet = false;
            constexpr auto READ_TIMEOUT = std::chrono::seconds(10);

            while (true)
            {
                boost::system::error_code read_ec;
                const std::size_t n = co_await read_some_with_timeout(active_stream, net::buffer(buffer), READ_TIMEOUT, read_ec);
                if (read_ec == net::error::timed_out)
                {
                    std::cout << "Read timeout, closing." << std::endl;
                    break;
                }
                if (read_ec && read_ec != net::error::eof)
                {
                    throw boost::system::system_error(read_ec);
                }
                if (n == 0)
                {
                    break;
                }

                total_bytes += n;
                if (!printed_snippet)
                {
                    std::string response(buffer.data(), n);
                    std::cout << std::format("Received {} bytes. Content snippet:\n", n) << std::endl;
                    std::cout << response.substr(0, 500) << "..." << std::endl;
                    printed_snippet = true;
                }
                else
                {
                    std::cout << std::string(buffer.data(), n);
                }
            }
            std::cout << std::format("Total received bytes: {}", total_bytes) << std::endl;
            co_return;
        };

        if (http.port == 443)
        {
            ssl::context inner_ssl_ctx(ssl::context::tlsv12_client);
            inner_ssl_ctx.set_verify_mode(ssl::verify_none);
            ssl::stream<ssl::stream<tcp::socket>> inner_stream(std::move(stream), inner_ssl_ctx);

            if (!SSL_set_tlsext_host_name(inner_stream.native_handle(), http.host.c_str()))
            {
                throw boost::system::system_error(
                    boost::system::error_code(
                        static_cast<int>(::ERR_get_error()),
                        boost::asio::error::get_ssl_category()));
            }

            std::cout << "Performing inner TLS handshake to target..." << std::endl;
            co_await inner_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
            std::cout << "Inner TLS handshake success." << std::endl;
            co_await transfer(inner_stream, "HTTPS");
        }
        else
        {
            co_await transfer(stream, "HTTP");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Client exception: " << e.what() << std::endl;
    }
    co_return;
}

int main(const int argc, char **argv)
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::cout << "Starting Trojan Client for Website Access Test..." << std::endl;

    try
    {
        net::io_context ioc;
        const std::string batch_file_path = (argc > 1)
                                                ? std::string(argv[1])
                                                : std::string(R"(C:\Users\C1373\Desktop\code\ForwardEngine\test\trojan_data.json)");

        const auto batch_json = load_file_data(batch_file_path);
        std::vector<http_endpoint> targets;
        if (!json::deserialize(std::string_view(batch_json.data(), batch_json.size()), targets))
        {
            std::cerr << "Deserialize batch json failed" << std::endl;
            return 1;
        }

        const trojan_endpoint trojan{};
        for (const auto &one_target : targets)
        {
            const std::string http_req = "GET / HTTP/1.1\r\nHost: " + one_target.host + "\r\nUser-Agent: xray-test-client\r\nConnection: close\r\n\r\n";
            net::co_spawn(ioc, trojan_https_request(one_target, http_req, trojan), net::detached);
        }

        ioc.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Main exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
