#include <prism/channel/connection/pool.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/config.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <iostream>
#include <cassert>
#include <thread>
#include <string>

namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

/**
 * @brief 回显服务器
 * @details 用于测试链路的最小上游服务：收到的数据原样写回。
 * @param acceptor 接收器（按值接管所有权）
 * @return `net::awaitable<void>`
 * @note 该测试只需要处理一个连接，满足用例即可。
 */
net::awaitable<void> echo_server(tcp::acceptor acceptor)
{
    try
    {
        tcp::socket socket = co_await acceptor.async_accept(net::use_awaitable);
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
    catch (...)
    {
    }
}

/**
 * @brief 极简正向代理服务器（仅支持 HTTP `CONNECT`）
 * @details 用于验证 `router::route_forward` 的失败回退能力：
 * 1. 从客户端读取 `CONNECT` 请求头（读到 `\\r\\n\\r\\n` 为止）
 * 2. 连接到指定的上游 endpoint（这里是本地 `echo_server`）
 * 3. 回复 `200 Connection Established` 表示隧道已建立
 * 4. 启动双向转发，直到任一侧关闭或发生错误
 * @param acceptor 接收器（按值接管所有权）
 * @param upstream_endpoint 上游服务端点（本测试中为 `echo_server` 的监听端口）
 * @return `net::awaitable<void>`
 * @note 这是测试桩，不实现完整 HTTP 解析，也不支持认证头。
 */
net::awaitable<void> positive_proxy_server(tcp::acceptor acceptor, tcp::endpoint upstream_endpoint)
{
    try
    {
        tcp::socket client_socket = co_await acceptor.async_accept(net::use_awaitable);
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        std::string header;
        header.reserve(1024);
        std::array<char, 1024> read_buf{};
        while (header.find("\r\n\r\n") == std::string::npos && header.size() < 8192)
        {
            ec.clear();
            const auto n = co_await client_socket.async_read_some(net::buffer(read_buf), token);
            if (ec || n == 0)
            {
                co_return;
            }
            header.append(read_buf.data(), read_buf.data() + n);
        }

        if (header.find("\r\n\r\n") == std::string::npos)
        {
            co_return;
        }

        tcp::socket upstream_socket(co_await net::this_coro::executor);
        ec.clear();
        co_await upstream_socket.async_connect(upstream_endpoint, token);
        if (ec)
        {
            co_return;
        }

        static constexpr std::string_view response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        ec.clear();
        co_await net::async_write(client_socket, net::buffer(response), token);
        if (ec)
        {
            co_return;
        }

        /**
         * @brief 单向转发协程
         * @details 从 `read_stream` 读取数据，写入到 `write_stream`。
         * 任一方向出错或读到 0 字节即退出，由上层 `||` 触发另一方向协程的取消/结束。
         */
        auto forward = [](auto &read_stream, auto &write_stream) -> net::awaitable<void>
        {
            std::array<char, 4096> buf{};
            boost::system::error_code inner_ec;
            auto inner_token = net::redirect_error(net::use_awaitable, inner_ec);
            while (true)
            {
                inner_ec.clear();
                const auto n = co_await read_stream.async_read_some(net::buffer(buf), inner_token);
                if (inner_ec || n == 0)
                {
                    co_return;
                }
                inner_ec.clear();
                co_await net::async_write(write_stream, net::buffer(buf.data(), n), inner_token);
                if (inner_ec)
                {
                    co_return;
                }
            }
        };

        using namespace boost::asio::experimental::awaitable_operators;
        co_await (forward(client_socket, upstream_socket) || forward(upstream_socket, client_socket));
    }
    catch (...)
    {
    }
}

/**
 * @brief 连接池与正向代理回退用例
 * @details 测试分两部分：
 * 1) 验证连接池复用：`async_acquire` 两次拿到同一个 socket 指针
 * 2) 验证回退：对不可解析域名发起 `route_forward`，应走上游代理 `CONNECT`，并能与回显服务通信
 * @param ioc `io_context`
 * @param echo_port 回显服务端口
 * @param proxy_port 伪正向代理端口
 * @return `net::awaitable<void>`
 */
net::awaitable<void> run_test(net::io_context &ioc, unsigned short echo_port, unsigned short proxy_port)
{
    std::cout << "[Test] Starting..." << std::endl;
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), echo_port);

    psm::channel::connection_pool pool(ioc);
    psm::resolve::config dns_cfg;
    psm::resolve::router dist(pool, ioc, std::move(dns_cfg));

    try
    {
        std::cout << "[Test] Step 1: Acquire connection" << std::endl;
        auto [code1, c1] = co_await pool.async_acquire(endpoint);
        assert(psm::fault::succeeded(code1));
        assert(c1.valid());
        std::cout << "  Got c1" << std::endl;
        auto c1_ptr = c1.get();

        std::cout << "[Test] Step 2: Recycle connection (by destruction)" << std::endl;
        c1 = psm::channel::pooled_connection{};

        std::cout << "[Test] Step 3: Acquire again (should reuse)" << std::endl;
        auto [code2, c2] = co_await pool.async_acquire(endpoint);
        assert(psm::fault::succeeded(code2));
        assert(c2.valid());
        assert(c2.get() == c1_ptr);
        c2 = psm::channel::pooled_connection{};

        std::cout << "[Test] Step 4: Route via positive proxy fallback" << std::endl;
        dist.set_positive_endpoint("127.0.0.1", proxy_port);

        /**
         * @details 使用不可解析域名触发"直连失败"，从而覆盖回退分支：
         * - 直连 DNS 解析失败 -> `route_forward` 回退到 `route_positive`
         * - `route_positive` 连接到 `positive_proxy_server`，通过 `CONNECT` 建立到 echo 的隧道
         */
        auto [route_ec, conn] = co_await dist.async_forward("example.invalid", "80");
        assert(psm::fault::succeeded(route_ec));
        assert(conn.valid());

        static constexpr std::string_view msg = "ping";
        boost::system::error_code rw_ec;
        auto token = net::redirect_error(net::use_awaitable, rw_ec);
        co_await net::async_write(*conn, net::buffer(msg), token);
        assert(!rw_ec);

        std::array<char, 16> buf{};
        rw_ec.clear();
        const auto n = co_await conn->async_read_some(net::buffer(buf), token);
        assert(!rw_ec);
        assert(n == msg.size());
        assert(std::string_view(buf.data(), n) == msg);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Test Failed: " << e.what() << std::endl;
        exit(1);
    }

    std::cout << "[Test] Passed." << std::endl;
    co_return;
}

int main()
{
    try
    {
        net::io_context ioc;

        // 设置接收器
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const unsigned short echo_port = echo_acceptor.local_endpoint().port();
        std::cout << "Echo server listening on port " << echo_port << std::endl;

        tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const unsigned short proxy_port = proxy_acceptor.local_endpoint().port();
        std::cout << "Positive proxy server listening on port " << proxy_port << std::endl;

        net::co_spawn(ioc, echo_server(std::move(echo_acceptor)), net::detached);
        net::co_spawn(ioc, positive_proxy_server(std::move(proxy_acceptor), tcp::endpoint(net::ip::make_address("127.0.0.1"), echo_port)), net::detached);
        net::co_spawn(ioc, run_test(ioc, echo_port, proxy_port), net::detached);

        auto io_func = [&ioc]()
        {
            ioc.run();
        }; // 单独开线程调度任务

        std::jthread io_thread(io_func);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Main Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
