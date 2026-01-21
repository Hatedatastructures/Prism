#include <forward-engine/transport/source.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <cassert>
#include <thread>

namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

// 简单的 Echo 服务器用于接受连接
net::awaitable<void> echo_server(tcp::acceptor &acceptor)
{
    while (true)
    {
        try
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);
            // 保持连接打开，不需要读取
            // 使用分离的协程保持 socket 存活一段时间或直到对端关闭
            auto task = [s = std::move(socket)]() mutable -> net::awaitable<void>
            {
                try
                {
                    char data[1024];
                    while (true)
                    {
                        auto n = co_await s.async_read_some(net::buffer(data), net::use_awaitable);
                        if (n == 0)
                            break;
                    }
                }
                catch (...)
                {
                }
                co_return;
            };

            net::co_spawn(acceptor.get_executor(), std::move(task), net::detached);
            break;
        }
        catch (...)
        {
            break;
        }
    }
}

net::awaitable<void> run_test(net::io_context &ioc, unsigned short port)
{
    std::cout << "[Test] Starting..." << std::endl;
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), port);

    ngx::transport::source pool(ioc);

    try
    {
        std::cout << "[Test] Step 1: Acquire connection" << std::endl;
        auto c1 = co_await pool.acquire_tcp(endpoint);
        std::cout << "  Got c1" << std::endl;
        auto c1_ptr = c1.get();
        assert(c1_ptr != nullptr);

        std::cout << "[Test] Step 2: Recycle connection (by destruction)" << std::endl;
        c1.reset();

        std::cout << "[Test] Step 3: Acquire again (should reuse)" << std::endl;
        auto c2 = co_await pool.acquire_tcp(endpoint);
        std::cout << "  Got c2" << std::endl;
        assert(c2.get() == c1_ptr);
        c2.reset();
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
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const unsigned short port = acceptor.local_endpoint().port();
        std::cout << "Server listening on port " << port << std::endl;

        net::co_spawn(ioc, echo_server(acceptor), net::detached);
        net::co_spawn(ioc, run_test(ioc, port), net::detached);

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
