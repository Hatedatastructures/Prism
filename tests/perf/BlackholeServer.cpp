// @file BlackholeServer.cpp
// @brief 多线程异步黑洞 TCP 服务（性能测试后端，替代 python 避免 GIL/单线程瓶颈）
// @details N 线程事件循环 + per-connection strand，零线程增长，高并发高吞吐。
// 用法：BlackholeServer [port] [threads]（默认端口 18081，线程 8）
#include <boost/asio.hpp>

#include <array>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace net = boost::asio;

namespace
{
    void start_read(const std::shared_ptr<net::ip::tcp::socket> &sock,
                    const net::strand<net::any_io_executor> &strand)
    {
        auto buf = std::make_shared<std::array<char, 65536>>();
        sock->async_read_some(net::buffer(*buf),
            net::bind_executor(strand, [sock, buf, strand](const boost::system::error_code &ec, std::size_t)
            {
                if (ec)
                    return;
                start_read(sock, strand);
            }));
    }
} // namespace

auto main(int argc, char **argv) -> int
{
    const auto port = argc > 1 ? std::stoi(argv[1]) : 18081;
    const auto threads = argc > 2 ? std::stoi(argv[2]) : 8;

    net::io_context ioc;
    net::ip::tcp::acceptor acc(ioc,
        net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port));

    auto accept_loop = [&](auto &&self) -> void
    {
        acc.async_accept(ioc,
            [&](const boost::system::error_code &ec, net::ip::tcp::socket sock)
            {
                if (!ec)
                {
                    auto strand = std::make_shared<net::strand<net::any_io_executor>>(
                        net::make_strand(sock.get_executor()));
                    start_read(std::make_shared<net::ip::tcp::socket>(std::move(sock)), *strand);
                }
                self(self);
            });
    };
    accept_loop(accept_loop);

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });

    std::cerr << "blackhole listening on " << port << ", threads=" << threads << "\n";
    for (auto &t : pool)
        t.join();
}
