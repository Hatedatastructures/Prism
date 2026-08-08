// @file FileServer.cpp
// @brief 多线程异步 HTTP 大文件服务（性能测试后端，替代 python 避免 GIL/单线程瓶颈）
// @details N 线程事件循环 + per-session strand，支持并发连接高吞吐。
// 用法：FileServer <root_dir> [port] [threads]（默认端口 18080，线程 8）
#include <boost/asio.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace net = boost::asio;

namespace
{
    class session : public std::enable_shared_from_this<session>
    {
    public:
        session(net::ip::tcp::socket sock, std::string root)
            : sock_(std::move(sock)), root_(std::move(root)),
              strand_(net::make_strand(sock_.get_executor()))
        {
        }

        auto start() -> void
        {
            read_request();
        }

    private:
        auto read_request() -> void
        {
            auto self = shared_from_this();
            sock_.async_read_some(net::buffer(req_buf_),
                net::bind_executor(strand_, [self](const boost::system::error_code &ec, std::size_t n)
                {
                    if (ec)
                        return;
                    self->handle_request(n);
                }));
        }

        auto handle_request(const std::size_t n) -> void
        {
            std::string_view req(req_buf_.data(), n);
            if (req.substr(0, 4) != "GET ")
                return;
            const auto sp = req.find(' ', 4);
            if (sp == std::string_view::npos)
                return;
            std::string path(req.substr(4, sp - 4));
            if (path.empty() || path[0] != '/')
                return;

            const auto full = std::filesystem::path(root_) / path.substr(1);
            file_.open(full, std::ios::binary);
            if (!file_.is_open())
            {
                const auto resp = std::make_shared<std::string>(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                auto self = shared_from_this();
                net::async_write(sock_, net::buffer(*resp),
                    net::bind_executor(strand_, [self, resp](const boost::system::error_code &, std::size_t) {}));
                return;
            }

            file_.seekg(0, std::ios::end);
            const auto size = file_.tellg();
            file_.seekg(0, std::ios::beg);

            pending_ = std::make_shared<std::string>(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                "Content-Length: " + std::to_string(size) + "\r\nConnection: close\r\n\r\n");
            write_pending();
        }

        auto write_pending() -> void
        {
            auto self = shared_from_this();
            net::async_write(sock_, net::buffer(*pending_),
                net::bind_executor(strand_, [self](const boost::system::error_code &ec, std::size_t)
                {
                    if (ec)
                        return;
                    self->send_file();
                }));
        }

        auto send_file() -> void
        {
            auto self = shared_from_this();
            file_.read(file_buf_.data(), file_buf_.size());
            const auto n = static_cast<std::size_t>(file_.gcount());
            if (n == 0)
                return;
            net::async_write(sock_, net::buffer(file_buf_.data(), n),
                net::bind_executor(strand_, [self](const boost::system::error_code &ec, std::size_t)
                {
                    if (ec)
                        return;
                    self->send_file();
                }));
        }

        net::ip::tcp::socket sock_;
        net::strand<net::io_context::executor_type> strand_;
        std::string root_;
        std::array<char, 262144> req_buf_{};
        std::array<char, 262144> file_buf_{};
        std::ifstream file_;
        std::shared_ptr<std::string> pending_;
    };
} // namespace

auto main(int argc, char **argv) -> int
{
    if (argc < 2)
    {
        std::cerr << "usage: FileServer <root_dir> [port] [threads]\n";
        return 1;
    }
    const std::string root = argv[1];
    const auto port = argc > 2 ? std::stoi(argv[2]) : 18080;
    const auto threads = argc > 3 ? std::stoi(argv[3]) : 8;

    net::io_context ioc;
    net::ip::tcp::acceptor acc(ioc,
        net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port));

    auto accept_loop = [&](auto &&self) -> void
    {
        acc.async_accept(ioc,
            [&](const boost::system::error_code &ec, net::ip::tcp::socket sock)
            {
                if (!ec)
                    std::make_shared<session>(std::move(sock), root)->start();
                self(self);
            });
    };
    accept_loop(accept_loop);

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });

    std::cerr << "file server listening on " << port << ", root=" << root
              << ", threads=" << threads << "\n";
    for (auto &t : pool)
        t.join();
}
