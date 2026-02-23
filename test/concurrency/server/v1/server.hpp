#pragma once

#include <string_view>
#include <iostream>
#include <fstream>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <forward-engine/trace.hpp>

#include "mime.hpp"
#include "conversation.hpp"

namespace srv::core
{
    using namespace boost::asio::experimental::awaitable_operators;

    struct config final
    {
        std::uint16_t server_port = 6789;
        std::uint16_t dashboard_port = 9876;
        std::uint32_t threads = std::thread::hardware_concurrency();
    }; // struct config

    class server final
    {
    public:
        server(const config &cfg)
            : io_context_(cfg.threads), server_acceptor_(io_context_),
              dashboard_acceptor_(io_context_)
        {
            boost::asio::ip::tcp::endpoint server_endpoint{boost::asio::ip::tcp::v4(), cfg.server_port};
            server_acceptor_.open(server_endpoint.protocol());
            server_acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            server_acceptor_.bind(server_endpoint);
            server_acceptor_.listen();

            boost::asio::ip::tcp::endpoint dashboard_endpoint{boost::asio::ip::tcp::v4(), cfg.dashboard_port};
            dashboard_acceptor_.open(dashboard_endpoint.protocol());
            dashboard_acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            dashboard_acceptor_.bind(dashboard_endpoint);
            dashboard_acceptor_.listen();
        }

        void start()
        {
            auto task_function = [this]() -> boost::asio::awaitable<void>
            {
                co_await (accept_connection(server_acceptor_, "server", srv::site_kind::main_site) &&
                          accept_connection(dashboard_acceptor_, "dashboard", srv::site_kind::stats_site));
            };
            boost::asio::co_spawn(io_context_, task_function, boost::asio::detached);

            io_context_.run();
        }

    private:
        template <typename Acceptor>
        boost::asio::awaitable<void> accept_connection(Acceptor &acceptor, std::string_view name, srv::site_kind kind)
        {
            ngx::trace::debug("[{}] 开始监听端口...", name);
            while (true)
            {
                auto [ec, socket] = co_await acceptor.async_accept(boost::asio::as_tuple(boost::asio::use_awaitable));
                if (ec)
                {
                    ngx::trace::error("[{}] 接受连接失败: {}", name, ec.message());
                    continue; // 继续接受下一个连接
                }
                ngx::trace::debug("[{}] 接受连接成功: {}", name, socket.remote_endpoint().address().to_string());
                auto session = std::make_shared<srv::workers::conversation>(std::move(socket), kind);
                session->start();
            }
        }

        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::acceptor server_acceptor_;
        boost::asio::ip::tcp::acceptor dashboard_acceptor_;
    }; // class server
}
