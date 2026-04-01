#pragma once

#include <string_view>
#include <thread>

#include <boost/asio.hpp>
#include <prism/trace.hpp>

#include "conversation.hpp"

namespace srv
{
    struct config final
    {
        std::uint16_t port = 8000;
        std::uint32_t threads = std::thread::hardware_concurrency();
        std::chrono::milliseconds response_delay{0};
    };

    class server final
    {
    public:
        server(const config &cfg)
            : io_context_(static_cast<int>(cfg.threads)),
              acceptor_(io_context_),
              response_delay_(cfg.response_delay)
        {
            boost::asio::ip::tcp::endpoint endpoint{boost::asio::ip::tcp::v4(), cfg.port};
            acceptor_.open(endpoint.protocol());
            acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor_.bind(endpoint);
            acceptor_.listen();
        }

        void start()
        {
            psm::trace::debug("[server] 开始监听端口 {}...", acceptor_.local_endpoint().port());

            boost::asio::co_spawn(io_context_, accept_loop(), boost::asio::detached);

            io_context_.run();
        }

        void stop()
        {
            io_context_.stop();
        }

    private:
        boost::asio::awaitable<void> accept_loop()
        {
            while (true)
            {   // 死循环获取 socket
                boost::system::error_code ec;
                auto socket = co_await acceptor_.async_accept(
                    boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                if (ec)
                {
                    psm::trace::error("[server] 接受连接失败: {}", ec.message());
                    continue;
                }

                psm::trace::debug("[server] 新连接: {}:{}", socket.remote_endpoint().address().to_string(),
                                  socket.remote_endpoint().port());

                const auto session = std::make_shared<conversation>(std::move(socket), response_delay_);
                session->start();
            }
        }

        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::acceptor acceptor_;
        std::chrono::milliseconds response_delay_;
    };
}
