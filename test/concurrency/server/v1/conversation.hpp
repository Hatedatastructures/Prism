#pragma once

#include <string_view>
#include <boost/asio.hpp>
#include "handler.hpp"

namespace srv::workers
{
    class conversation final : public std::enable_shared_from_this<conversation>
    {
    public:
        explicit conversation(boost::asio::ip::tcp::socket socket, srv::site_kind kind)
            : socket_(std::move(socket)), kind_(kind)
        {
        }

        void start()
        {
            auto process = [self = this->shared_from_this()]() -> boost::asio::awaitable<void>
            {
                co_await self->discriminator();
            };
            boost::asio::co_spawn(socket_.get_executor(), std::move(process), boost::asio::detached);
        }

    private:
        boost::asio::awaitable<void> discriminator()
        {
            while (true)
            {
                co_await srv::handler::http(socket_, kind_);
            }
        }
        boost::asio::ip::tcp::socket socket_;
        srv::site_kind kind_;
    };
}
