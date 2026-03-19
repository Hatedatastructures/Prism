#pragma once

#include <chrono>
#include <boost/asio.hpp>
#include <forward-engine/memory.hpp>
#include "handler.hpp"

namespace srv
{
    class conversation final : public std::enable_shared_from_this<conversation>
    {
    public:
        explicit conversation(
            boost::asio::ip::tcp::socket socket,
            std::chrono::milliseconds delay)
            : socket_(std::move(socket)), delay_(delay)
        {
        }

        void start()
        {
            auto self = shared_from_this();
            auto process = [self = std::move(self)]() -> boost::asio::awaitable<void>
            {
                co_await self->run();
            };

            boost::asio::co_spawn(socket_.get_executor(), std::move(process), boost::asio::detached);
        }

    private:
        boost::asio::awaitable<void> run()
        {
            http::request req;
            const auto read_result = co_await http::async_read(socket_, req, ngx::memory::current_resource());

            if (ngx::fault::failed(read_result))
            {
                if (read_result != ngx::fault::code::eof)
                {
                    ngx::trace::error("initial read failed: {}", ngx::fault::cached_message(read_result));
                }
                co_return;
            }

            const auto mode = detect_mode(req.target());

            if (mode == srv::mode::stress)
            {
                ngx::trace::info("stress mode activated");
                co_await handle_stress(socket_, ngx::memory::current_resource());
            }
            else
            {
                co_await handle_concurrent();
            }

            boost::system::error_code ec;
            socket_.close(ec);
        }

        boost::asio::awaitable<void> handle_concurrent()
        {
            const auto &preset = preset_ok;
            const auto res = handler::make_response(preset, ngx::memory::current_resource());

            const auto response_data = http::serialize(res, ngx::memory::current_resource());
            co_await net::async_write(socket_, net::buffer(response_data), net::use_awaitable);
        }

        boost::asio::ip::tcp::socket socket_;
        std::chrono::milliseconds delay_;
    };
}
