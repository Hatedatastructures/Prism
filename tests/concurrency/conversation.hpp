#pragma once

#include <chrono>
#include <boost/asio.hpp>
#include <prism/memory.hpp>
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
            const auto read_result = co_await http::async_read(socket_, req, psm::memory::current_resource());

            if (psm::fault::failed(read_result))
            {
                if (read_result != psm::fault::code::eof)
                {
                    psm::trace::error("initial read failed: {}", psm::fault::cached_message(read_result));
                }
                co_return;
            }

            const auto mode = detect_mode(req.target());

            if (mode == srv::mode::stress)
            {
                psm::trace::info("stress mode activated");
                co_await handle_stress(socket_, psm::memory::current_resource());
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
            const auto res = handler::make_response(preset, psm::memory::current_resource());

            const auto response_data = http::serialize(res, psm::memory::current_resource());
            co_await net::async_write(socket_, net::buffer(response_data), net::use_awaitable);
        }

        boost::asio::ip::tcp::socket socket_;
        std::chrono::milliseconds delay_;
    };
}
