#pragma once

#include <chrono>
#include <boost/asio.hpp>
#include <prism/memory.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/trace.hpp>
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
            // 读取 HTTP 请求头
            std::array<char, 8192> buf{};
            boost::system::error_code ec;
            std::size_t used = 0;

            while (true)
            {
                const auto sv = std::string_view(buf.data(), used);
                if (sv.find("\r\n\r\n") != std::string_view::npos)
                {
                    break;
                }

                auto n = co_await socket_.async_read_some(
                    net::buffer(buf.data() + used, buf.size() - used),
                    net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    if (ec != net::error::eof)
                    {
                        psm::trace::error("initial read failed: {}", ec.message());
                    }
                    co_return;
                }
                used += n;
            }

            // 解析请求
            const auto raw = std::string_view(buf.data(), used);
            psm::protocol::http::proxy_request req;
            if (psm::fault::failed(psm::protocol::http::parse_proxy_request(raw, req)))
            {
                psm::trace::error("parse request failed");
                co_return;
            }

            const auto mode = detect_mode(req.target);

            if (mode == srv::mode::stress)
            {
                psm::trace::info("stress mode activated");
                co_await handle_stress(socket_, psm::memory::current_resource());
            }
            else
            {
                co_await handle_concurrent();
            }

            socket_.close(ec);
        }

        boost::asio::awaitable<void> handle_concurrent()
        {
            const auto response_data = build_http_response(
                200, "OK", JSON_CONTENT,
                R"({"code":0,"message":"success"})");
            co_await net::async_write(socket_, net::buffer(response_data), net::use_awaitable);
        }

        boost::asio::ip::tcp::socket socket_;
        std::chrono::milliseconds delay_;
    };
}
