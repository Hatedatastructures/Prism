#pragma once

#include <string_view>
#include <chrono>
#include <array>
#include <cstring>

#include <boost/asio.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/trace.hpp>

namespace srv
{
    namespace net = boost::asio;

    constexpr std::string_view JSON_CONTENT = "application/json; charset=utf-8";

    inline auto build_http_response(const unsigned int status_code, const std::string_view reason,
                                    const std::string_view content_type, const std::string_view body)
        -> std::string
    {
        std::string res;
        res.reserve(256 + body.size());
        res.append("HTTP/1.1 ");
        res.append(std::to_string(status_code));
        res.push_back(' ');
        res.append(reason);
        res.append("\r\n");
        res.append("Content-Type: ");
        res.append(content_type);
        res.append("\r\n");
        res.append("Content-Length: ");
        res.append(std::to_string(body.size()));
        res.append("\r\n");
        res.append("Connection: close\r\n");
        res.append("\r\n");
        res.append(body);
        return res;
    }

    inline auto build_stress_response(const std::string_view chunk_data)
        -> std::string
    {
        return build_http_response(200, "OK", JSON_CONTENT, chunk_data);
    }

    enum class mode
    {
        concurrent,
        stress
    };

    inline auto detect_mode(std::string_view target) -> mode
    {
        if (const auto pos = target.find('?'); pos != std::string_view::npos)
        {
            target = target.substr(0, pos);
        }

        if (target == "/stress")
        {
            return mode::stress;
        }

        return mode::concurrent;
    }

    inline auto handle_stress(net::ip::tcp::socket &socket, psm::memory::resource_pointer mr = nullptr)
        -> net::awaitable<void>
    {
        constexpr std::size_t chunk_size = 4 * 1024;

        std::string chunk_data(chunk_size, '\0');
        for (std::size_t i = 0; i < chunk_size; ++i)
        {
            chunk_data[i] = static_cast<char>('A' + (i % 26));
        }

        auto response_data = build_stress_response(chunk_data);

        std::array<char, 256> recv_buf{};

        net::steady_timer timer(co_await net::this_coro::executor);
        boost::system::error_code ec;

        socket.non_blocking(true, ec);
        if (ec)
        {
            psm::trace::error("stress mode: failed to set non-blocking: {}", ec.message());
            co_return;
        }

        psm::trace::debug("stress mode: sending 4KB response every 50ms or on client message...");

        while (true)
        {
            timer.expires_after(std::chrono::milliseconds(50));

            bool has_data = false;

            ec.clear();
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            if (!ec)
            {
                ec.clear();
                if (auto n = socket.read_some(net::buffer(recv_buf), ec); n > 0)
                {
                    has_data = true;
                    psm::trace::debug("stress mode: received {} bytes from client", n);
                }
                else if (ec == net::error::would_block || ec == net::error::try_again)
                {
                }
                else if (ec)
                {
                    psm::trace::debug("stress mode: client disconnected ({})", ec.message());
                    co_return;
                }
            }

            ec.clear();
            co_await net::async_write(socket, net::buffer(response_data), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                psm::trace::debug("stress mode: write failed ({})", ec.message());
                break;
            }

            psm::trace::debug("stress mode: sent 4KB response ({})", has_data ? "client triggered" : "timeout");
        }
    }
}
