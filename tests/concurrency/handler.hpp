#pragma once

#include <string_view>
#include <chrono>
#include <array>
#include <cstring>

#include <boost/asio.hpp>
#include <prism/protocol.hpp>
#include <prism/trace.hpp>

namespace srv
{
    namespace http = psm::protocol::http;
    namespace net = boost::asio;

    constexpr std::string_view JSON_CONTENT = "application/json; charset=utf-8";

    struct response_preset final
    {
        http::status status_code;
        std::string_view content_type;
        std::string_view body;
    };

    inline constexpr response_preset preset_ok{
        http::status::ok,
        JSON_CONTENT,
        R"({"code":0,"message":"success"})"};

    class handler final
    {
    public:
        static auto make_response(const response_preset &preset, psm::memory::resource_pointer mr = nullptr)
            -> http::response
        {
            if (!mr)
            {
                mr = psm::memory::current_resource();
            }

            http::response res;
            res.status(preset.status_code);
            res.set(http::field::content_type, preset.content_type);
            res.set(http::field::connection, "close");

            psm::memory::string body(preset.body.begin(), preset.body.end(), mr);
            res.body(std::move(body));

            return res;
        }
    };

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
        if (!mr)
        {
            mr = psm::memory::current_resource();
        }

        constexpr std::size_t chunk_size = 4 * 1024;

        psm::memory::string chunk_data(chunk_size, '\0', mr);
        for (std::size_t i = 0; i < chunk_size; ++i)
        {
            chunk_data[i] = static_cast<char>('A' + (i % 26));
        }

        http::response resp;
        resp.version(11);
        resp.status(http::status::ok);
        resp.set(http::field::content_type, JSON_CONTENT);
        resp.set(http::field::connection, "keep-alive");
        resp.body(psm::memory::string(chunk_data, mr));

        const auto response_data = http::serialize(resp, mr);

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
