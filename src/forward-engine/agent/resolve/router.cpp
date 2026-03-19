#include <forward-engine/agent/resolve/router.hpp>

#include <exception.hpp>

#include <array>
#include <charconv>
#include <string>

namespace ngx::agent::resolve
{
    router::router(tcpool &pool, net::io_context &ioc, const memory::resource_pointer mr)
        : resolver_(ioc),
          mr_(mr ? mr : memory::current_resource()),
          datagram_dns_(resolver_.get_executor(), mr_),
          reverse_map_(mr_),
          arbiter_(pool, blacklist_, datagram_dns_, reverse_map_, resolver_.get_executor()),
          stream_dns_(pool, resolver_.get_executor(), mr_)
    {
    }

    void router::set_positive_endpoint(const std::string_view host, const std::uint16_t port)
    {
        if (host.empty() || port == 0)
        {
            positive_host_.reset();
            positive_port_ = 0;
            return;
        }

        memory::string host_value(mr_);
        host_value.assign(host);
        positive_host_ = std::move(host_value);
        positive_port_ = port;
    }

    void router::add_reverse_route(const std::string_view host, const tcp::endpoint &ep)
    {
        memory::string host_key(mr_);
        host_key.assign(host);
        reverse_map_.insert_or_assign(std::move(host_key), ep);
    }

    auto router::async_positive(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        if (!positive_host_ || positive_port_ == 0)
        {
            co_return std::make_pair(fault::code::host_unreachable, nullptr);
        }

        boost::system::error_code ec;
        const auto proxy_port = std::to_string(positive_port_);
        auto token = net::redirect_error(net::use_awaitable, ec);
        const auto endpoints = co_await resolver_.async_resolve(*positive_host_, proxy_port, token);
        if (ec || endpoints.empty())
        {
            co_return std::make_pair(fault::code::host_unreachable, nullptr);
        }

        auto socket = unique_sock(new tcp::socket(resolver_.get_executor()), deleter{});
        co_await net::async_connect(*socket, endpoints, token);
        if (ec)
        {
            co_return std::make_pair(fault::code::host_unreachable, nullptr);
        }

        socket->set_option(net::ip::tcp::no_delay(true));

        memory::string request(mr_);
        request.reserve(256);
        request.append("CONNECT ");
        request.append(host.begin(), host.end());
        request.push_back(':');
        request.append(port.begin(), port.end());
        request.append(" HTTP/1.1\r\nHost: ");
        request.append(host.begin(), host.end());
        request.push_back(':');
        request.append(port.begin(), port.end());
        request.append("\r\nProxy-Connection: Keep-Alive\r\n\r\n");

        ec.clear();
        co_await net::async_write(*socket, net::buffer(request), token);
        if (ec)
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        memory::string header(mr_);
        header.reserve(1024);

        std::array<char, 1024> buffer{};
        while (header.find("\r\n\r\n") == std::string::npos && header.size() < 8192)
        {
            ec.clear();
            const auto n = co_await socket->async_read_some(net::buffer(buffer), token);
            if (ec || n == 0)
            {
                co_return std::make_pair(fault::code::bad_gateway, nullptr);
            }
            header.append(buffer.data(), n);
        }

        if (header.find("\r\n\r\n") == std::string::npos)
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        const auto header_view = std::string_view(header);
        const auto line_end = header_view.find("\r\n");
        const auto status_line = header_view.substr(0, line_end == std::string_view::npos ? header_view.size() : line_end);
        const auto first_space = status_line.find(' ');
        if (first_space == std::string_view::npos)
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        const auto second_space = status_line.find(' ', first_space + 1);
        const auto code_width = second_space == std::string_view::npos ? std::string_view::npos : second_space - first_space - 1;
        const auto code_view = status_line.substr(first_space + 1, code_width);
        int status_code = 0;
        const auto [ptr, parse_ec] = std::from_chars(code_view.data(), code_view.data() + code_view.size(), status_code);
        static_cast<void>(ptr);
        if (parse_ec != std::errc() || status_code != 200)
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        co_return std::make_pair(fault::code::success, std::move(socket));
    }

    auto router::async_forward(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        if (blacklist_.domain(host))
        {
            co_return std::make_pair(fault::code::blocked, nullptr);
        }

        auto [ec, socket] = co_await stream_dns_.resolve(host, port);
        if (!fault::failed(ec) && socket && socket->is_open())
        {
            co_return std::make_pair(ec, std::move(socket));
        }

        co_return co_await async_positive(host, port);
    }

    auto router::async_reverse(const std::string_view host) const
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        co_return co_await arbiter_.route_reverse(host);
    }

    auto router::async_direct(const tcp::endpoint ep) const
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        co_return co_await arbiter_.route_direct(ep);
    }

    auto router::async_datagram(const std::string_view host, const std::string_view port) const
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
    {
        co_return co_await arbiter_.route_datagram(host, port);
    }

    auto router::resolve_datagram_target(const std::string_view host, const std::string_view port) const
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        co_return co_await arbiter_.resolve_datagram_target(host, port);
    }
} // namespace ngx::agent::resolve
