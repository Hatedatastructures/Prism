#include <forward-engine/agent/resolve/router.hpp>

#include <exception.hpp>
#include <trace.hpp>

#include <array>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <charconv>
#include <memory>
#include <string>

namespace ngx::agent::resolve
{
    router::router(tcpool &pool, net::io_context &ioc, const memory::resource_pointer mr, const bool disable_ipv6)
        : resolver_(ioc),
          mr_(mr ? mr : memory::current_resource()),
          datagram_dns_(resolver_.get_executor(), mr_),
          reverse_map_(mr_),
          arbiter_(pool, blacklist_, datagram_dns_, reverse_map_, resolver_.get_executor()),
          stream_dns_(pool, resolver_.get_executor(), mr_, std::chrono::seconds(120), 10000, disable_ipv6)
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
        // TODO: 正向代理模式暂未实现，当前没有后端服务无法测试
        static_cast<void>(host);
        static_cast<void>(port);
        co_return std::make_pair(fault::code::not_supported, nullptr);
    }

    auto router::async_forward(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        if (blacklist_.domain(host))
        {
            co_return std::make_pair(fault::code::blocked, nullptr);
        }

        auto [ec, socket] = co_await stream_dns_.resolve(host, port);
        co_return std::make_pair(ec, std::move(socket));
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
