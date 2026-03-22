#include <forward-engine/resolve/router.hpp>

#include <exception.hpp>
#include <trace.hpp>

#include <algorithm>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <memory>
#include <string>

namespace ngx::resolve
{
    router::router(tcpool &pool, net::io_context &ioc, config dns_cfg,
                   const memory::resource_pointer mr, const bool disable_ipv6)
        : pool_(pool),
          mr_(mr ? mr : memory::current_resource()),
          dns_(ioc, std::move(dns_cfg), mr_),
          reverse_map_(mr_),
          executor_(ioc.get_executor()),
          disable_ipv6_(disable_ipv6)
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
        // 禁用 IPv6 时，直接拒绝 IPv6 地址字面量
        if (disable_ipv6_)
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec && addr.is_v6())
            {
                trace::debug("[Resolve] IPv6 disabled, rejected literal: {}", host);
                co_return std::make_pair(fault::code::host_unreachable, nullptr);
            }
        }

        // DNS 解析
        auto [resolve_ec, endpoints] = co_await dns_.resolve_tcp(host, port);
        if (fault::failed(resolve_ec) || endpoints.empty())
        {
            trace::warn("[Resolve] DNS resolve {}:{} failed", host, port);
            co_return std::make_pair(fault::code::host_unreachable, nullptr);
        }

        // IPv6 过滤
        if (disable_ipv6_)
        {
            const auto before = endpoints.size();
            std::erase_if(endpoints, [](const tcp::endpoint &ep)
                          { return ep.address().is_v6(); });
            if (const auto removed = before - endpoints.size(); removed > 0)
            {
                trace::debug("[Resolve] IPv6 disabled, filtered {} endpoints", removed);
            }
        }

        if (endpoints.empty())
        {
            co_return std::make_pair(fault::code::host_unreachable, nullptr);
        }

        // 尝试连接
        auto socket = co_await connect_with_retry(endpoints);
        if (socket)
        {
            co_return std::make_pair(fault::code::success, std::move(socket));
        }

        co_return std::make_pair(fault::code::bad_gateway, nullptr);
    }

    auto router::connect_with_retry(const std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<unique_sock>
    {
        constexpr std::size_t max_attempts = 3;
        std::size_t attempted = 0;

        for (const auto &ep : endpoints)
        {
            if (disable_ipv6_ && ep.address().is_v6())
            {
                continue;
            }

            trace::debug("[Resolve] connect attempt [{}] {}", attempted + 1, ep.address().to_string());

            auto socket = co_await pool_.acquire_tcp(ep);
            if (socket && socket->is_open())
            {
                co_return socket;
            }

            if (++attempted >= max_attempts)
            {
                break;
            }
        }

        co_return nullptr;
    }

    auto router::async_reverse(const std::string_view host) const
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        const auto route = reverse_map_.find(host);
        if (route == reverse_map_.end())
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        auto socket = co_await pool_.acquire_tcp(route->second);
        if (!socket || !socket->is_open())
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        co_return std::make_pair(fault::code::success, std::move(socket));
    }

    auto router::async_direct(const tcp::endpoint ep) const
        -> net::awaitable<std::pair<fault::code, unique_sock>>
    {
        auto socket = co_await pool_.acquire_tcp(ep);
        if (!socket || !socket->is_open())
        {
            co_return std::make_pair(fault::code::bad_gateway, nullptr);
        }

        co_return std::make_pair(fault::code::success, std::move(socket));
    }

    auto router::async_datagram(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
    {
        const auto [resolve_ec, target] = co_await dns_.resolve_udp(host, port);
        if (fault::failed(resolve_ec))
        {
            co_return std::pair{resolve_ec, net::ip::udp::socket{executor_}};
        }

        co_return open_udp_socket(executor_, target);
    }

    auto router::resolve_datagram_target(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        co_return co_await dns_.resolve_udp(host, port);
    }
} // namespace ngx::resolve
