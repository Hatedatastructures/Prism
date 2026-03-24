#include <forward-engine/resolve/router.hpp>

#include <exception.hpp>
#include <trace.hpp>

#include <algorithm>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <memory>
#include <string>

namespace ngx::resolve
{
    router::router(connection_pool &pool, net::io_context &ioc, config dns_cfg,
                   const memory::resource_pointer mr)
        : pool_(pool),
          mr_(mr ? mr : memory::current_resource()),
          dns_(ioc, std::move(dns_cfg), mr_),
          reverse_map_(mr_),
          executor_(ioc.get_executor())
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
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        // TODO: 正向代理模式暂未实现，当前没有后端服务无法测试
        static_cast<void>(host);
        static_cast<void>(port);
        co_return std::make_pair(fault::code::not_supported, pooled_connection{});
    }

    auto router::async_forward(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        // 统一检测 IP 字面量（IPv4 / IPv6）
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                // IPv6 + 禁用 → 拒绝
                if (addr.is_v6() && ipv6_disabled())
                {
                    trace::debug("[Resolve] IPv6 disabled, rejected literal: {}", host);
                    co_return std::make_pair(fault::code::host_unreachable, pooled_connection{});
                }
                // IPv4 或 IPv6（未禁用）→ 直接构造 endpoint 连接
                const auto port_num = static_cast<std::uint16_t>(std::stoi(std::string(port)));
                const tcp::endpoint ep(addr, port_num);
                trace::debug("[Resolve] literal address, direct connect: {}", host);
                auto [code, conn] = co_await pool_.async_acquire(ep);
                if (conn.valid())
                {
                    co_return std::make_pair(fault::code::success, std::move(conn));
                }
                co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
            }
        }

        // 非字面量 → DNS 解析
        auto [resolve_ec, endpoints] = co_await dns_.resolve_tcp(host, port);
        if (fault::failed(resolve_ec) || endpoints.empty())
        {
            trace::warn("[Resolve] DNS resolve {}:{} failed", host, port);
            co_return std::make_pair(fault::code::host_unreachable, pooled_connection{});
        }

        // 尝试连接
        auto conn = co_await connect_with_retry(endpoints);
        if (conn.valid())
        {
            co_return std::make_pair(fault::code::success, std::move(conn));
        }

        co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
    }

    auto router::connect_with_retry(const std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>
    {
        constexpr std::size_t max_attempts = 3;
        std::size_t attempted = 0;

        for (const auto &ep : endpoints)
        {
            trace::debug("[Resolve] connect attempt [{}] {}", attempted + 1, ep.address().to_string());

            auto [code, conn] = co_await pool_.async_acquire(ep);
            if (conn.valid())
            {
                co_return conn;
            }

            if (++attempted >= max_attempts)
            {
                break;
            }
        }

        co_return pooled_connection{};
    }

    auto router::async_reverse(const std::string_view host) const
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        const auto route = reverse_map_.find(host);
        if (route == reverse_map_.end())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        auto [code, conn] = co_await pool_.async_acquire(route->second);
        if (!conn.valid())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
    }

    auto router::async_direct(const tcp::endpoint ep) const
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        auto [code, conn] = co_await pool_.async_acquire(ep);
        if (!conn.valid())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
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
