#include <prism/net/connect/dial/dial.hpp>

#include <prism/net/connect/dial/racer.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/net/resolve/dns/detail/utility.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

using namespace psm::trace;

namespace psm::connect
{

    using resolve::dns::detail::parse_port;

    auto retry_connect(router &rt, const std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>
    {
        if (endpoints.empty())
        {
            co_return pooled_connection{};
        }

        address_racer racer(rt.pool());
        co_return co_await racer.race(endpoints);
    }

    auto async_direct(router &rt, const tcp::endpoint ep)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        auto [code, conn] = co_await rt.pool().async_acquire(ep);
        if (!conn.valid())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
    }

    auto async_forward(router &rt, const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        {
            // 尝试解析为 IP 字面量，成功则跳过 DNS
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && rt.ipv6_disabled())
                {
                    trace::debug<flt::conn | flt::protocol>("IPv6 disabled, rejected literal: {}", host);
                    co_return std::make_pair(fault::code::host_noreply, pooled_connection{});
                }
                const auto port_num = parse_port(port).value_or(0);
                const tcp::endpoint ep(addr, port_num);
                trace::debug<flt::conn | flt::protocol>("literal address, direct connect: {}", host);
                auto [code, conn] = co_await rt.pool().async_acquire(ep);
                if (conn.valid())
                {
                    co_return std::make_pair(fault::code::success, std::move(conn));
                }
                co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
            }
        }

        // DNS 返回多结果，Happy Eyeballs 竞速连接
        auto [resolve_ec, endpoints] = co_await rt.dns().resolve_tcp(host, port);
        if (fault::failed(resolve_ec) || endpoints.empty())
        {
            trace::warn<flt::conn | flt::protocol>("DNS resolve {}:{} failed", host, port);
            co_return std::make_pair(fault::code::host_noreply, pooled_connection{});
        }

        auto conn = co_await retry_connect(rt, endpoints);
        if (conn.valid())
        {
            co_return std::make_pair(fault::code::success, std::move(conn));
        }

        co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
    }

    auto async_datagram(router &rt, const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
    {
        net::ip::udp::endpoint target;
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && rt.ipv6_disabled())
                {
                    co_return std::pair{fault::code::host_noreply, net::ip::udp::socket{rt.executor()}};
                }
                const auto port_num = parse_port(port).value_or(0);
                target = net::ip::udp::endpoint(addr, port_num);
            }
            else
            {
                const auto [resolve_ec, resolved] = co_await rt.dns().resolve_udp(host, port);
                if (fault::failed(resolve_ec))
                {
                    co_return std::pair{resolve_ec, net::ip::udp::socket{rt.executor()}};
                }
                target = resolved;
            }
        }

        co_return open_udp(rt.executor(), target);
    }

    auto resolve_dgram(router &rt, const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && rt.ipv6_disabled())
                {
                    co_return std::make_pair(fault::code::host_noreply, net::ip::udp::endpoint{});
                }
                const auto port_num = parse_port(port).value_or(0);
                co_return std::make_pair(fault::code::success, net::ip::udp::endpoint(addr, port_num));
            }
        }
        co_return co_await rt.dns().resolve_udp(host, port);
    }

    // 核心拨号入口：根据 dial_options 决定连接方式
    // 1. 反向路由（allow_reverse）：查反向映射表，将目标地址映射到预配置的上游
    // 2. 正向路由（async_forward）：DNS 解析 → Happy Eyeballs 竞速 → 连接池复用
    // 连接成功后包装为 transport::reliable 返回
    auto dial(router &rt, dial_options opts)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        const auto &label = opts.label;
        const auto &target = opts.target;

        if (rt.ipv6_disabled() && is_ipv6(target.host))
        {
            trace::debug<flt::conn | flt::protocol>("{} rejecting IPv6 literal: {}:{}", label, target.host, target.port);
            co_return std::make_pair(fault::code::ipv6_disabled, nullptr);
        }

        fault::code ec;
        pooled_connection conn;
        // 反向路由查找：非 no_reverse/neither 且目标非正向代理时查反向映射表
        // 反向路由允许将特定目标域名映射到预配置的上游，用于负载均衡或路由策略
        const auto allow_reverse = opts.routing != dial_options::flag::no_reverse
            && opts.routing != dial_options::flag::neither;
        if (allow_reverse && !target.positive)
        {
            auto result = co_await rt.async_reverse(target.host);
            ec = result.first;
            conn = std::move(result.second);
        }
        else
        {
            auto result = co_await async_forward(rt, target.host, target.port);
            ec = result.first;
            conn = std::move(result.second);
        }

        if (fault::failed(ec))
        {
            trace::warn<flt::conn | flt::protocol>("{} route failed: {}, target: {}:{}", label,
                                                    fault::describe(ec), target.host, target.port);
            co_return std::make_pair(ec, nullptr);
        }

        const auto require_open = opts.routing != dial_options::flag::no_open
            && opts.routing != dial_options::flag::neither;
        if (require_open && !conn.valid())
        {
            trace::warn<flt::conn | flt::protocol>("{} socket not open, target: {}:{}", label, target.host, target.port);
            co_return std::make_pair(fault::code::connection_refused, nullptr);
        }

        trace::info<flt::conn | flt::protocol>("{} success, target: {}:{}", label, target.host, target.port);
        co_return std::make_pair(ec, transport::make_reliable(std::move(conn)));
    }

    auto dial(outbound::proxy &outbound_proxy, const protocol::target &target, const net::any_io_executor &executor)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        auto [ec, trans] = co_await outbound_proxy.async_connect(target, executor);
        if (fault::failed(ec) || !trans)
        {
            trace::debug<flt::conn | flt::protocol>("outbound dial failed: {}, target: {}:{}",
                         fault::describe(ec), target.host, target.port);
        }
        co_return std::pair{ec, std::move(trans)};
    }

} // namespace psm::connect
