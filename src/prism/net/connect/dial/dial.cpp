#include <prism/net/connect/dial/connector.hpp>

#include <prism/net/connect/dial/racer.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/net/dns/detail/utility.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

using namespace psm::trace;

namespace psm::connect
{

    using dns::detail::parse_port;

    auto retry_connect(router &rt, const std::span<const tcp::endpoint> endpoints,
                       std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<pooled_connection>
    {
        if (endpoints.empty())
        {
            co_return pooled_connection{};
        }

        address_racer racer(rt.pool());
        co_return co_await racer.race(endpoints, trace);
    }

    auto async_direct(router &rt, const tcp::endpoint ep, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        auto [code, conn] = co_await rt.pool().async_acquire(ep, trace);
        if (!conn.valid())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
    }

    auto async_forward(router &rt, const std::string_view host, const std::string_view port, std::shared_ptr<trace::trace_context> trace)
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
                    trace::debug<flt::conn | flt::protocol>(trace, "IPv6 disabled, rejected literal: {}", host);
                    co_return std::make_pair(fault::code::host_noreply, pooled_connection{});
                }
                const auto port_num = parse_port(port).value_or(0);
                const tcp::endpoint ep(addr, port_num);
                trace::debug<flt::conn | flt::protocol>(trace, "literal address, direct connect: {}", host);
                auto [code, conn] = co_await rt.pool().async_acquire(ep, trace);
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
            trace::warn<flt::conn | flt::protocol>(trace, "DNS resolve {}:{} failed", host, port);
            co_return std::make_pair(fault::code::host_noreply, pooled_connection{});
        }

        auto conn = co_await retry_connect(rt, endpoints, trace);
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

    auto dial(outbound::proxy &outbound_proxy, const psm::connect::target &target, const net::any_io_executor &executor, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        auto [ec, trans] = co_await outbound_proxy.async_connect(target, executor);
        if (fault::failed(ec) || !trans)
        {
            trace::debug<flt::conn | flt::protocol>(trace, "outbound dial failed: {}, target: {}:{}",
                         fault::describe(ec), target.host, target.port);
        }
        co_return std::pair{ec, std::move(trans)};
    }

} // namespace psm::connect
