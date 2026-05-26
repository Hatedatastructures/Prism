#include <prism/connect/dial/dial.hpp>

#include <prism/connect/dial/racer.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/resolve/dns/detail/utility.hpp>
#include <prism/trace.hpp>
#include <prism/transport/reliable.hpp>

constexpr std::string_view DialStr = "[Connect.Dial]";

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
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && rt.ipv6_disabled())
                {
                    trace::debug("[Connect.Dial] IPv6 disabled, rejected literal: {}", host);
                    co_return std::make_pair(fault::code::host_noreply, pooled_connection{});
                }
                const auto port_num = parse_port(port).value_or(0);
                const tcp::endpoint ep(addr, port_num);
                trace::debug("[Connect.Dial] literal address, direct connect: {}", host);
                auto [code, conn] = co_await rt.pool().async_acquire(ep);
                if (conn.valid())
                {
                    co_return std::make_pair(fault::code::success, std::move(conn));
                }
                co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
            }
        }

        auto [resolve_ec, endpoints] = co_await rt.dns().resolve_tcp(host, port);
        if (fault::failed(resolve_ec) || endpoints.empty())
        {
            trace::warn("[Connect.Dial] DNS resolve {}:{} failed", host, port);
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

    auto dial(router &rt, dial_options opts)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        const auto &label = opts.label;
        const auto &target = opts.target;

        if (rt.ipv6_disabled() && is_ipv6(target.host))
        {
            trace::debug("{} {} rejecting IPv6 literal: {}:{}", DialStr, label, target.host, target.port);
            co_return std::make_pair(fault::code::ipv6_disabled, nullptr);
        }

        fault::code ec;
        pooled_connection conn;
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
            trace::warn("{} {} route failed: {}, target: {}:{}", DialStr, label,
                        fault::describe(ec), target.host, target.port);
            co_return std::make_pair(ec, nullptr);
        }

        const auto require_open = opts.routing != dial_options::flag::no_open
            && opts.routing != dial_options::flag::neither;
        if (require_open && !conn.valid())
        {
            trace::warn("{} {} socket not open, target: {}:{}", DialStr, label, target.host, target.port);
            co_return std::make_pair(fault::code::connection_refused, nullptr);
        }

        trace::info("{} {} success, target: {}:{}", DialStr, label, target.host, target.port);
        co_return std::make_pair(ec, transport::make_reliable(std::move(conn)));
    }

    auto dial(outbound::proxy &outbound_proxy, const protocol::target &target, const net::any_io_executor &executor)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        auto [ec, trans] = co_await outbound_proxy.async_connect(target, executor);
        if (fault::failed(ec) || !trans)
        {
            trace::debug("{} outbound dial failed: {}, target: {}:{}", DialStr,
                         fault::describe(ec), target.host, target.port);
        }
        co_return std::pair{ec, std::move(trans)};
    }

} // namespace psm::connect
