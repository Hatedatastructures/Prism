#include <prism/diagnose/diagnose.hpp>
#include <prism/net/connection/outbound/dial.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <utility>

using namespace psm::diagnose;

namespace psm::outbound
{
    namespace net = boost::asio;

    auto dial(dial_handles handles, const psm::connect::target &target, dial_options opts)
        -> net::awaitable<dial_result>
    {
        dial_result result;

        const auto start = std::chrono::steady_clock::now();

        auto [ec, trans] = co_await handles.outbound.async_connect(target, handles.ioc.get_executor());

        result.elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        result.code = ec;
        result.transport = std::move(trans);
        result.reverse_routed = !target.positive;

        if (fault::failed(ec) || !result.transport)
        {
            if (ec == fault::code::ipv6_disabled)
            {
                diagnose::debug(opts.trace, "outbound::dial: IPv6 disabled: {}:{}", target.host, target.port);
            }
            else
            {
                diagnose::warn(opts.trace, "outbound::dial: failed: {}, target: {}:{}", fault::describe(ec),
                               target.host, target.port);
            }
            co_return result;
        }

        if (opts.report_traffic)
        {
            handles.traffic.on_connect();
        }

        diagnose::access(opts.trace, "outbound::dial: success, target: {}:{}, elapsed={}ms", target.host,
                         target.port, result.elapsed.count());

        co_return result;
    }

    auto resolve_datagram(psm::outbound::direct &outbound, std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        auto router_fn = outbound.make_router();
        co_return co_await router_fn(host, port);
    }

} // namespace psm::outbound
