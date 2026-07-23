/**
 * @file handler.cpp
 * @brief HTTP 协议处理器实现
 */

#include <prism/protocol/http/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/outbound/dial.hpp>
#include <prism/net/connect/dial/connector.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/protocol/http/conn.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <string_view>
#include <utility>

namespace psm::protocol::http
{
    using namespace psm::trace;

    handler::handler(protocol::handler_params params) noexcept
        : res_(params.res)
        , data_(params.data)
    {
    }

    auto handler::run() -> net::awaitable<void>
    {
        auto trace = res_.trace;

        res_.arena.reset();

        auto inbound = psm::transport::wrap_with_preview(std::move(res_.inbound), data_);
        res_.inbound = nullptr;

        auto relay = make_conn(std::move(inbound), &*res_.worker->process->accounts);
        auto [ec, req] = co_await relay->handshake();
        if (fault::failed(ec))
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "handshake failed: {}", fault::describe(ec));
            co_return;
        }

        const auto target = recognition::resolve(req);
        if (trace)
            trace::info<flt::conn | flt::protocol>(trace,
                "{} {} -> {}:{}", req.method, req.target, target.host, target.port);

        psm::outbound::dial_options dial_opts;
        dial_opts.trace = trace;
        auto dial_res = co_await psm::outbound::dial(
            {*res_.worker->outbound, res_.worker->ioc, res_.worker->traffic}, target, dial_opts);
        const auto dial_ec = dial_res.code;
        auto outbound = std::move(dial_res.transport);

        if (fault::failed(dial_ec) || !outbound)
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "dial failed: {}:{}", target.host, target.port);
            co_await relay->send_gateway_err();
            co_return;
        }

        if (req.method == "CONNECT")
        {
            if (fault::failed(co_await relay->send_ok()))
                co_return;
            auto t_opts = psm::connect::tunnel_options{};
            t_opts.inbound = relay->release();
            t_opts.outbound = outbound;
            t_opts.trace = trace;
            t_opts.buffer_size = res_.buffer;
            t_opts.traffic = &res_.worker->traffic;
            t_opts.detected = res_.detected;
            t_opts.lease = &res_.lease;
            co_await psm::connect::tunnel(std::move(t_opts));
        }
        else
        {
            co_await relay->forward(req, outbound, res_.arena.get());
            auto t_opts = psm::connect::tunnel_options{};
            t_opts.inbound = relay->release();
            t_opts.outbound = outbound;
            t_opts.trace = trace;
            t_opts.buffer_size = res_.buffer;
            t_opts.traffic = &res_.worker->traffic;
            t_opts.detected = res_.detected;
            t_opts.lease = &res_.lease;
            co_await psm::connect::tunnel(std::move(t_opts));
        }
    }
} // namespace psm::protocol::http
