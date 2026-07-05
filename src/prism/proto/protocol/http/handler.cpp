/**
 * @file handler.cpp
 * @brief HTTP 协议处理器实现
 */

#include <prism/proto/protocol/http/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/worker/resources.hpp>
#include <prism/instance/outbound/dial.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/proto/protocol/http/conn.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <string_view>
#include <utility>

namespace psm::protocol::http
{
    using namespace psm::trace;

    handler::handler(protocol::handler_params params) noexcept
        : ctx_(params.ctx)
        , data_(params.data)
        , prefix_(std::move(params.trace))
    {
    }

    auto handler::run() -> net::awaitable<void>
    {
        auto wr = ctx_.worker_ctx.resources.lock();
        if (!wr)
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_, "worker resources expired");
            co_return;
        }

        ctx_.frame_arena.reset();

        auto inbound = psm::transport::wrap_with_preview(
            std::move(ctx_.inbound), data_);
        ctx_.inbound = nullptr;

        auto relay = make_conn(std::move(inbound), ctx_.server_ctx.account_store.get());
        auto [ec, req] = co_await relay->handshake();
        if (fault::failed(ec))
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_,
                "handshake failed: {}", fault::describe(ec));
            co_return;
        }

        const auto target = recognition::resolve(req);
        trace::info<flt::conn | flt::protocol>(*prefix_,
            "{} {} -> {}:{}", req.method, req.target, target.host, target.port);

        // 通过 outbound::dial 统一入口拨号
        psm::outbound::dial_options dial_opts;
        dial_opts.trace = prefix_;
        auto dial_res = co_await psm::outbound::dial(wr, target, dial_opts);
        const auto dial_ec = dial_res.code;
        auto outbound = std::move(dial_res.transport);

        if (fault::failed(dial_ec) || !outbound)
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_,
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
            t_opts.trace = prefix_;
            t_opts.buffer_size = ctx_.buffer_size;
            t_opts.traffic = &wr->traffic();
            t_opts.detected = ctx_.detected_protocol;
            t_opts.lease = &ctx_.account_lease;
            co_await psm::connect::tunnel(std::move(t_opts));
        }
        else
        {
            co_await relay->forward(req, outbound, ctx_.frame_arena.get());
            auto t_opts = psm::connect::tunnel_options{};
            t_opts.inbound = relay->release();
            t_opts.outbound = outbound;
            t_opts.trace = prefix_;
            t_opts.buffer_size = ctx_.buffer_size;
            t_opts.traffic = &wr->traffic();
            t_opts.detected = ctx_.detected_protocol;
            t_opts.lease = &ctx_.account_lease;
            co_await psm::connect::tunnel(std::move(t_opts));
        }
    }
} // namespace psm::protocol::http
