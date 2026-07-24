#include <prism/net/connect/tunnel/forward/pipeline.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/outbound/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/tunnel/tunnel_relay.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/trace/trace.hpp>

#include <utility>

using namespace psm::trace;

namespace psm::connect
{
    namespace net = boost::asio;

    auto forward_pipeline(
        psm::resource::session &res,
        const psm::connect::target &target,
        pipeline_options opts) -> net::awaitable<fault::code>
    {
        auto mux_sw = psm::connect::mux_switch::off;
        if (res.worker->process->cfg->mux.enabled)
            mux_sw = psm::connect::mux_switch::on;
        if (psm::connect::is_mux(target.host, mux_sw))
        {
            if (opts.trace)
                trace::info<flt::conn | flt::protocol>(opts.trace, "mux session started");
            const auto ok = co_await spawn_mux_session(
                mux_session_options{res, std::move(opts.inbound), opts.trace});
            if (!ok)
            {
                if (opts.trace)
                    trace::warn<flt::conn | flt::protocol>(opts.trace,
                        "mux bootstrap failed");
                co_return fault::code::bad_gateway;
            }
            co_return fault::code::success;
        }

        psm::outbound::dial_options dial_opts;
        dial_opts.trace = opts.trace;
        dial_opts.allow_reverse = target.positive;
        auto dial_res = co_await psm::outbound::dial(
            {*res.worker->outbound, res.worker->ioc, res.worker->traffic}, target, dial_opts);
        if (fault::failed(dial_res.code) || !dial_res.transport)
        {
            co_return dial_res.code;
        }

        tunnel_options t_opts;
        t_opts.inbound = std::move(opts.inbound);
        t_opts.outbound = std::move(dial_res.transport);
        t_opts.trace = opts.trace;
        t_opts.buffer_size = res.buffer;
        t_opts.traffic = &res.worker->traffic;
        t_opts.detected = res.detected;
        t_opts.lease = &res.lease;
        if (res.worker->process->cfg->stealth.pad.enabled())
        {
            t_opts.pad_cfg = &res.worker->process->cfg->stealth.pad;
        }

        tunnel_relay relay{std::move(t_opts)};
        co_await relay.run();
        co_return fault::code::success;
    }

    auto spawn_mux_session(mux_session_options opts) -> net::awaitable<bool>
    {
        auto transport = std::move(opts.transport);
        auto trace_ctx = std::move(opts.trace);

        auto mux_proto = co_await multiplex::bootstrap(
            multiplex::bootstrap_context{
                .transport = std::move(transport),
                .res = &opts.res,
            });

        if (!mux_proto)
        {
            co_return false;
        }
        mux_proto->start();
        co_return true;
    }

} // namespace psm::connect
