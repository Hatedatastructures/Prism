#include <prism/net/connect/tunnel/forward/pipeline.hpp>

#include <prism/context/context.hpp>
#include <prism/instance/outbound/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/tunnel/tunnel_relay.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/proto/multiplex/bootstrap.hpp>
#include <prism/trace/trace.hpp>

#include <utility>

using namespace psm::trace;

namespace psm::connect
{
    namespace net = boost::asio;

    auto forward_pipeline(
        psm::worker::handle handle,
        context::session &session,
        pipeline_options opts) -> net::awaitable<fault::code>
    {
        if (!handle)
        {
            trace::warn<flt::conn | flt::protocol>(opts.trace,
                "forward_pipeline: worker::handle expired");
            co_return fault::code::resource_unavailable;
        }

        if (opts.enable_mux_check)
        {
            auto mux_sw = psm::connect::mux_switch::off;
            if (session.server_ctx.config().mux.enabled)
            {
                mux_sw = psm::connect::mux_switch::on;
            }
            if (psm::connect::is_mux(opts.target.host, mux_sw))
            {
                trace::info<flt::conn | flt::protocol>(opts.trace, "mux session started");
                const auto ok = co_await spawn_mux_session(
                    mux_session_options{handle, session, std::move(opts.inbound), opts.trace});
                if (!ok)
                {
                    trace::warn<flt::conn | flt::protocol>(opts.trace,
                        "mux bootstrap failed");
                    co_return fault::code::bad_gateway;
                }
                co_return fault::code::success;
            }
        }

        psm::outbound::dial_options dial_opts;
        dial_opts.trace = opts.trace;
        dial_opts.allow_reverse = opts.target.positive;
        auto dial_res = co_await psm::outbound::dial(handle, opts.target, dial_opts);
        if (fault::failed(dial_res.code) || !dial_res.transport)
        {
            co_return dial_res.code;
        }

        tunnel_options t_opts;
        t_opts.inbound = std::move(opts.inbound);
        t_opts.outbound = std::move(dial_res.transport);
        t_opts.trace = opts.trace;
        t_opts.buffer_size = session.buffer_size;
        t_opts.traffic = &handle->traffic();
        t_opts.detected = session.detected_protocol;
        t_opts.lease = &session.account_lease;
        if (session.server_ctx.config().stealth.pad.enabled())
        {
            t_opts.pad_cfg = &session.server_ctx.config().stealth.pad;
        }

        tunnel_relay relay{std::move(t_opts)};
        co_await relay.run();
        co_return fault::code::success;
    }

    auto spawn_mux_session(mux_session_options opts) -> net::awaitable<bool>
    {
        auto handle = std::move(opts.handle);
        auto &session = opts.session;
        auto transport = std::move(opts.transport);
        auto trace_ctx = std::move(opts.trace);

        if (!handle)
        {
            trace::warn<flt::conn | flt::protocol>(trace_ctx,
                "spawn_mux_session: worker::handle expired");
            co_return false;
        }

        auto mux_proto = co_await multiplex::bootstrap(
            multiplex::bootstrap_context{
                .transport = std::move(transport),
                .outbound = &handle->outbound(),
                .cfg = session.server_ctx.config().mux,
                .traffic = &handle->traffic(),
                .proto = session.detected_protocol,
                .prefix = std::move(trace_ctx),
            });

        if (!mux_proto)
        {
            co_return false;
        }
        mux_proto->start();
        co_return true;
    }

} // namespace psm::connect
