/**
 * @file handler.cpp
 * @brief Shadowsocks 2022 协议处理器实现
 */

#include <prism/proto/protocol/shadowsocks/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/worker/resources.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/net/connect/tunnel/forward/basic.hpp>
#include <prism/net/connect/tunnel/forward_relay.hpp>
#include <prism/proto/multiplex/bootstrap.hpp>
#include <prism/proto/protocol/shadowsocks/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <utility>

namespace psm::protocol::shadowsocks
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

        auto inbound = psm::transport::wrap_with_preview(
            std::move(ctx_.inbound), data_);
        ctx_.inbound = nullptr;

        thread_local std::shared_ptr<salt_pool> worker_salt_pool;
        thread_local std::int64_t cached_ttl = 0;
        const auto current_ttl = ctx_.server_ctx.config().protocol.shadowsocks.salt_ttl;
        if (!worker_salt_pool || cached_ttl != current_ttl)
        {
            worker_salt_pool = std::make_shared<salt_pool>(current_ttl);
            cached_ttl = current_ttl;
        }

        auto agent = make_conn(std::move(inbound),
            ctx_.server_ctx.config().protocol.shadowsocks, worker_salt_pool);

        auto [ec, req] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_,
                "handshake failed: {}", fault::describe(ec));
            co_return;
        }

        trace::info<flt::conn | flt::protocol>(*prefix_,
            "CONNECT -> {}:{}", agent->target().host, agent->target().port);

        auto ack_ec = co_await agent->acknowledge();
        if (fault::failed(ack_ec))
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_,
                "acknowledge failed: {}", fault::describe(ack_ec));
            co_return;
        }

        auto mux_sw = psm::connect::mux_switch::off;
        if (ctx_.server_ctx.config().mux.enabled)
            mux_sw = psm::connect::mux_switch::on;
        if (psm::connect::is_mux(agent->target().host, mux_sw))
        {
            trace::info<flt::conn | flt::protocol>(*prefix_, "mux session started");
            auto mux_proto = co_await multiplex::bootstrap(
                multiplex::bootstrap_context{
                    .transport = std::static_pointer_cast<transport::transmission>(agent),
                    .outbound = &wr->outbound(),
                    .cfg = ctx_.server_ctx.config().mux,
                    .traffic = &wr->traffic(),
                    .proto = ctx_.detected_protocol, .prefix = prefix_,
                });
            if (mux_proto)
                mux_proto->start();
            co_return;
        }

        auto trans = std::static_pointer_cast<transport::transmission>(agent);
        psm::connect::forward_relay fr{ctx_,
            {"SS2022", agent->target(), std::move(trans), prefix_}};
        co_await fr.run();
    }
} // namespace psm::protocol::shadowsocks
