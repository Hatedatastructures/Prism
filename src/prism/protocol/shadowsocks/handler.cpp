/**
 * @file handler.cpp
 * @brief Shadowsocks 2022 协议处理器实现
 */

#include <prism/protocol/shadowsocks/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/net/connect/tunnel/forward/basic.hpp>
#include <prism/net/connect/tunnel/forward_relay.hpp>
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/protocol/shadowsocks/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <utility>

namespace psm::protocol::shadowsocks
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

        auto inbound = psm::transport::wrap_with_preview(std::move(res_.inbound), data_);
        res_.inbound = nullptr;

        thread_local std::shared_ptr<salt_pool> worker_salt_pool;
        thread_local std::int64_t cached_ttl = 0;
        const auto current_ttl = res_.worker->process->cfg->protocol.shadowsocks.salt_ttl;
        if (!worker_salt_pool || cached_ttl != current_ttl)
        {
            worker_salt_pool = std::make_shared<salt_pool>(current_ttl);
            cached_ttl = current_ttl;
        }

        auto agent = make_conn(std::move(inbound),
            res_.worker->process->cfg->protocol.shadowsocks, worker_salt_pool);

        auto [ec, req] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "handshake failed: {}", fault::describe(ec));
            co_return;
        }

        if (trace)
            trace::info<flt::conn | flt::protocol>(trace,
                "CONNECT -> {}:{}", agent->target().host, agent->target().port);

        auto ack_ec = co_await agent->acknowledge();
        if (fault::failed(ack_ec))
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "acknowledge failed: {}", fault::describe(ack_ec));
            co_return;
        }

        auto mux_sw = psm::connect::mux_switch::off;
        if (res_.worker->process->cfg->mux.enabled)
            mux_sw = psm::connect::mux_switch::on;
        if (psm::connect::is_mux(agent->target().host, mux_sw))
        {
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace, "mux session started");
            auto mux_proto = co_await multiplex::bootstrap(
                multiplex::bootstrap_context{
                    .transport = std::static_pointer_cast<transport::transmission>(agent),
                    .res = &res_,
                });
            if (mux_proto)
                mux_proto->start();
            co_return;
        }

        auto trans = std::static_pointer_cast<transport::transmission>(agent);
        psm::connect::forward_relay fr{res_, {"SS2022", agent->target(), std::move(trans), trace}};
        co_await fr.run();
    }
} // namespace psm::protocol::shadowsocks
