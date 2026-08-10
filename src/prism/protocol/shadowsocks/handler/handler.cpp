/**
 * @file handler.cpp
 * @brief Shadowsocks 2022 协议处理器实现
 */

#include <prism/protocol/shadowsocks/handler/handler.hpp>

#include <prism/settings/settings.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward_relay.hpp>
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/protocol/shadowsocks/handler/conn.hpp>
#include <prism/protocol/vmess/handler/handler.hpp>
#include <prism/protocol/vmess/vmess.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/preview.hpp>

#include <chrono>
#include <utility>

namespace psm::protocol::shadowsocks
{
    using namespace psm::diagnose;

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

        const auto hs_begin = std::chrono::steady_clock::now();
        auto [ec, req] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            // SS2022 握手失败：若启用 VMess，回退尝试（共享 probe fallback 通道）
            const auto &vmess_cfg = res_.worker->process->cfg->protocol.vmess;
            if (vmess_cfg.enable_tcp || vmess_cfg.enable_udp)
            {
                if (trace)
                    diagnose::debug(trace,
                        "ss2022 handshake failed ({}), falling back to vmess",
                        fault::describe(ec));
                co_await psm::protocol::vmess::fallback_run(res_, data_, agent->release());
                co_return;
            }
            if (trace)
                diagnose::warn(trace,
                    "handshake failed: {}", fault::describe(ec));
            co_return;
        }

        if (trace)
        {
            const auto hs_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - hs_begin).count();
            diagnose::access(trace,
                "CONNECT -> {}:{} (ss2022 handshake {} ms)",
                agent->target().host, agent->target().port, hs_ms);
        }

        auto ack_ec = co_await agent->acknowledge();
        if (fault::failed(ack_ec))
        {
            if (trace)
                diagnose::warn(trace,
                    "acknowledge failed: {}", fault::describe(ack_ec));
            co_return;
        }

        auto mux_sw = psm::connect::mux_switch::off;
        if (res_.worker->process->cfg->mux.enabled)
            mux_sw = psm::connect::mux_switch::on;
        if (psm::connect::is_mux(agent->target().host, mux_sw))
        {
            if (trace)
                diagnose::debug(trace, "mux session started");
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
