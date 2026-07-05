/**
 * @file handler.cpp
 * @brief Trojan 协议处理器实现
 */

#include <prism/proto/protocol/trojan/handler.hpp>

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/worker/resources.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/tunnel/forward/basic.hpp>
#include <prism/net/connect/tunnel/forward/pipeline.hpp>
#include <prism/net/connect/tunnel/forward_relay.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/proto/multiplex/bootstrap.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/proto/protocol/trojan/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>
#include <utility>

namespace psm::protocol::trojan
{
    using namespace psm::trace;
    namespace account = psm::account;

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

        auto verifier = [this](std::string_view credential) -> bool
        {
            if (!ctx_.server_ctx.account_store.get())
            {
                trace::warn<flt::conn | flt::protocol>(
                    *prefix_, "account directory not configured");
                return false;
            }
            auto lease = account::try_acquire(*ctx_.server_ctx.account_store.get(), credential);
            if (!lease)
            {
                trace::warn<flt::conn | flt::protocol>(
                    *prefix_, "credential verification failed");
                return false;
            }
            ctx_.account_lease = std::move(lease);
            return true;
        };

        const auto agent = make_conn(std::move(inbound),
            ctx_.server_ctx.config().protocol.trojan, std::move(verifier));
        agent->set_traffic(&wr->traffic(), ctx_.detected_protocol);

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_,
                "handshake failed: {}", fault::describe(trojan_ec));
            co_return;
        }

        switch (req.cmd)
        {
        case command::connect:
        {
            target target(ctx_.frame_arena.get());
            target.host = to_string(req.destination_address, ctx_.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf), req.port);
            target.port.assign(port_buf, std::distance(port_buf, pe));

            target.positive = true;
            trace::info<flt::conn | flt::protocol>(*prefix_,
                "CONNECT -> {}:{}", target.host, target.port);
            // forward_pipeline 内部自动检查 mux 标记（is_mux）并分流
            co_await psm::connect::forward_pipeline(
                wr, ctx_,
                psm::connect::pipeline_options{agent->release(), target, prefix_});
            ctx_.inbound = nullptr;
            break;
        }
        case command::udp_associate:
        {
            trace::info<flt::conn | flt::protocol>(*prefix_, "UDP_ASSOCIATE started");
            using route_fn = std::function<net::awaitable<
                std::pair<fault::code, net::ip::udp::endpoint>>(
                std::string_view, std::string_view)>;
            route_fn dgram_router = wr->outbound().make_router();
            const auto ec = co_await agent->async_associate(std::move(dgram_router));
            if (fault::failed(ec))
                trace::warn<flt::conn | flt::protocol>(*prefix_,
                    "UDP_ASSOCIATE failed: {}", fault::describe(ec));
            else
                trace::info<flt::conn | flt::protocol>(*prefix_, "UDP_ASSOCIATE completed");
            break;
        }
        case command::mux:
        {
            trace::info<flt::conn | flt::protocol>(*prefix_,
                "mux session started (cmd=0x7F)");
            const auto mux_ok = co_await psm::connect::spawn_mux_session(
                psm::connect::mux_session_options{wr, ctx_, agent->release(), prefix_});
            if (!mux_ok)
            {
                trace::warn<flt::conn | flt::protocol>(*prefix_, "mux bootstrap failed");
            }
            ctx_.inbound = nullptr;
            co_return;
        }
        default:
            trace::warn<flt::conn | flt::protocol>(*prefix_,
                "unknown command: {}", static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::protocol::trojan
