/**
 * @file handler.cpp
 * @brief VLESS 协议处理器实现
 */

#include <prism/protocol/vless/handler.hpp>

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/net/connect/dial/connector.hpp>
#include <prism/net/connect/tunnel/forward/basic.hpp>
#include <prism/net/connect/tunnel/forward/pipeline.hpp>
#include <prism/net/connect/tunnel/forward_relay.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/protocol/common/mux.hpp>
#include <prism/protocol/vless/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <cstdint>
#include <charconv>
#include <utility>

namespace psm::protocol::vless
{
    using namespace psm::trace;
    namespace account = psm::account;

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

        auto verifier = [this](std::string_view credential) -> bool
        {
            auto &dir = *res_.worker->process->accounts;
            auto lease = account::try_acquire(dir, credential);
            if (!lease)
            {
                if (auto t = res_.trace)
                    trace::warn<flt::conn | flt::protocol>(t,
                        "credential verification failed");
                return false;
            }
            res_.lease = std::move(lease);
            return true;
        };

        const auto agent = make_conn(std::move(inbound),
            res_.worker->process->cfg->protocol.vless, std::move(verifier));
        agent->set_traffic(&res_.worker->traffic, res_.detected);

        auto [vless_ec, req] = co_await agent->handshake();
        if (fault::failed(vless_ec))
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "handshake failed: {}", fault::describe(vless_ec));
            co_return;
        }

        switch (req.cmd)
        {
        case command::tcp:
        case command::mux:
        {
            target target(res_.arena.get());
            target.host = to_string(req.destination_address, res_.arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf),
                static_cast<std::uint32_t>(req.port));
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace,
                    "CONNECT -> {}:{}", target.host, target.port);

            co_await psm::connect::forward_pipeline(res_, target,
                psm::connect::pipeline_options{agent->release(), trace});
            res_.inbound = nullptr;
            break;
        }
        case command::udp:
        {
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace, "UDP associate started");
            using route_fn = std::function<net::awaitable<
                std::pair<fault::code, net::ip::udp::endpoint>>(
                std::string_view, std::string_view)>;
            route_fn dgram_router = res_.worker->outbound->make_router();
            const auto ec = co_await agent->async_associate(std::move(dgram_router));
            if (fault::failed(ec))
            {
                if (trace)
                    trace::warn<flt::conn | flt::protocol>(trace,
                        "UDP associate failed: {}", fault::describe(ec));
            }
            else if (trace)
            {
                trace::info<flt::conn | flt::protocol>(trace, "UDP associate completed");
            }
            break;
        }
        default:
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "unknown command: {}", static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::protocol::vless
