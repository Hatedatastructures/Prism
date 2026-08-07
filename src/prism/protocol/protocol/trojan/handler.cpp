/**
 * @file handler.cpp
 * @brief Trojan 协议处理器实现
 */

#include <prism/protocol/trojan/handler/handler.hpp>

#include <prism/user/directory.hpp>
#include <prism/settings/settings.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward/pipeline.hpp>
#include <prism/net/connection/tunnel/forward_relay.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/protocol/trojan/handler/conn.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>
#include <utility>

namespace psm::protocol::trojan
{
    using namespace psm::diagnose;
    namespace account = psm::user;

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
            auto lease = user::try_acquire(dir, credential);
            if (!lease)
            {
                if (auto t = res_.trace)
                    diagnose::warn(t,
                        "credential verification failed");
                return false;
            }
            res_.lease = std::move(lease);
            return true;
        };

        const auto agent = make_conn(std::move(inbound),
            res_.worker->process->cfg->protocol.trojan, std::move(verifier));
        agent->set_traffic(&res_.worker->traffic, res_.detected);

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            if (trace)
                diagnose::warn(trace,
                    "handshake failed: {}", fault::describe(trojan_ec));
            co_return;
        }

        switch (req.cmd)
        {
        case command::connect:
        {
            target target(res_.arena.get());
            target.host = to_string(req.destination_address, res_.arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf), req.port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            if (trace)
                diagnose::info(trace,
                    "CONNECT -> {}:{}", target.host, target.port);

            co_await psm::connect::forward_pipeline(res_, target,
                psm::connect::pipeline_options{agent->release(), trace});
            res_.inbound = nullptr;
            break;
        }
        case command::udp_associate:
        {
            if (trace)
                diagnose::debug(trace, "UDP_ASSOCIATE started");
            using route_fn = std::function<net::awaitable<
                std::pair<fault::code, net::ip::udp::endpoint>>(
                std::string_view, std::string_view)>;
            route_fn dgram_router = res_.worker->outbound->make_router();
            const auto ec = co_await agent->async_associate(std::move(dgram_router));
            if (fault::failed(ec))
            {
                if (trace)
                    diagnose::warn(trace,
                        "UDP_ASSOCIATE failed: {}", fault::describe(ec));
            }
            else if (trace)
            {
                diagnose::debug(trace, "UDP_ASSOCIATE completed");
            }
            break;
        }
        case command::mux:
        {
            if (trace)
                diagnose::debug(trace,
                    "mux session started (cmd=0x7F)");
            const auto mux_ok = co_await psm::connect::spawn_mux_session(
                psm::connect::mux_session_options{res_, agent->release(), trace});
            if (!mux_ok && trace)
            {
                diagnose::warn(trace, "mux bootstrap failed");
            }
            res_.inbound = nullptr;
            co_return;
        }
        default:
            if (trace)
                diagnose::warn(trace,
                    "unknown command: {}", static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::protocol::trojan
