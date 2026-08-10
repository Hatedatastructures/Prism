/**
 * @file handler.cpp
 * @brief VMess 协议处理器实现
 */

#include <prism/protocol/vmess/handler/handler.hpp>

#include <prism/user/directory.hpp>
#include <prism/settings/settings.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward/pipeline.hpp>
#include <prism/net/connection/tunnel/forward_relay.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/protocol/vmess/handler/conn.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>
#include <utility>

namespace psm::protocol::vmess
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
        co_await fallback_run(res_, data_);
    }

    auto fallback_run(psm::resource::session &res, const std::span<const std::byte> data,
                      shared_transmission inbound) -> net::awaitable<void>
    {
        auto trace = res.trace;

        if (!inbound)
        {
            // 正常分发路径：从会话资源取回传输层并包装预读
            if (!res.inbound)
            {
                co_return;
            }
            inbound = psm::transport::wrap_with_preview(std::move(res.inbound), data);
            res.inbound = nullptr;
        }

        // 从账户目录枚举 UUID 派生 cmdKey 表
        auto &dir = *res.worker->process->accounts;
        std::vector<std::string_view> credentials;
        dir.enumerate(credentials);

        std::vector<user_key> keys;
        keys.reserve(credentials.size());
        for (const auto &credential : credentials)
        {
            // 仅接受 36 字符 UUID 形式凭证
            std::array<std::uint8_t, 16> uuid_bytes{};
            if (!codec::parse_uuid(credential, uuid_bytes))
                continue;
            const auto cmd = codec::cmd_key_from_uuid(uuid_bytes);
            keys.push_back(user_key{cmd});
        }
        if (keys.empty())
        {
            if (trace)
                diagnose::warn(trace, "no vmess users configured");
            co_return;
        }

        const auto agent = make_conn(std::move(inbound),
            res.worker->process->cfg->protocol.vmess, std::move(keys));
        agent->set_traffic(&res.worker->traffic, res.detected);

        auto [vmess_ec, req] = co_await agent->handshake();
        if (fault::failed(vmess_ec))
        {
            if (trace)
                diagnose::warn(trace,
                    "handshake failed: {}", fault::describe(vmess_ec));
            co_return;
        }

        switch (req.command)
        {
        case static_cast<std::uint8_t>(command::tcp):
        {
            target target(res.arena.get());
            target.host = psm::protocol::common::addr_to_str(req.destination, res.arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf),
                static_cast<std::uint32_t>(req.port));
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            if (trace)
                diagnose::access(trace,
                    "CONNECT -> {}:{}", target.host, target.port);

            co_await psm::connect::forward_pipeline(res, target,
                psm::connect::pipeline_options{agent, trace});
            res.inbound = nullptr;
            break;
        }
        case static_cast<std::uint8_t>(command::udp):
        {
            if (trace)
                diagnose::debug(trace, "UDP associate started");
            using route_fn = std::function<net::awaitable<
                std::pair<fault::code, net::ip::udp::endpoint>>(
                std::string_view, std::string_view)>;
            route_fn dgram_router = res.worker->outbound->make_router();
            const auto ec = co_await agent->async_associate(std::move(dgram_router));
            if (fault::failed(ec))
            {
                if (trace)
                    diagnose::warn(trace,
                        "UDP associate failed: {}", fault::describe(ec));
            }
            else if (trace)
            {
                diagnose::debug(trace, "UDP associate completed");
            }
            break;
        }
        case static_cast<std::uint8_t>(command::mux):
        {
            if (trace)
                diagnose::debug(trace, "v2ray mux session requested");
            // v2ray mux 帧循环（后续版本接入）
            co_return;
        }
        default:
            if (trace)
                diagnose::warn(trace,
                    "unknown command: {}", static_cast<int>(req.command));
            break;
        }
    }
} // namespace psm::protocol::vmess
