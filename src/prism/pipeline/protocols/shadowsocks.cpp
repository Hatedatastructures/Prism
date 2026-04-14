#include <prism/pipeline/protocols/shadowsocks.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/shadowsocks.hpp>
#include <prism/trace/spdlog.hpp>

constexpr std::string_view shadowsocks_tag = "[Pipeline.Shadowsocks]";

namespace psm::pipeline
{
    auto shadowsocks(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        auto inbound = std::move(ctx.inbound);
        if (!data.empty())
        {
            inbound = std::make_shared<primitives::preview>(std::move(inbound), data, nullptr);
        }

        // 全局 salt pool（跨会话共享）
        static auto global_salt_pool = std::make_shared<protocol::shadowsocks::salt_pool>(
            ctx.server.cfg.shadowsocks.salt_pool_ttl);

        // 创建 SS2022 relay
        auto agent = protocol::shadowsocks::make_relay(
            std::move(inbound), ctx.server.cfg.shadowsocks, global_salt_pool);

        // 执行握手：解密请求、验证时间戳、解析地址
        auto [ec, req] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::warn("{} handshake failed: {}", shadowsocks_tag, fault::describe(ec));
            co_return;
        }

        // 解析目标地址
        trace::info("{} CONNECT -> {}:{}", shadowsocks_tag, agent->target().host, agent->target().port);

        // 通过路由器建立到目标的连接
        const std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
        auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "SS2022", agent->target(), true, true);
        if (fault::failed(dial_ec) || !outbound)
        {
            if (dial_ec == fault::code::ipv6_disabled)
            {
                trace::debug("{} IPv6 disabled: {}:{}", shadowsocks_tag, agent->target().host, agent->target().port);
            }
            else
            {
                trace::warn("{} dial failed: {}, target: {}:{}", shadowsocks_tag, fault::describe(dial_ec),
                            agent->target().host, agent->target().port);
            }
            co_return;
        }

        // 关键：relay 本身作为 inbound（不 release），AEAD 加解密持续进行
        co_await primitives::tunnel(
            std::static_pointer_cast<channel::transport::transmission>(agent),
            std::move(outbound), ctx);
    }
} // namespace psm::pipeline
