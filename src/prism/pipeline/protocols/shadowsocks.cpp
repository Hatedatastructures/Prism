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
        auto inbound = primitives::wrap_with_preview(ctx, data, true);

        // worker 线程独占 salt pool（thread_local 保证每个工作线程独立实例，无需锁）
        thread_local auto worker_salt_pool = std::make_shared<protocol::shadowsocks::salt_pool>(
            ctx.server.cfg.shadowsocks.salt_pool_ttl);

        // 创建 SS2022 relay
        auto agent = protocol::shadowsocks::make_relay(
            std::move(inbound), ctx.server.cfg.shadowsocks, worker_salt_pool);

        // 执行握手：解密请求、验证时间戳、解析地址
        auto [ec, req] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::warn("{} handshake failed: {}", shadowsocks_tag, fault::describe(ec));
            co_return;
        }

        // 解析目标地址
        trace::info("{} CONNECT -> {}:{}", shadowsocks_tag, agent->target().host, agent->target().port);

        // 先拨号上游 — 失败时不发送响应，客户端看到连接失败而非误导性成功
        auto [dial_ec, outbound] = co_await primitives::dial(ctx.worker.router, "SS2022", agent->target(), true, true);
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

        // 拨号成功，发送握手响应
        auto ack_ec = co_await agent->acknowledge();
        if (fault::failed(ack_ec))
        {
            trace::warn("{} acknowledge failed: {}", shadowsocks_tag, fault::describe(ack_ec));
            co_return;
        }

        // 关键：relay 本身作为 inbound（不 release），AEAD 加解密持续进行
        co_await primitives::tunnel(
            std::static_pointer_cast<channel::transport::transmission>(agent),
            std::move(outbound), ctx);
    }
} // namespace psm::pipeline
