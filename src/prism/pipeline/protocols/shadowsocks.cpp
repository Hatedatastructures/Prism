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

        // 乐观响应：先发送 acknowledge 再拨号（与 mihomo 一致）
        auto ack_ec = co_await agent->acknowledge();
        if (fault::failed(ack_ec))
        {
            trace::warn("{} acknowledge failed: {}", shadowsocks_tag, fault::describe(ack_ec));
            co_return;
        }

        // 拨号 + 隧道转发（relay 本身作为 inbound，AEAD 加解密持续进行）
        co_await primitives::forward(ctx, "SS2022", agent->target(), std::static_pointer_cast<channel::transport::transmission>(agent));
    }
} // namespace psm::pipeline
