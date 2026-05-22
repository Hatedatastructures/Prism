#include <prism/protocol/shadowsocks/process.hpp>
#include <prism/protocol/shadowsocks/conn.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/transport/preview.hpp>
#include <prism/config.hpp>
#include <prism/trace/spdlog.hpp>

constexpr std::string_view shadowsocks_tag = "[Protocol.Shadowsocks]";

namespace psm::protocol::shadowsocks
{
    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        auto inbound = psm::transport::wrap_with_preview(std::move(ctx.inbound), data, ctx.frame_arena.get());
        ctx.inbound = nullptr;

        // worker 线程独占 salt pool（thread_local 保证每个工作线程独立实例，无需锁）
        thread_local std::shared_ptr<salt_pool> worker_salt_pool;
        thread_local std::int64_t cached_ttl = 0;
        const auto current_ttl = ctx.server_ctx.config().protocol.shadowsocks.salt_pool_ttl;
        if (!worker_salt_pool || cached_ttl != current_ttl)
        {
            worker_salt_pool = std::make_shared<salt_pool>(current_ttl);
            cached_ttl = current_ttl;
        }

        // 创建 SS2022 relay
        auto agent = make_conn(
            std::move(inbound), ctx.server_ctx.config().protocol.shadowsocks, worker_salt_pool);

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
        co_await psm::connect::forward(ctx, "SS2022", agent->target(), std::static_pointer_cast<transport::transmission>(agent));
    }
} // namespace psm::protocol::shadowsocks
