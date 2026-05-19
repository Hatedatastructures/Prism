/**
 * @file scheme.cpp
 * @brief ShadowTLS v3 伪装方案实现
 * @details ShadowTLS 是 Tier 1 方案，需要 HMAC 验证确认身份。
 */

#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/stealth/shadowtls/transport.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/channel/transport/snapshot.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>

#include <typeinfo>

namespace psm::stealth::shadowtls
{
    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        const auto &st_cfg = cfg.stealth.shadowtls;
        // v3: 需要至少一个用户、握手目标和 SNI 白名单
        if (st_cfg.version == 3)
            return !st_cfg.users.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
        // v2: 需要密码、握手目标和 SNI 白名单
        return !st_cfg.password.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "shadowtls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        memory::vector<memory::string> names;
        for (const auto &name : cfg.stealth.shadowtls.server_names)
            names.push_back(memory::string(name));
        return names;
    }

    auto scheme::sniff(std::uint32_t bitmap,
                       const protocol::tls::client_hello_features &features) const
        -> sniff_result
    {
        using namespace protocol::tls;

        // Tier 0: 非标准 session_id 长度（零成本）
        if (has_feature(bitmap, session_id_non_standard))
        {
            return {
                .hit = true,
                .solo = false,  // 不能独占，需要 Tier 1 HMAC 验证
                .hint = 150,
                .note = "non-standard session_id length"};
        }

        return {.hit = false};
    }

    auto scheme::verify(const protocol::tls::client_hello_features &features,
                         std::span<const std::byte> raw,
                         const psm::config &cfg) const
        -> verify_result
    {
        const auto &st_cfg = cfg.stealth.shadowtls;

        // Tier 1: HMAC 验证（延迟执行）
        // 需要 session_id_len == 32 且 raw_client_hello >= 76 字节
        if (raw.size() >= 76 && features.session_id_len == 32)
        {
            if (st_cfg.version == 3)
            {
                for (const auto &user : st_cfg.users)
                {
                    if (user.password.empty())
                        continue;
                    if (verify_client_hello(raw, user.password))
                    {
                        trace::debug("[ShadowTLS] HMAC verified, user: {}", user.name);
                        return {
                            .score = 900,
                            .solo_flag = 0xFFFF,  // 独占
                            .note = memory::string("HMAC verified, user: ") + memory::string(user.name)};
                    }
                }
            }
            else if (!st_cfg.password.empty())
            {
                if (verify_client_hello(raw, st_cfg.password))
                {
                    trace::debug("[ShadowTLS] HMAC verified (v2)");
                    return {
                        .score = 900,
                        .solo_flag = 0xFFFF,
                        .note = "HMAC verified"};
                }
            }
        }

        // HMAC 不匹配
        return {.score = 50, .solo_flag = 0, .note = "HMAC not verified"};
    }

    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        // === 调试日志：确认 inbound 类型、preread 数据 ===
        trace::info("[ShadowTlsScheme] ctx.preread size={}", ctx.preread.size());
        if (ctx.preread.size() > 0)
        {
            const auto *raw = reinterpret_cast<const std::uint8_t *>(ctx.preread.data());
            trace::info("[ShadowTlsScheme] ctx.preread[0:5] = {:02x}{:02x}{:02x}{:02x}{:02x}",
                raw[0], raw[1], raw[2], raw[3], raw[4]);
        }

        // 调试：确认 inbound 实际类型
        trace::info("[ShadowTlsScheme] inbound type_name: {}", typeid(*ctx.inbound).name());
        if (ctx.inbound.use_count() > 0)
        {
            auto *inner_check = ctx.inbound.get();
            trace::info("[ShadowTlsScheme] inbound get() type_name: {}", typeid(*inner_check).name());
            // 检查是否能 dynamic_cast 到 preview
            if (auto *p = dynamic_cast<pipeline::primitives::preview *>(inner_check))
            {
                trace::info("[ShadowTlsScheme] IS preview, inner type: {}", typeid(*p->inner()).name());
            }
        if (auto *s = dynamic_cast<channel::transport::snapshot *>(inner_check))
            {
                trace::info("[ShadowTlsScheme] IS snapshot, inner type: {}", typeid(*s->inner()).name());
            }
            if (dynamic_cast<channel::transport::reliable *>(inner_check))
            {
                trace::info("[ShadowTlsScheme] IS reliable");
            }
        }

        // 获取底层 reliable transport 的 raw socket
        auto *rel = pipeline::primitives::find_reliable(ctx.inbound);
        trace::info("[ShadowTlsScheme] find_reliable returned={}", rel ? "yes" : "nullptr");

        if (!rel)
        {
            trace::info("[ShadowTlsScheme] Cannot access reliable transport, pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        // 使用 Recognition 层已读取的 ClientHello（不再从 socket 重复读取）
        auto hs = co_await stealth::shadowtls::handshake(
            rel->native_socket(),
            ctx.cfg->stealth.shadowtls,
            std::move(ctx.preread));

        if (hs.authenticated)
        {
            auto &first_frame = hs.client_first_frame;
            if (!first_frame.empty())
            {
                // ShadowTLS v3: first_frame 格式是 TLS header(5) + payload
                // 需要剥离 TLS header，只保留 payload 作为内层协议数据
                constexpr std::size_t tls_header_size = 5;
                if (first_frame.size() > tls_header_size)
                {
                    // 剥离 TLS header，提取真正的 payload
                    auto payload = std::span<const std::byte>(
                        first_frame.data() + tls_header_size,
                        first_frame.size() - tls_header_size);

                    trace::debug("[ShadowTlsScheme] first_frame TLS header stripped, payload_size={}", payload.size());

                    // 使用 payload（不含 TLS header）进行协议检测
                    auto inner_view = std::string_view(
                        reinterpret_cast<const char *>(payload.data()), payload.size());
                    result.detected = protocol::analysis::detect_tls(inner_view);

                    // 如果不是 TLS，可能是 SS2022
                    if (result.detected == protocol::protocol_type::unknown)
                    {
                        result.detected = protocol::protocol_type::shadowsocks;
                    }

                    // 从 reliable transport 中释放 socket 的所有权
                    auto raw_socket_opt = rel->release_socket();
                    if (!raw_socket_opt)
                    {
                        trace::warn("[ShadowTlsScheme] Cannot release socket from reliable transport");
                        result.detected = protocol::protocol_type::tls;
                        result.transport = std::move(ctx.inbound);
                        co_return result;
                    }
                    auto raw_socket = std::move(*raw_socket_opt);
                    trace::debug("[ShadowTlsScheme] socket released from reliable transport");

                    // 创建 ShadowTLS transport wrapper，持续处理 ShadowTLS 协议
                    // 使用 handshake 阶段累积的 HMAC 上下文，确保 HMAC 状态连续
                    // hmac_write_ctx: 写入方向（初始 = password + SR + "S")
                    // hmac_read_ctx: 读取方向（初始 = password + SR + "C" + first_frame_payload + HMAC[:4])
                    auto shadowtls_trans = std::make_shared<shadowtls_transport>(
                        std::move(raw_socket),
                        hs.matched_password,
                        std::span<const std::byte>(hs.server_random.data(), hs.server_random.size()),
                        payload,
                        std::move(hs.hmac_write_ctx),
                        std::move(hs.hmac_read_ctx));

                    // ShadowTLS.Transport 管理初始数据，不放入 preread 避免数据重复
                    result.transport = shadowtls_trans;
                    result.scheme = "shadowtls";

                    trace::debug("[ShadowTlsScheme] Authenticated (user: {}), inner protocol: {}, shadowtls_transport created (HMAC inherited)",
                                 hs.matched_user, protocol::to_string_view(result.detected));
                }
                else
                {
                    // first_frame 太小，无法剥离 TLS header
                    trace::warn("[ShadowTlsScheme] first_frame too small to strip TLS header: size={}", first_frame.size());
                    result.detected = protocol::protocol_type::tls;
                    result.transport = std::move(ctx.inbound);
                }
            }
        }
        else
        {
            result.detected = protocol::protocol_type::tls;
            trace::debug("[ShadowTlsScheme] Not ShadowTLS, pass to next scheme");
        }

        co_return result;
    }
} // namespace psm::stealth::shadowtls