#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/util/auth.hpp>
#include <prism/stealth/shadowtls/transport.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/snapshot.hpp>
#include <prism/transport/preview.hpp>
#include <prism/connect/util.hpp>
#include <prism/protocol/types.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::shadowtls
{
    using hello_features = protocol::tls::hello_features;

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        const auto &st_cfg = cfg.stealth.shadowtls;
        // v3: 需要至少一个用户、握手目标和 SNI 白名单
        if (st_cfg.version == 3)
            return !st_cfg.users.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
        // v2: 需要密码、握手目标和 SNI 白名单
        return !st_cfg.password.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
    }

    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "shadowtls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.shadowtls.server_names);
    }

    auto scheme::sniff(std::uint32_t bitmap,
                       const hello_features & /*features*/) const
        -> sniff_result
    {
        // Tier 0: 非标准 session_id 长度（零成本）
        if (recognition::tls::has_feature(bitmap, recognition::tls::session_id_non_standard))
        {
            return {
                .hit = true,
                .solo = false,  // 不能独占，需要 Tier 1 HMAC 验证
                .hint = 150,
                .note = "non-standard session_id length"};
        }

        return {.hit = false};
    }

    auto scheme::verify(const hello_features &features,
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

        // 获取底层 reliable transport 的 raw socket
        auto *rel = ctx.inbound->lowest_layer<transport::reliable>();

        if (!rel)
        {
            trace::info("[ShadowTlsScheme] Cannot access reliable transport, pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        // 使用 Recognition 层已读取的 ClientHello（不再从 socket 重复读取）
        handshake_detail detail;
        auto hs_result = co_await stealth::shadowtls::handshake(
            rel->native_socket(),
            ctx.cfg->stealth.shadowtls,
            std::move(ctx.preread),
            detail);

        if (fault::succeeded(hs_result.error) && !detail.client_firstframe.empty())
        {
            auto &first_frame = detail.client_firstframe;
            // ShadowTLS v3: first_frame 格式是 TLS header(5) + payload
            // 需要剥离 TLS header，只保留 payload 作为内层协议数据
            constexpr std::size_t local_tls_hdrsize = 5;
            if (first_frame.size() > local_tls_hdrsize)
            {
                // 剥离 TLS header，提取真正的 payload
                auto payload = std::span<const std::byte>(
                    first_frame.data() + local_tls_hdrsize,
                    first_frame.size() - local_tls_hdrsize);

                trace::debug("[ShadowTlsScheme] first_frame TLS header stripped, payload_size={}", payload.size());

                // 使用 payload（不含 TLS header）进行协议检测
                // safe: casting uint8_t payload to string_view for inner protocol detection
                auto inner_view = std::string_view(
                    reinterpret_cast<const char *>(payload.data()), payload.size());
                result.detected = recognition::probe::detect_tls(inner_view);

                // detect_tls() 不再自动 fallback 到 shadowsocks，
                // 对于 ShadowTLS 场景，数据已足够多（payload 通常数百字节），
                // 如果不是 HTTP/VLESS/Trojan，则排除法认为是 SS2022
                if (result.detected == protocol::protocol_type::unknown)
                {
                    result.detected = protocol::protocol_type::shadowsocks;
                    trace::debug("[ShadowTlsScheme] no known protocol matched, fallback to shadowsocks");
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
                    shadowtls_handover{
                        detail.matched_password,
                        std::span<const std::byte>(detail.server_random.data(), detail.server_random.size()),
                        payload,
                        std::move(detail.hmac_write_ctx),
                        std::move(detail.hmac_read_ctx)
                    });

                // ShadowTLS.Transport 管理初始数据，不放入 preread 避免数据重复
                result.transport = shadowtls_trans;
                result.scheme = "shadowtls";

                trace::debug("[ShadowTlsScheme] Authenticated (user: {}), inner protocol: {}, shadowtls_transport created (HMAC inherited)",
                             detail.matched_user, protocol::to_string_view(result.detected));
            }
            else
            {
                // first_frame 太小，无法剥离 TLS header
                trace::warn("[ShadowTlsScheme] first_frame too small to strip TLS header: size={}", first_frame.size());
                result.detected = protocol::protocol_type::tls;
                result.transport = std::move(ctx.inbound);
            }
        }
        else
        {
            result.detected = protocol::protocol_type::tls;
            result.error = hs_result.error;
            result.polluted = hs_result.polluted;
            trace::debug("[ShadowTlsScheme] Not ShadowTLS, pass to next scheme");
        }

        co_return result;
    }
} // namespace psm::stealth::shadowtls
