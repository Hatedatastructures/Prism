/**
 * @file scheme.cpp
 * @brief TrustTunnel 伪装方案实现
 * @details TrustTunnel 使用标准 TLS 证书，支持 TCP 和 UDP 传输。
 * TrustTunnel 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 *
 * **当前状态**：基础框架已实现，认证逻辑待完善。
 */
#include <prism/stealth/trusttunnel/scheme.hpp>
#include <prism/connect.hpp>
#include <prism/config.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/protocol/protocol_type.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>

namespace psm::stealth::trusttunnel
{
    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.trusttunnel.enabled();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "trusttunnel";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.trusttunnel.server_names);
    }

    auto scheme::guess(const psm::config &cfg) const
        -> verify_result
    {
        // TrustTunnel 无 ClientHello 独占特征，依赖 SNI 匹配
        // SNI 路由阶段已过滤，这里只需要返回基础分
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "TrustTunnel: rely on SNI match"};
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

        const auto &cfg = ctx.cfg->stealth.trusttunnel;

        // TODO: 实现完整的 TrustTunnel 握手流程
        // 1. 执行标准 TLS 握手（使用配置的证书）
        // 2. 读取 TLS 应用数据（客户端首帧）
        // 3. 验证用户身份
        // 4. 根据网络配置选择传输模式（TCP/UDP）
        // 5. 认证成功后检测内层协议

        // 当前返回 TLS 表示"不是我"，传递给下一个 scheme
        result.detected = protocol::protocol_type::tls;
        result.transport = std::move(ctx.inbound);
        trace::debug("[TrustTunnel] TrustTunnel not detected, pass to next scheme");

        co_return result;
    }
} // namespace psm::stealth::trusttunnel