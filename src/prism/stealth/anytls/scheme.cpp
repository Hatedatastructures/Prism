/**
 * @file scheme.cpp
 * @brief AnyTLS 伪装方案实现
 * @details AnyTLS 使用标准 TLS 证书，通过应用层认证实现代理功能。
 * AnyTLS 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 *
 * **当前状态**：基础框架已实现，认证逻辑待完善。
 */
#include <prism/stealth/anytls/scheme.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>

namespace psm::stealth::anytls
{
    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.anytls.enabled();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "anytls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        memory::vector<memory::string> names;
        for (const auto &name : cfg.stealth.anytls.server_names)
            names.push_back(memory::string(name));
        return names;
    }

    auto scheme::verify(const protocol::tls::client_hello_features &features,
                         std::span<const std::byte> raw,
                         const psm::config &cfg) const
        -> verify_result
    {
        // 如果有 ECH 配置且 ClientHello 有 ECH 扩展，尝试解密
        if (!cfg.stealth.anytls.ech_key.empty())
        {
            using namespace protocol::tls;
            auto bitmap = build_feature_bitmap(features);

            // 检查是否有 ECH 扩展
            if (has_feature(bitmap, has_ech))
            {
                // TODO: ECH 解密验证
                // 使用 ech_key 解密 ECH payload，获取 inner ClientHello
                // 检查 inner SNI 是否匹配 server_names

                trace::debug("[AnyTLS] ECH extension present, key configured");
                return {
                    .score = 300,
                    .solo_flag = 0,
                    .note = "ECH extension present, may be AnyTLS"};
            }
        }

        // 无 ECH 或 ECH 未配置，返回 low 分（依赖 SNI 匹配）
        return {.score = 0, .solo_flag = 0, .note = "no ECH"};
    }

    auto scheme::guess(const psm::config &cfg) const
        -> verify_result
    {
        // AnyTLS 无 ClientHello 独占特征，依赖 SNI 匹配
        // SNI 路由阶段已过滤，这里只需要返回基础分
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "AnyTLS: rely on SNI match"};
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

        const auto &cfg = ctx.cfg->stealth.anytls;

        // TODO: 实现完整的 AnyTLS 握手流程
        // 1. 执行标准 TLS 握手（使用配置的证书）
        // 2. 读取 TLS 应用数据（客户端首帧）
        // 3. 解析 AnyTLS 认证帧格式: [password_length:2][password:N][padding:variable]
        // 4. 验证用户身份
        // 5. 认证成功后检测内层协议

        // 当前返回 TLS 表示"不是我"，传递给下一个 scheme
        result.detected = protocol::protocol_type::tls;
        result.transport = std::move(ctx.inbound);
        trace::debug("[AnyTLS] AnyTLS not detected, pass to next scheme");

        co_return result;
    }
} // namespace psm::stealth::anytls