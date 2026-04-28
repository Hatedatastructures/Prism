/**
 * @file reality.cpp
 * @brief Reality 方案特征分析器实现
 */

#include <prism/recognition/arrival/reality.hpp>
#include <prism/recognition/arrival/registry.hpp>
#include <prism/config.hpp>
#include <prism/trace.hpp>

namespace psm::recognition::arrival
{
    auto reality_analyzer::analyze(const arrival_features &features, const config &cfg) const
        -> confidence
    {
        // Reality 必须匹配配置的 server_names
        if (!check_sni_match(features.server_name, cfg.stealth.reality.server_names))
        {
            trace::debug("[RealityAnalyzer] SNI '{}' not matched", features.server_name);
            return confidence::none;
        }

        // Reality 特征检测
        // 1. session_id 长度为 32 字节（Reality 使用固定长度嵌入认证数据）
        // 2. 存在 X25519 key_share 扩展（Reality 需要进行 ECDH 密钥交换）
        const bool has_full_session_id = features.session_id_len == 32;
        const bool has_x25519 = features.has_x25519_key_share;

        if (has_full_session_id && has_x25519)
        {
            trace::debug("[RealityAnalyzer] Full Reality features detected: session_id=32, x25519=true");
            return confidence::high;
        }

        if (has_x25519)
        {
            trace::debug("[RealityAnalyzer] Partial Reality features: x25519=true, session_id={}",
                         features.session_id_len);
            return confidence::medium;
        }

        // SNI 匹配但没有 X25519，可能是客户端配置问题或其他 TLS 连接
        trace::debug("[RealityAnalyzer] SNI matched but no X25519 key_share");
        return confidence::low;
    }

    auto reality_analyzer::is_enabled(const config &cfg) const noexcept -> bool
    {
        return cfg.stealth.reality.enabled();
    }

    auto reality_analyzer::check_sni_match(const std::string_view sni, const memory::vector<memory::string> &server_names)
        -> bool
    {
        if (sni.empty() || server_names.empty())
            return false;

        for (const auto &name : server_names)
        {
            if (sni == std::string_view(name))
                return true;
        }

        return false;
    }
} // namespace psm::recognition::arrival

// 注册 Reality 分析器
REGISTER_ARRIVAL_ANALYZER(psm::recognition::arrival::reality_analyzer)