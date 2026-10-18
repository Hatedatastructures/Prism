/**
 * @file TlsCandidateModel.hpp
 * @brief TLS carrier 候选的稳定类型与接入回调契约。
 * @details 这里拥有 carrier 选择元数据、SNI/ALPN policy 和 binding Inspect；
 *          ClientHello 解析、prepare 与实际 carrier 接入位于对应 helper 头文件。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /// 具体 carrier 的服务端接入回调。
    using CarrierAcceptFn = std::function<Net::awaitable<Core::CarrierAcceptResult>(
        Core::CarrierAcceptInput)>;
    using CarrierAcceptPreparedFn = std::function<Net::awaitable<Core::CarrierAcceptResult>(
        Core::CarrierAcceptPreparedInput)>;

    /**
     * @enum TlsCarrier
     * @brief 已有 Prism TLS carrier 方案名。
     */
    using TlsCarrier = Prism::Composition::Protocol::CarrierKind;

    /**
     * @struct TlsCandidateOptions
     * @brief TLS carrier 候选筛选与提交参数。
     */
    struct TlsCandidateOptions
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};
        TlsCarrier Carrier{TlsCarrier::Native};
        /** @brief 此绑定的真实 Native SSL_CTX 在 carrier 调用期间保活。 */
        bool HasNativeTlsContext{false};
    };

    /**
     * @struct TlsMatchPolicy
     * @brief ClientHello 的纯 TLS 匹配规则。
     * @details 规则值由冷路径按值拥有；发布后通过 const shared state 供
     *          CandidateBinding 与 Spec.Inspect 共同读取，热路径不复制字符串。
     */
    struct TlsMatchPolicy final
    {
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};
        /** @brief 只表示 ECH 扩展语法交给实际 TLS/wire owner 判断。 */
        bool PassesEchExtension{false};
        /** @brief 实际使用 Native SSL_CTX；SNI/ALPN 延至握手结果核验。 */
        bool HasNativeTlsContext{false};
    };

    /**
     * @struct TlsCandidateBinding
     * @brief TLS carrier Runtime 候选。
     */
    struct TlsCandidateBinding
    {
        Core::CandidateSpec Spec;
        std::string Scheme;

        [[nodiscard]] auto Inspect(const Core::ClientHelloFeatures &Features) const -> Core::MatchState;

    private:
        friend class TlsCandidateFactory;
        std::shared_ptr<const TlsMatchPolicy> MatchPolicy_;
    };

    namespace detail
    {

        [[nodiscard]] inline auto Normalize(std::string_view Value) -> std::string
        {
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                unsigned char Lower = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(Lower));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        [[nodiscard]] inline auto MatchesServerName(
            std::string_view ServerName,
            const std::vector<std::string> &Patterns) -> bool
        {
            const auto Normalized = Normalize(ServerName);
            if (Normalized.empty())
            {
                return false;
            }
            for (const auto &RawPattern : Patterns)
            {
                const auto Pattern = Normalize(RawPattern);
                if (Pattern == Normalized)
                {
                    return true;
                }
                if (Pattern.starts_with("*.") && Normalized.ends_with(Pattern.substr(1)))
                {
                    const auto Prefix = std::string_view(Normalized).substr(
                        0, Normalized.size() - Pattern.size() + 1);
                    if (!Prefix.empty() && Prefix.find('.') == std::string_view::npos)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        [[nodiscard]] inline auto MatchesAlpn(
            const std::vector<std::string> &Offered,
            const std::vector<std::string> &Expected) -> bool
        {
            if (Expected.empty())
            {
                return true;
            }
            return std::any_of(Expected.begin(), Expected.end(), [&Offered](const auto &Need)
                               { return std::find(Offered.begin(), Offered.end(), Need) != Offered.end(); });
        }

        [[nodiscard]] inline auto InspectFeatures(
            const Core::ClientHelloFeatures &Features,
            const TlsMatchPolicy &Policy) -> Core::MatchState
        {
            // HasEch 只表示扩展语法，GREASE 与真实 offer 都交给所属 TLS/wire owner。
            if (Features.HasEch && !Policy.PassesEchExtension)
            {
                return Core::MatchState::Rejected;
            }
            if (Features.HasEch && Policy.HasNativeTlsContext)
            {
                // 带扩展的 ClientHello 外层 SNI/ALPN 不足以筛掉同一 SSL_CTX 的候选。
                return Core::MatchState::Structural;
            }
            if (Policy.Fallback)
            {
                return Core::MatchState::Structural;
            }
            if (!MatchesServerName(Features.ServerName, Policy.ServerNames) ||
                !MatchesAlpn(Features.AlpnProtocols, Policy.Alpn))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

    } // namespace detail

    inline auto TlsCandidateBinding::Inspect(const Core::ClientHelloFeatures &Features) const
        -> Core::MatchState
    {
        if (!MatchPolicy_)
        {
            return Core::MatchState::Rejected;
        }
        return detail::InspectFeatures(Features, *MatchPolicy_);
    }

} // namespace Prism::Composition::Recognition
