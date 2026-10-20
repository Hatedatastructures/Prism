/** @file TlsCandidateModel.cpp @brief TLS candidate policy 的规范化与匹配实现。 */

#include <Prism/Composition/Recognition/TlsCandidateModel.hpp>

#include <algorithm>

namespace Prism::Composition::Recognition
{
    namespace detail
    {

        auto Normalize(const std::string_view Value) -> std::string
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

        auto MatchesServerName(const std::string_view ServerName,
            const std::vector<std::string>& Patterns) -> bool
        {
            const auto Normalized = Normalize(ServerName);
            if (Normalized.empty())
            {
                return false;
            }
            for (const auto& RawPattern : Patterns)
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

        auto MatchesAlpn(const std::vector<std::string>& Offered,
            const std::vector<std::string>& Expected) -> bool
        {
            if (Expected.empty())
            {
                return true;
            }
            return std::any_of(Expected.begin(), Expected.end(), [&Offered](const auto& Need)
            {
                return std::find(Offered.begin(), Offered.end(), Need) != Offered.end();
            });
        }

        auto InspectFeatures(const Core::ClientHelloFeatures& Features,
            const TlsMatchPolicy& Policy) -> Core::MatchState
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

    auto TlsCandidateBinding::Inspect(const Core::ClientHelloFeatures& Features) const
        -> Core::MatchState
    {
        if (!MatchPolicy_)
        {
            return Core::MatchState::Rejected;
        }
        return detail::InspectFeatures(Features, *MatchPolicy_);
    }

} // namespace Prism::Composition::Recognition
