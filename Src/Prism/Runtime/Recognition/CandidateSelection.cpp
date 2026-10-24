/** @file CandidateSelection.cpp @brief Profile 路由候选和 TLS 预读边界选择实现。 */
#include <Prism/Runtime/Recognition/CandidateSelection.hpp>

#include <Prism/Runtime/Recognition/Tls.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Prism::Recognition::detail
{
    auto IsTlsRouteCandidate(const CandidateHandle& Handle) noexcept -> bool
    {
        return Handle.Protocol() == Prism::Contract::ProtocolType::Tls ||
            Handle.Kind() == CandidateKind::TlsCarrier;
    }

    auto HasTlsRouteCandidate(const Profile& ProfileValue,
        const std::vector<CandidateId>& Candidates) noexcept -> bool
    {
        return std::any_of(Candidates.begin(), Candidates.end(),
            [&ProfileValue](const auto Id) { return IsTlsRouteCandidate(ProfileValue.FindCandidate(Id)); });
    }

    auto ResolveSniRoute(const Profile& ProfileValue, const ProbeSnapshot& Snapshot) -> RouteDecision
    {
        RouteDecision Result;
        if (!ProfileValue.HasRoutes())
        {
            return Result;
        }
        Result.Applicable = true;
        const auto Data = Snapshot.Data();
        if (Data.empty())
        {
            Result.NeedMore = true;
            Result.Required = 1;
            return Result;
        }
        if (std::to_integer<std::uint8_t>(Data.front()) != 0x16)
        {
            Result.Applicable = false;
            return Result;
        }

        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(Data.data()), Data.size());
        const auto Scan = ::Prism::Recognition::detail::ScanClientHello(Bytes);
        if (Scan.Status == Error::NeedMore)
        {
            Result.NeedMore = true;
            Result.Required = (std::max)(Snapshot.Size() + 1, Scan.Required);
            return Result;
        }
        if (Scan.Status != Error::None)
        {
            return Result;
        }

        const auto [ParseError, Features] = ParseClientHelloProgress(Bytes);
        if (ParseError == Error::None)
        {
            Result.Candidate = ProfileValue.LookupRoute(Features.ServerName);
        }
        return Result;
    }

    auto TlsProbeRequired(const ProbeSnapshot& Snapshot) -> std::size_t
    {
        const auto Data = Snapshot.Data();
        if (Data.empty() || std::to_integer<std::uint8_t>(Data.front()) != 0x16)
        {
            return 0;
        }
        const auto Bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(Data.data()), Data.size());
        const auto Scan = ScanClientHello(Bytes);
        if (Scan.Status == Error::NeedMore)
        {
            return Scan.Required;
        }
        return 0;
    }
}
