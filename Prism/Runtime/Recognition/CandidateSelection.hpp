/**
 * @file CandidateSelection.hpp
 * @brief Configured recognition candidate matching and route selection.
 */

#pragma once

#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Recognition
{

    namespace detail
    {
        /**
         * @struct RouteDecision
         * @brief 同一预读快照上的 SNI 路由解析结果
         */
        struct RouteDecision
        {
            std::optional<CandidateId> Candidate;
            std::size_t Required{0};
            bool Applicable{false};
            bool NeedMore{false};
        };

        [[nodiscard]] inline auto IsTlsRouteCandidate(const CandidateHandle& Handle) noexcept -> bool
        {
            return Handle.Protocol() == Prism::Contract::ProtocolType::Tls || Handle.Kind() == CandidateKind::TlsCarrier;
        }

        [[nodiscard]] inline auto HasTlsRouteCandidate(const Profile& Profile,
            const std::vector<CandidateId>& Candidates) noexcept -> bool
        {
            return std::any_of(Candidates.begin(), Candidates.end(),
                [&Profile](const auto Id) { return IsTlsRouteCandidate(Profile.FindCandidate(Id)); });
        }

        /**
         * @brief 从同一 ProbeSnapshot 解析 SNI 并查找 Profile route
         * @param Profile 不可变识别 Profile
         * @param Snapshot 当前连接预读快照
         * @return route 候选及下一次读取边界
         * @details 仅在调用方已确认活动候选包含 TLS carrier 时调用。未命中 route
         *          保持空 Candidate，由 coordinator 映射为 NoMatch。
         */
        [[nodiscard]] inline auto ResolveSniRoute(const Profile& Profile, const ProbeSnapshot& Snapshot)
            -> RouteDecision
        {
            RouteDecision Result;
            if (!Profile.HasRoutes())
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
                Result.Candidate = Profile.LookupRoute(Features.ServerName);
            }
            return Result;
        }

        /**
         * @brief 获取当前 TLS ClientHello 扫描器给出的下一读取边界
         * @param Snapshot 当前连接预读快照
         * @return 需要补齐的绝对字节数；非 TLS 或已结束时返回 0
         * @details 只扫描已捕获字节，不执行 I/O。这样 TLS 多记录握手
         *          可以一次补齐到下一条结构边界，避免按字节增长。
         */
        [[nodiscard]] inline auto TlsProbeRequired(const ProbeSnapshot& Snapshot) -> std::size_t
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

    } // namespace detail

} // namespace Prism::Recognition
