/**
 * @file CandidateSelection.hpp
 * @brief 配置识别候选匹配与路由选择。
 */

#pragma once

#include <Prism/Runtime/Recognition/CandidateHandle.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Types.hpp>

#include <cstddef>
#include <optional>
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

        [[nodiscard]] auto IsTlsRouteCandidate(const CandidateHandle& Handle) noexcept -> bool;

        [[nodiscard]] auto HasTlsRouteCandidate(const Profile& Profile,
            const std::vector<CandidateId>& Candidates) noexcept -> bool;

        /**
         * @brief 从同一 ProbeSnapshot 解析 SNI 并查找 Profile route
         * @param Profile 不可变识别 Profile
         * @param Snapshot 当前连接预读快照
         * @return route 候选及下一次读取边界
         * @details 仅在调用方已确认活动候选包含 TLS carrier 时调用。未命中 route
         *          保持空 Candidate，由 coordinator 映射为 NoMatch。
         */
        [[nodiscard]] auto ResolveSniRoute(const Profile& Profile, const ProbeSnapshot& Snapshot)
            -> RouteDecision;

        /**
         * @brief 获取当前 TLS ClientHello 扫描器给出的下一读取边界
         * @param Snapshot 当前连接预读快照
         * @return 需要补齐的绝对字节数；非 TLS 或已结束时返回 0
         * @details 只扫描已捕获字节，不执行 I/O。这样 TLS 多记录握手
         *          可以一次补齐到下一条结构边界，避免按字节增长。
         */
        [[nodiscard]] auto TlsProbeRequired(const ProbeSnapshot& Snapshot) -> std::size_t;

    } // namespace detail

} // namespace Prism::Recognition
