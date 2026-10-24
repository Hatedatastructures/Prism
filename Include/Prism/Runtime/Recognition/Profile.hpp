/**
 * @file Profile.hpp
 * @brief Prism 识别 Profile 的编译编排与只读查询。
 * @details Profile 发布已排序候选 owner、首字节决策表和 SNI 路由索引；
 *          启动校验与索引构造分别位于独立的 support headers。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Runtime/Recognition/Candidate.hpp>
#include <Prism/Runtime/Recognition/CandidateHandle.hpp>
#include <Prism/Runtime/Recognition/DecisionTable.hpp>
#include <Prism/Runtime/Recognition/ProfileRoutes.hpp>
#include <Prism/Runtime/Recognition/ProfileTypes.hpp>

namespace Prism::Recognition
{

    class Profile;
    using SharedProfile = std::shared_ptr<const Profile>;

    /**
     * @struct ProfileModel
     * @brief Profile 构造所需的已编译值状态。
     * @details 候选、决策表和路由索引在构造完成后只读发布。
     */
    struct ProfileModel
    {
        RecognitionMode Mode{RecognitionMode::Configured};
        CandidateId ConfiguredCandidate{InvalidCandidate};
        RecognitionBudget Budget{};
        SharedCandidateStore Candidates{};
        DecisionTable Decision;
        ProfileRouteIndex Routes;
    };

    namespace ProfileSupport
    {
        [[nodiscard]] auto BuildDecisionTable(const std::vector<CandidateSpec>& Candidates,
            DecisionTable& Decision) -> std::optional<ProfileError>;
    }

    /**
     * @class Profile
     * @brief 已编译且不可变的识别 Profile。
     * @details 编译只发生在启动/配置冷路径；在线调用只读取已发布 owner。
     */
    class Profile : public std::enable_shared_from_this<Profile>
    {
    public:
        Profile(const Profile &) = delete;
        auto operator=(const Profile &) -> Profile & = delete;
        Profile(Profile &&) = delete;
        auto operator=(Profile &&) -> Profile & = delete;
        ~Profile() = default;

        /**
         * @brief 编译并验证 Profile。
         * @param Spec 启动阶段配置；函数取得其候选和路由值的所有权。
         * @return 成功时返回不可变 Profile。
         */
        [[nodiscard]] static auto Compile(ProfileSpec Spec) -> std::expected<SharedProfile, ProfileError>;

        /// 识别模式。
        [[nodiscard]] auto Mode() const noexcept -> RecognitionMode
        {
            return Mode_;
        }

        /// Configured 模式明确选中的候选编号。
        [[nodiscard]] auto ConfiguredCandidate() const noexcept -> CandidateId
        {
            return ConfiguredCandidate_;
        }

        /// 总预算。
        [[nodiscard]] auto Budget() const noexcept -> RecognitionBudget
        {
            return Budget_;
        }

        /// 候选数量。
        [[nodiscard]] auto CandidateCount() const noexcept -> std::size_t
        {
            return Candidates_ ? Candidates_->Size() : 0;
        }

        [[nodiscard]] auto HasTlsCandidate() const noexcept -> bool;

        /// 按稳定 tier/priority 顺序获取候选 ID。
        [[nodiscard]] auto CandidateIdAt(std::size_t Index) const noexcept -> CandidateId
        {
            if (!Candidates_ || Index >= Candidates_->Size())
            {
                return InvalidCandidate;
            }
            return Candidates_->Values()[Index].Id;
        }

        [[nodiscard]] auto CandidateName(CandidateId Id) const -> std::string;

        [[nodiscard]] auto CandidateProtocol(CandidateId Id) const noexcept
            -> Prism::Contract::ProtocolType;

        /// 查询首字节候选；返回固定大小位图，不暴露 Profile 内部存储。
        [[nodiscard]] auto LookupCandidates(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
        {
            return Decision_.Lookup(FirstByte);
        }

        /// 查询 fallback 候选；返回固定大小位图。
        [[nodiscard]] auto FallbackCandidates() const noexcept -> CandidateBitmap
        {
            return Decision_.Fallback();
        }

        /// 查询仅由显式 FirstBytes 产生的首字节候选，不包含 fallback。
        [[nodiscard]] auto IndexedCandidates(std::uint8_t FirstByte) const noexcept -> CandidateBitmap;

        /// 决策表已发布。
        [[nodiscard]] auto IsDecisionSealed() const noexcept -> bool
        {
            return Decision_.IsSealed();
        }

        /// 返回持有候选 owner 的句柄；句柄可安全跨协程保存。
        [[nodiscard]] auto FindCandidate(CandidateId Id) const -> CandidateHandle
        {
            return CandidateHandle(Candidates_, Id);
        }

        /**
         * @brief 查询 SNI 路由。
         * @param Sni 客户端 SNI。
         * @return 精确或最长单标签 wildcard 的候选 ID，最后才使用默认候选。
         */
        [[nodiscard]] auto LookupRoute(std::string_view Sni) const -> std::optional<CandidateId>
        {
            return ProfileSupport::LookupRoute(Routes_, Sni);
        }

        /// 精确路由条目数。
        [[nodiscard]] auto ExactRouteCount() const noexcept -> std::size_t
        {
            return Routes_.Exact.size();
        }

        /// wildcard 路由条目数。
        [[nodiscard]] auto WildcardRouteCount() const noexcept -> std::size_t
        {
            return Routes_.Wildcards.size();
        }

        /// 是否配置了至少一个 SNI 路由。
        [[nodiscard]] auto HasRoutes() const noexcept -> bool
        {
            return !Routes_.Exact.empty() || !Routes_.Wildcards.empty() ||
                Routes_.DefaultCandidate != InvalidCandidate;
        }

    private:
        explicit Profile(ProfileModel Data);

        RecognitionMode Mode_{RecognitionMode::Configured};
        CandidateId ConfiguredCandidate_{InvalidCandidate};
        RecognitionBudget Budget_{};
        SharedCandidateStore Candidates_{};
        DecisionTable Decision_{};
        ProfileRouteIndex Routes_{};
    };

} // namespace Prism::Recognition
