/**
 * @file ProfileBuilder.hpp
 * @brief Composition 层识别 Profile 与候选 resolver 构建器
 * @details 将 CandidateBinding 的 Runtime 描述和 winner-only 接入回调
 *          一起发布。Profile 编译失败时不会发布半成品 resolver。
 */

#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>

namespace Prism::Composition::Recognition
{

    namespace Core = Prism::Recognition;

    namespace detail
    {

        [[nodiscard]] auto NormalizeProtocol(std::string_view Value) -> std::string;

        [[nodiscard]] auto NormalizeScheme(std::string_view Value) -> std::string;

        [[nodiscard]] auto ParseProtocol(std::string_view Value)
            -> std::optional<Prism::Contract::ProtocolType>;

        [[nodiscard]] auto IsQuicProtocol(Prism::Contract::ProtocolType Protocol) noexcept -> bool;

        [[nodiscard]] auto WithRouteServerNames(
            const RecognitionDefinition &Config, CandidateDefinition Candidate)
            -> CandidateDefinition;

        [[nodiscard]] auto SameOuter(
            const CandidateDefinition &Left, const CandidateDefinition &Right) -> bool;

        auto ApplyCandidateMetadata(const CandidateDefinition &Candidate,
            CandidateBinding &Binding) -> void;

    } // namespace detail

    /**
     * @struct ProfileBuilderOptions
     * @brief Profile 编译选项
     */
    struct ProfileBuilderOptions
    {
        Core::RecognitionMode Mode{Core::RecognitionMode::Configured};
        Core::CandidateId ConfiguredCandidate{Core::InvalidCandidate};
        Core::CandidateId DefaultCandidate{Core::InvalidCandidate};
        Core::RecognitionBudget Budget{};
        std::vector<Core::RouteBinding> Routes;
    };

    /**
     * @struct ProfileBuildResult
     * @brief 已编译 Profile 与候选 resolver
     */
    struct ProfileBuildResult
    {
        Core::SharedProfile Profile;
        std::function<std::shared_ptr<Prism::Contract::StreamFactory>(Core::CandidateId)> Resolver;

        [[nodiscard]] auto Resolve(Core::CandidateId Id) const
            -> std::shared_ptr<Prism::Contract::StreamFactory>;

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Profile != nullptr && static_cast<bool>(Resolver);
        }
    };

    /**
     * @class ProfileBuilder
     * @brief 从 Composition 候选绑定构建 immutable recognition Profile
     */
    class ProfileBuilder
    {
    public:
        /**
         * @brief 从已拥有的 candidate binding 列表编译 immutable profile。
         * @param Bindings 按值移动；成功后 Profile 与 resolver 接管 Accept shared owners。
         * @param Options 按值移动的模式、路由和预算；不保存调用方地址。
         * @return ProfileBuildResult 或 typed ProfileError；失败不发布半成品 owner。
         * @note 同步 cold CPU 操作，无 cancellation/executor、网络 I/O、half-close 或最终关闭；
         *       成功后的 protocol/root owner 负责运行期关闭。
         */
        [[nodiscard]] static auto Build(std::vector<CandidateBinding> Bindings,
                                        ProfileBuilderOptions Options = {})
            -> std::expected<ProfileBuildResult, Core::ProfileError>;

        /**
         * @brief 移动一个 candidate binding 后复用列表编译路径。
         * @param Binding 按值移动，Accept owner 由返回的 resolver 接管。
         * @param Options 按值移动的 profile 选项。
         * @return typed ProfileError 或 immutable profile；不执行 I/O/cancellation。
         * @note 没有 stream half-close 或最终关闭者语义；成功 owner 由 resolver/protocol 管理。
         */
        [[nodiscard]] static auto Build(CandidateBinding Binding,
                                        ProfileBuilderOptions Options = {})
            -> std::expected<ProfileBuildResult, Core::ProfileError>;

        /**
         * @brief 从 cold definition 借用调用期 factory 构造并编译 profile。
         * @param Definition 同步借用的 definition；函数不保存其地址。
         * @param Factory 同步调用的 candidate builder，返回值拥有 Accept owner。
         * @return immutable profile/resolver 或 typed ProfileError；缺 factory/候选会失败。
         * @note 纯同步 cold assembly，无网络 I/O、取消、executor、half-close 或最终关闭者；
         *       运行期关闭归返回的 protocol/root owner。
         */
        [[nodiscard]] static auto Build(const RecognitionDefinition &Definition,
                                        CandidateBuilder Factory)
            -> std::expected<ProfileBuildResult, Core::ProfileError>;
    };

    [[nodiscard]] auto BuildProfile(std::vector<CandidateBinding> Bindings,
                             ProfileBuilderOptions Options = {})
        -> std::expected<ProfileBuildResult, Core::ProfileError>;

} // namespace Prism::Composition::Recognition
