/**
 * @file ProfileBuilder.hpp
 * @brief Composition 层识别 Profile 与候选 resolver 构建器
 * @details 将 CandidateBinding 的 Runtime 描述和 winner-only 接入回调
 *          一起发布。Profile 编译失败时不会发布半成品 resolver。
 */

#pragma once

#include <expected>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <preview/Composition/Recognition/CandidateFactory.hpp>

namespace Preview::Composition::Recognition
{

    namespace Core = Preview::Recognition;
    namespace Runtime = Preview::Runtime;

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
        Runtime::SessionOptions::ResolveCandidateFn Resolver;

        [[nodiscard]] auto Resolve(Core::CandidateId Id) const -> Runtime::SessionOptions::ProtocolAcceptFn
        {
            if (Resolver)
            {
                return Resolver(Id);
            }
            return Runtime::SessionOptions::ProtocolAcceptFn{};
        }

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
        [[nodiscard]] static auto Build(std::vector<CandidateBinding> Bindings,
                                        ProfileBuilderOptions Options = {})
            -> std::expected<ProfileBuildResult, Core::ProfileError>
        {
            Core::ProfileSpec Spec;
            Spec.Mode = Options.Mode;
            Spec.ConfiguredCandidate = Options.ConfiguredCandidate;
            Spec.DefaultCandidate = Options.DefaultCandidate;
            Spec.Budget = Options.Budget;
            Spec.Routes = std::move(Options.Routes);

            std::unordered_map<Core::CandidateId, Runtime::SessionOptions::ProtocolAcceptFn> Acceptors;
            Acceptors.reserve(Bindings.size());
            Spec.Candidates.reserve(Bindings.size());
            for (auto &Binding : Bindings)
            {
                if (!Binding.Accept)
                {
                    return std::unexpected(Core::ProfileError::MissingResolver);
                }
                if (Options.Mode == Core::RecognitionMode::Configured &&
                    Spec.ConfiguredCandidate == Core::InvalidCandidate && Bindings.size() == 1)
                {
                    Spec.ConfiguredCandidate = Binding.Spec.Id;
                }
                Spec.Candidates.push_back(std::move(Binding.Spec));
                Acceptors.emplace(Binding.Spec.Id, std::move(Binding.Accept));
            }

            auto Compiled = Core::Profile::Compile(std::move(Spec));
            if (!Compiled)
            {
                return std::unexpected(Compiled.error());
            }

            ProfileBuildResult Result;
            Result.Profile = std::move(*Compiled);
            auto ResolveFunction = [Acceptors = std::move(Acceptors)](Core::CandidateId Id)
                -> Runtime::SessionOptions::ProtocolAcceptFn
            {
                const auto It = Acceptors.find(Id);
                if (It == Acceptors.end())
                {
                    return Runtime::SessionOptions::ProtocolAcceptFn{};
                }
                return It->second;
            };
            Result.Resolver = std::move(ResolveFunction);
            return Result;
        }

        [[nodiscard]] static auto Build(CandidateBinding Binding,
                                        ProfileBuilderOptions Options = {})
            -> std::expected<ProfileBuildResult, Core::ProfileError>
        {
            std::vector<CandidateBinding> Bindings;
            Bindings.push_back(std::move(Binding));
            return Build(std::move(Bindings), std::move(Options));
        }
    };

    inline auto BuildProfile(std::vector<CandidateBinding> Bindings,
                             ProfileBuilderOptions Options = {})
        -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        return ProfileBuilder::Build(std::move(Bindings), std::move(Options));
    }

} // namespace Preview::Composition::Recognition
